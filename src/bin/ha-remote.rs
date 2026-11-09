use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use ha_remote::{
    AUTH_SOCKET, Config, Result, Ws, error, exit_if_fatal, http_client, http_error, info,
    load_config, py_round, run_timeout, secret, tailscale_note, utc_now_iso, warn,
};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::runtime::Handle;
use tokio::sync::{Notify, mpsc};
use wayland_client::globals::{GlobalListContents, registry_queue_init};
use wayland_client::protocol::{wl_registry::WlRegistry, wl_seat::WlSeat};
use wayland_client::{Connection, Dispatch, Proxy, QueueHandle, delegate_noop};
use wayland_protocols::ext::idle_notify::v1::client::ext_idle_notification_v1::{
    self, ExtIdleNotificationV1,
};
use wayland_protocols::ext::idle_notify::v1::client::ext_idle_notifier_v1::ExtIdleNotifierV1;

const COOLDOWN_S: f64 = 5.0;
const POLL_S: Duration = Duration::from_secs(5);
const CONFIRM_WINDOW_S: f64 = 20.0;
const IDLE_AFTER_MS: u32 = 120_000;
const UNLOCK_HOLD_S: f64 = 20.0;
const EPOCH: &str = "1970-01-01T00:00:00+00:00";

/// `time.monotonic()`: CLOCK_MONOTONIC seconds, so a zero start means "long ago".
fn now() -> f64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid, writable timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

fn sleep_s(s: f64) {
    std::thread::sleep(Duration::from_secs_f64(s));
}

fn kbd_save() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from)
        .join("ha-remote-kbd")
}

fn first(dir: &str, pick: impl Fn(&str, &Path) -> bool) -> Option<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .collect();
    paths.sort();
    paths.into_iter().find(|p| {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        !name.starts_with('.') && pick(name, p)
    })
}

fn supply_type(p: &Path, want: &str) -> bool {
    read(p.join("type")).as_deref() == Some(want)
}

fn read(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
}

fn percent(device: Option<&Path>) -> Option<i64> {
    let device = device?;
    let cur: i64 = read(device.join("brightness"))?.parse().ok()?;
    let top: i64 = read(device.join("max_brightness"))?.parse().ok()?;
    (top != 0).then(|| py_round(cur as f64 * 100.0 / top as f64))
}

fn run(cmd: &[&str]) -> io::Result<Output> {
    Handle::current().block_on(run_timeout(cmd, Duration::from_secs(10)))
}

fn stdout(cmd: &[&str]) -> io::Result<String> {
    run(cmd).map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

fn noctalia_status() -> Result<Value> {
    Ok(serde_json::from_str(&stdout(&[
        "noctalia", "msg", "status",
    ])?)?)
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

fn py_float(v: &Value) -> std::result::Result<f64, String> {
    match v {
        Value::Number(n) => n.as_f64().ok_or_else(|| format!("bad number {n}")),
        Value::Bool(b) => Ok(f64::from(u8::from(*b))),
        Value::String(s) => s
            .trim()
            .parse()
            .map_err(|_| format!("could not convert string to float: {s:?}")),
        other => Err(format!(
            "float() argument must be a string or a number, not {other}"
        )),
    }
}

/// The level of an `ha_remote_cmd` event: fan percentage, else light brightness 0–255.
fn level(data: &Value) -> std::result::Result<Option<i64>, String> {
    let given = |k| {
        data.get(k)
            .filter(|v| !(v.is_null() || *v == "" || *v == "None"))
    };
    let pct = if let Some(p) = given("percentage") {
        py_float(p)?
    } else if let Some(b) = given("brightness") {
        py_float(b)? * 100.0 / 255.0
    } else {
        return Ok(None);
    };
    if !pct.is_finite() {
        return Err(format!("cannot round {pct}"));
    }
    Ok(Some(py_round(pct).max(1)))
}

fn checksum(report: &mut [u8; 64]) {
    report[3] = report[4..].iter().fold(0u8, |a, b| a.wrapping_add(*b));
}

fn frame(key: u8, cmd: u8, fields: &[u8]) -> [u8; 64] {
    let mut r = [0u8; 64];
    r[0] = 0x55;
    r[1] = cmd;
    for (i, b) in fields.iter().enumerate() {
        r[4 + i] = b ^ key;
    }
    r
}

fn nuphy_xfer(f: &mut File, report: &mut [u8; 64]) -> io::Result<[u8; 64]> {
    checksum(report);
    let mut out = vec![0];
    out.extend_from_slice(report);
    f.write_all(&out)?;
    loop {
        let mut pfd = libc::pollfd {
            fd: f.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is one valid pollfd for an open fd.
        match unsafe { libc::poll(&mut pfd, 1, 1000) } {
            n if n < 0 => return Err(io::Error::last_os_error()),
            0 => return Err(io::ErrorKind::TimedOut.into()),
            _ => {}
        }
        let mut reply = [0u8; 64];
        let n = f.read(&mut reply)?;
        if n > 1 && reply[1] == report[1] {
            return Ok(reply);
        }
    }
}

fn nuphy_set(level: Option<i64>) -> bool {
    let Some(level) = level else { return false };
    let Ok(dir) = std::fs::read_dir("/dev/input/by-id") else {
        return false;
    };
    let mut reached = false;
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // The dongle doesn't relay backlight commands to the keyboard.
        if !name.starts_with("usb-NuPhy")
            || !name.ends_with("-if03-hidraw")
            || name.contains("Dongle")
        {
            continue;
        }
        let Ok(mut f) = OpenOptions::new().read(true).write(true).open(entry.path()) else {
            continue;
        };
        let mut attempt = || -> io::Result<()> {
            let mut hello = [0u8; 64];
            hello[0] = 0x55;
            hello[1] = 0xee;
            File::open("/dev/urandom")?.read_exact(&mut hello[8..])?;
            let key = nuphy_xfer(&mut f, &mut hello)?[4];
            let mut apply = frame(key, 0xd5, &[0x11, 0, 0, 0]);
            nuphy_xfer(&mut f, &mut apply)?;
            nuphy_xfer(&mut f, &mut frame(key, 0xd6, &[1, 1, 0, 1, level as u8]))?;
            nuphy_xfer(&mut f, &mut apply)?;
            Ok(())
        };
        if attempt().is_ok() {
            reached = true;
        }
    }
    reached
}

fn smc(name: &str) -> Vec<(String, i64)> {
    let mut out: Vec<(String, i64)> = Vec::new();
    let Ok(dir) = std::fs::read_dir("/sys/class/hwmon") else {
        return out;
    };
    let mut hwmons: Vec<PathBuf> = dir
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("hwmon"))
        .map(|e| e.path())
        .collect();
    hwmons.sort();
    for hwmon in hwmons {
        if read(hwmon.join("name")).as_deref() != Some(name) {
            continue;
        }
        let Ok(files) = std::fs::read_dir(&hwmon) else {
            continue;
        };
        let mut labels: Vec<String> = files
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with("_label") && !n.starts_with('.'))
            .collect();
        labels.sort();
        for file in labels {
            let input = hwmon.join(file.replace("_label", "_input"));
            let (Some(label), Some(Ok(value))) = (
                read(hwmon.join(&file)),
                read(input).map(|v| v.parse::<i64>()),
            ) else {
                continue;
            };
            match out.iter_mut().find(|(l, _)| *l == label) {
                Some(slot) => slot.1 = value,
                None => out.push((label, value)),
            }
        }
    }
    out
}

/// Entity, state and attributes for one SMC reading, if it is a fan or a temperature.
fn smc_entity(prefix: &str, name: &str, label: &str, value: i64) -> Option<(String, Value, Value)> {
    let lower = label.to_lowercase().replace(['/', ' '], "_");
    let key = lower.strip_suffix("_temperature").unwrap_or(&lower);
    let key = key.strip_suffix("_temp").unwrap_or(key);
    if label.starts_with("Fan") {
        Some((
            format!("sensor.{prefix}_{key}"),
            json!(value),
            json!({"friendly_name": format!("{name} {}", label.to_lowercase()), "unit_of_measurement": "RPM",
                   "icon": "mdi:fan", "state_class": "measurement"}),
        ))
    } else if label.contains("Temp") || label.contains("Hotspot") {
        // round(value / 1000, 1): correctly rounded like Python's.
        let temp: f64 = format!("{:.1}", value as f64 / 1000.0).parse().ok()?;
        Some((
            format!("sensor.{prefix}_{key}_temp"),
            json!(temp),
            json!({"friendly_name": format!("{name} {label}"), "device_class": "temperature",
                   "unit_of_measurement": "°C", "state_class": "measurement"}),
        ))
    } else {
        None
    }
}

#[derive(Clone, Copy)]
enum Action {
    Suspend,
    PowerOff,
    NextTrack,
    StartJob,
}

impl Action {
    fn name(self) -> &'static str {
        match self {
            Action::Suspend => "suspend",
            Action::PowerOff => "power_off",
            Action::NextTrack => "next_track",
            Action::StartJob => "start_job",
        }
    }
}

struct Devices {
    screen: Option<PathBuf>,
    kbd: Option<PathBuf>,
    battery: Option<PathBuf>,
    ac: Option<PathBuf>,
}

struct State {
    busy: HashSet<String>,
    last_run: HashMap<String, f64>,
    armed_at: f64,
    job_started: f64,
    job_was_active: bool,
    job_cancelled: bool,
    screen_off: bool,
    unlocking_until: f64,
    screen_level: i64,
    kbd_level: i64,
    active: bool,
    locked: bool,
}

struct Snapshot {
    locked: bool,
    screen: Option<i64>,
    keyboard: Option<i64>,
    power: Option<i64>,
    job: bool,
    battery: Option<(Option<String>, Option<String>)>,
    plugged: Option<bool>,
    music: String,
    volume: Option<i64>,
    artist: Option<String>,
    title: Option<String>,
}

struct Remote {
    url: String,
    token: String,
    notify_service: Option<String>,
    player: String,
    job_unit: String,
    prefix: String,
    name: String,
    hwmon: String,
    locked_entity: String,
    job_entity: String,
    actions: Vec<(String, Action, f64)>,
    dev: Devices,
    http: reqwest::Client,
    st: Mutex<State>,
    sent: Mutex<HashMap<String, Value>>,
    poll_now: Notify,
    to_auth: mpsc::UnboundedSender<Value>,
    idle: AtomicBool,
}

impl Remote {
    fn new(cfg: &Config, to_auth: mpsc::UnboundedSender<Value>) -> Remote {
        let token = secret("token");
        let prefix = cfg.prefix();
        let e = |domain: &str, obj: &str| format!("{domain}.{prefix}_{obj}");
        let job_entity = e("input_boolean", "job");
        Remote {
            url: cfg.url(),
            http: http_client(&token, Some(Duration::from_secs(10)), None),
            token,
            notify_service: cfg.ha.notify_service.clone().filter(|s| !s.is_empty()),
            player: cfg.player.clone(),
            job_unit: cfg.job_unit.clone(),
            name: cfg.name(),
            hwmon: cfg.hwmon.clone(),
            locked_entity: e("binary_sensor", "locked"),
            actions: vec![
                (e("input_boolean", "suspend"), Action::Suspend, COOLDOWN_S),
                (e("input_boolean", "power_off"), Action::PowerOff, 1.0),
                (e("input_boolean", "next_track"), Action::NextTrack, 1.0),
                (job_entity.clone(), Action::StartJob, COOLDOWN_S),
            ],
            job_entity,
            dev: Devices {
                screen: first("/sys/class/backlight", |_, _| true),
                kbd: first("/sys/class/leds", |n, _| n.contains("kbd_backlight")),
                battery: first("/sys/class/power_supply", |_, p| supply_type(p, "Battery")),
                ac: first("/sys/class/power_supply", |_, p| supply_type(p, "Mains")),
            },
            st: Mutex::new(State {
                busy: HashSet::new(),
                last_run: HashMap::new(),
                armed_at: -CONFIRM_WINDOW_S,
                job_started: 0.0,
                job_was_active: false,
                job_cancelled: false,
                screen_off: false,
                unlocking_until: 0.0,
                screen_level: 70,
                kbd_level: 50,
                active: true,
                locked: false,
            }),
            sent: Mutex::new(HashMap::new()),
            poll_now: Notify::new(),
            to_auth,
            idle: AtomicBool::new(false),
            prefix,
        }
    }

    fn st(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn sent(&self) -> MutexGuard<'_, HashMap<String, Value>> {
        self.sent.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn tell_auth(&self, msg: Value) {
        let _ = self.to_auth.send(msg);
    }

    fn presence(self: &Arc<Self>, active: bool) {
        self.st().active = active;
        self.tell_auth(json!({"type": "presence", "active": active}));
        if active {
            // niri powers monitors back on at the first input.
            self.st().screen_off = false;
            self.poll_now.notify_one();
            let this = self.clone();
            tokio::spawn(async move {
                if let Ok(Ok(status)) = tokio::task::spawn_blocking(noctalia_status).await
                    && truthy(status.get("locked"))
                {
                    this.tell_auth(json!({"type": "lockscreen"}));
                }
            });
        }
    }

    fn set_percent(&self, device: &Path, pct: i64) -> io::Result<()> {
        let pct = pct.clamp(0, 100);
        // Via UPower, so noctalia's OSD and cached level follow.
        if self.dev.kbd.as_deref() == Some(device) {
            run(&[
                "noctalia",
                "msg",
                "keyboard-backlight-set",
                &pct.to_string(),
            ])?;
        } else {
            let name = device
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            run(&["brightnessctl", "-d", &name, "set", &format!("{pct}%")])?;
        }
        Ok(())
    }

    fn kbd_off(&self) -> io::Result<()> {
        let Some(kbd) = self.dev.kbd.as_deref() else {
            return Ok(());
        };
        // Save only once, or a second lock would save 0 and unlock would restore darkness.
        let save = kbd_save();
        if !save.exists() {
            std::fs::write(&save, percent(Some(kbd)).unwrap_or(0).to_string())?;
        }
        self.set_percent(kbd, 0)
    }

    fn kbd_restore(&self) -> io::Result<()> {
        let save = kbd_save();
        let (Some(value), Some(kbd)) = (read(&save), self.dev.kbd.as_deref()) else {
            return Ok(());
        };
        let _ = std::fs::remove_file(&save);
        if !value.is_empty()
            && value.chars().all(|c| c.is_ascii_digit())
            && let Ok(v) = value.parse()
        {
            self.set_percent(kbd, v)?;
        }
        Ok(())
    }

    // ---- actions (run in a worker thread)

    fn lock(&self) -> Result<()> {
        if truthy(noctalia_status()?.get("locked")) {
            info!("already locked: screen and keyboard off");
        } else {
            info!("locking");
            run(&["noctalia", "msg", "session", "lock"])?;
            // Give the lock surface time to map before DPMS off.
            sleep_s(1.5);
        }
        run(&["niri", "msg", "action", "power-off-monitors"])?;
        self.st().screen_off = true;
        Ok(self.kbd_off()?)
    }

    fn unlock(&self) -> Result<()> {
        if !truthy(noctalia_status()?.get("locked")) {
            info!("unlock: not locked");
            return Ok(());
        }
        info!("unlock: submitting the lock screen for phone approval");
        // Our own keystrokes must not count as someone at the keyboard.
        self.tell_auth(json!({"type": "hold", "s": UNLOCK_HOLD_S as i64}));
        self.st().unlocking_until = now() + UNLOCK_HOLD_S;
        self.poll_now.notify_one();
        run(&["niri", "msg", "action", "power-on-monitors"])?;
        self.st().screen_off = false;
        sleep_s(0.5);
        run(&[
            "wtype",
            "-M",
            "ctrl",
            "a",
            "-m",
            "ctrl",
            "-k",
            "BackSpace",
            "-k",
            "Return",
        ])?;
        Ok(())
    }

    fn suspend(&self) -> Result<()> {
        info!("suspending");
        self.say_offline();
        run(&["systemctl", "suspend"])?;
        Ok(())
    }

    fn power_off(&self) -> Result<()> {
        let t = now();
        let armed = {
            let mut st = self.st();
            let fresh = t - st.armed_at > CONFIRM_WINDOW_S;
            if fresh {
                st.armed_at = t;
            }
            fresh
        };
        if armed {
            info!("power off armed");
            return self.notify(
                &format!("{} power off", self.name),
                &format!("Press again within {CONFIRM_WINDOW_S} s to power off."),
            );
        }
        info!("powering off");
        self.say_offline();
        run(&["systemctl", "poweroff"])?;
        Ok(())
    }

    fn next_track(&self) -> Result<()> {
        run(&["playerctl", "-p", &self.player, "next"])?;
        Ok(())
    }

    fn pause_music(&self) -> Result<()> {
        // playerctl -a stops at the first player that errors.
        for player in stdout(&["playerctl", "-l"])?.split_whitespace() {
            run(&["playerctl", "-p", player, "pause"])?;
        }
        Ok(())
    }

    fn job_active(&self) -> io::Result<bool> {
        if self.job_unit.is_empty() {
            return Ok(false);
        }
        let state = stdout(&["systemctl", "--user", "is-active", &self.job_unit])?;
        Ok(matches!(state.trim(), "active" | "activating"))
    }

    fn start_job(&self) -> Result<()> {
        if self.job_active()? {
            return Ok(());
        }
        info!("starting {}", self.job_unit);
        {
            let mut st = self.st();
            st.job_started = now();
            st.job_was_active = true;
        }
        run(&["systemctl", "--user", "start", "--no-block", &self.job_unit])?;
        Ok(())
    }

    fn cancel_job(&self) -> Result<()> {
        if !self.job_active()? {
            return Ok(());
        }
        info!("cancelling {}", self.job_unit);
        self.st().job_cancelled = true;
        run(&["systemctl", "--user", "stop", "--no-block", &self.job_unit])?;
        Ok(())
    }

    fn act(&self, action: Action) -> Result<()> {
        match action {
            Action::Suspend => self.suspend(),
            Action::PowerOff => self.power_off(),
            Action::NextTrack => self.next_track(),
            Action::StartJob => self.start_job(),
        }
    }

    fn command(&self, target: Option<&str>, cmd: Option<&str>, pct: Option<i64>) -> Result<()> {
        match target {
            Some("session") => {
                return if cmd == Some("lock") {
                    self.lock()
                } else {
                    self.unlock()
                };
            }
            Some("music") => {
                if cmd == Some("off") {
                    return self.pause_music();
                }
                if cmd == Some("level") {
                    let pct = pct.ok_or("level without a percentage")?;
                    run(&[
                        "playerctl",
                        "-p",
                        &self.player,
                        "volume",
                        &format!("{:.2}", pct as f64 / 100.0),
                    ])?;
                }
                run(&["playerctl", "-p", &self.player, "play"])?;
                return Ok(());
            }
            _ => {}
        }
        let screen = target == Some("screen");
        let device = match target {
            Some("screen") => self.dev.screen.as_deref(),
            Some("keyboard") => self.dev.kbd.as_deref(),
            _ => None,
        };
        let Some(device) = device else { return Ok(()) };
        if cmd == Some("off") {
            if screen {
                run(&["niri", "msg", "action", "power-off-monitors"])?;
                self.st().screen_off = true;
            } else {
                self.set_percent(device, 0)?;
            }
            return Ok(());
        }
        if screen {
            run(&["niri", "msg", "action", "power-on-monitors"])?;
            self.st().screen_off = false;
        }
        if pct.is_some() || percent(Some(device)).unwrap_or(0) == 0 {
            let last = {
                let st = self.st();
                if screen {
                    st.screen_level
                } else {
                    st.kbd_level
                }
            };
            self.set_percent(device, pct.unwrap_or(last))?;
        }
        Ok(())
    }

    fn polkit_panel(&self, submit: bool) -> Result<()> {
        let status = noctalia_status()?;
        // Keys would go to the lock screen instead.
        if truthy(status.get("locked"))
            || status.get("activePanelId").and_then(Value::as_str) != Some("polkit")
        {
            return Ok(());
        }
        if submit {
            // The OnDemand panel only gets keys while its output is focused.
            let layers: Value = serde_json::from_str(&stdout(&["niri", "msg", "-j", "layers"])?)?;
            let output = layers
                .as_array()
                .into_iter()
                .flatten()
                .find(|la| la["namespace"] == "noctalia-panel")
                .and_then(|la| la["output"].as_str())
                .filter(|o| !o.is_empty());
            if let Some(output) = output {
                run(&["niri", "msg", "action", "focus-monitor", output])?;
            }
            // A window still holding focus (e.g. fullscreen over a top-layer panel) would get the keys.
            if stdout(&["niri", "msg", "-j", "focused-window"])?.trim() != "null" {
                warn!("polkit: panel has no keyboard focus; use a floating polkit panel");
                return Ok(());
            }
            // The panel ignores an empty submit; the approval is what authenticates, not this text.
            run(&["wtype", "x", "-k", "Return"])?;
        } else {
            run(&["noctalia", "msg", "panel-close", "polkit"])?;
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<Snapshot> {
        let status = noctalia_status()?;
        let power = smc(&self.hwmon)
            .into_iter()
            .find(|(l, _)| l == "Total System Power")
            .map(|(_, v)| v);
        let music = if self.player.is_empty() {
            String::new()
        } else {
            stdout(&["playerctl", "-p", &self.player, "status"])?
                .trim()
                .to_owned()
        };
        let mut snap = Snapshot {
            locked: truthy(status.get("locked")),
            screen: percent(self.dev.screen.as_deref()),
            keyboard: percent(self.dev.kbd.as_deref()),
            power: power.map(|p| py_round(p as f64 / 1e6)),
            job: self.job_active()?,
            battery: self
                .dev
                .battery
                .as_ref()
                .map(|b| (read(b.join("capacity")), read(b.join("status")))),
            plugged: self
                .dev
                .ac
                .as_ref()
                .map(|ac| read(ac.join("online")).as_deref() == Some("1")),
            music: if music.is_empty() {
                "Off".into()
            } else {
                music.clone()
            },
            volume: None,
            artist: None,
            title: None,
        };
        if !music.is_empty() {
            let volume = stdout(&["playerctl", "-p", &self.player, "volume"])?;
            let volume = volume.trim();
            if !volume.is_empty() {
                let v: f64 = volume.parse()?;
                if !v.is_finite() {
                    return Err(format!("cannot convert float {volume} to integer").into());
                }
                snap.volume = Some(py_round(v * 100.0));
            }
            let meta = stdout(&[
                "playerctl",
                "-p",
                &self.player,
                "metadata",
                "--format",
                "{{artist}}\t{{title}}",
            ])?;
            let (artist, title) = meta.trim().split_once('\t').unwrap_or((meta.trim(), ""));
            snap.artist = Some(artist.into());
            snap.title = Some(title.into());
        }
        Ok(snap)
    }

    // ---- HA plumbing

    fn block_on_ha<T>(&self, fut: impl Future<Output = Result<T>>) -> Result<T> {
        Handle::current()
            .block_on(async { tokio::time::timeout(Duration::from_secs(10), fut).await? })
    }

    fn notify(&self, title: &str, message: &str) -> Result<()> {
        let Some(ns) = &self.notify_service else {
            return Ok(());
        };
        self.block_on_ha(self.service("notify", ns, json!({"title": title, "message": message})))
    }

    fn say_offline(&self) {
        let entity = format!("sensor.{}_last_seen", self.prefix);
        if let Err(e) = self.block_on_ha(self.post_state(
            &entity,
            json!(EPOCH),
            json!({"device_class": "timestamp"}),
        )) {
            warn!("offline notice failed: {e}");
        }
    }

    async fn service(&self, domain: &str, name: &str, data: Value) -> Result<()> {
        let url = format!("{}/api/services/{domain}/{name}", self.url);
        self.http
            .post(url)
            .json(&data)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn post_state(&self, entity_id: &str, state: Value, attributes: Value) -> Result<()> {
        let body = json!({"state": state, "attributes": attributes});
        if self.sent().get(entity_id) == Some(&body) {
            return Ok(());
        }
        let url = format!("{}/api/states/{entity_id}", self.url);
        self.http
            .post(url)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        self.sent().insert(entity_id.to_owned(), body);
        Ok(())
    }

    async fn call(self: Arc<Self>, entity_id: String) {
        let Some(&(_, action, cooldown)) = self.actions.iter().find(|(e, _, _)| *e == entity_id)
        else {
            return;
        };
        if !self.st().busy.insert(entity_id.clone()) {
            return;
        }
        let ready = {
            let mut st = self.st();
            let last = st.last_run.get(&entity_id).copied().unwrap_or(-cooldown);
            let ready = now() - last >= cooldown;
            if ready {
                st.last_run.insert(entity_id.clone(), now());
            }
            ready
        };
        if ready {
            let this = self.clone();
            match tokio::task::spawn_blocking(move || this.act(action)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => error!("{} failed: {e}", action.name()),
                Err(e) => error!("{} failed: {e}", action.name()),
            }
        } else {
            warn!("{} ignored: cooldown", action.name());
        }
        self.st().busy.remove(&entity_id);
        self.poll_now.notify_one();
    }

    async fn commands(self: Arc<Self>, mut queue: mpsc::UnboundedReceiver<Value>) {
        while let Some(data) = queue.recv().await {
            let this = self.clone();
            let d = data.clone();
            let result = match level(&data) {
                Err(e) => Err(e.into()),
                Ok(pct) => tokio::task::spawn_blocking(move || {
                    this.command(
                        d.get("target").and_then(Value::as_str),
                        d.get("cmd").and_then(Value::as_str),
                        pct,
                    )
                })
                .await
                .unwrap_or_else(|e| Err(e.into())),
            };
            if let Err(e) = result {
                error!("command {data} failed: {e}");
            }
            self.poll_now.notify_one();
        }
    }

    fn on_trigger(self: &Arc<Self>, trigger: &Value) {
        let (before, after) = (trigger.get("from_state"), trigger.get("to_state"));
        // No from_state, or from unavailable: HA restoring the helper, not a press.
        let (true, true) = (truthy(before), truthy(after)) else {
            return;
        };
        let (before, after) = (&before.unwrap()["state"], &after.unwrap()["state"]);
        if before == "unavailable" {
            return;
        }
        let Some(entity_id) = trigger["entity_id"].as_str().map(str::to_owned) else {
            return;
        };
        if entity_id == self.job_entity {
            if before == "off" && after == "on" {
                tokio::spawn(self.clone().call(entity_id));
            } else if before == "on" && after == "off" {
                // The agent only turns this off itself once the job is gone, so this is the user.
                let this = self.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = this.cancel_job() {
                        error!("cancel_job failed: {e}");
                    }
                });
            }
        } else if after == "on" {
            // Momentary: HomeKit's own reset for input_button takes 10 s.
            let this = self.clone();
            let id = entity_id.clone();
            tokio::spawn(async move {
                if let Err(e) = this
                    .service("input_boolean", "turn_off", json!({"entity_id": id}))
                    .await
                {
                    error!("turn_off {id} failed: {}", describe(&e));
                }
            });
            tokio::spawn(self.clone().call(entity_id));
        }
    }

    async fn listen(self: &Arc<Self>, queue: &mpsc::UnboundedSender<Value>) -> Result<()> {
        let mut ws = Ws::connect(&self.url, true).await?;
        ws.auth(&self.token).await?;
        let entities: Vec<&str> = self.actions.iter().map(|(e, _, _)| e.as_str()).collect();
        ws.send(&json!({"id": 1, "type": "subscribe_trigger",
                        "trigger": {"platform": "state", "entity_id": entities}}))
            .await?;
        ws.send(&json!({"id": 2, "type": "subscribe_events", "event_type": "ha_remote_cmd"}))
            .await?;
        // HA may have restarted and lost pushed states.
        self.sent().clear();
        self.poll_now.notify_one();
        info!("connected");
        while let Some(data) = ws.recv().await? {
            if data["type"] == "result" && !truthy(data.get("success")) {
                let err = data.get("error").map_or("None".into(), Value::to_string);
                return Err(ha_remote::Fatal(format!("subscribe failed: {err}")).into());
            }
            if data["type"] != "event" {
                continue;
            }
            match data["id"].as_i64() {
                Some(1) => self.on_trigger(&data["event"]["variables"]["trigger"]),
                Some(2) => {
                    let _ = queue.send(data["event"]["data"].clone());
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn auth_link(self: Arc<Self>, mut rx: mpsc::UnboundedReceiver<Value>) {
        loop {
            if let Ok(stream) = tokio::net::UnixStream::connect(AUTH_SOCKET).await {
                while rx.try_recv().is_ok() {}
                let (active, locked) = {
                    let st = self.st();
                    (st.active, st.locked)
                };
                self.tell_auth(json!({"type": "presence", "active": active}));
                self.tell_auth(json!({"type": "locked", "locked": locked}));
                let (read, mut write) = stream.into_split();
                let mut lines = BufReader::new(read).lines();
                loop {
                    tokio::select! {
                        line = lines.next_line() => {
                            let Ok(Some(line)) = line else { break };
                            let Ok(msg) = serde_json::from_str::<Value>(&line) else { break };
                            let this = self.clone();
                            match msg["type"].as_str() {
                                Some("polkit") => {
                                    let submit = truthy(msg.get("submit"));
                                    tokio::task::spawn_blocking(move || {
                                        if let Err(e) = this.polkit_panel(submit) {
                                            error!("polkit_panel failed: {e}");
                                        }
                                    });
                                }
                                Some("unlock") => {
                                    tokio::task::spawn_blocking(move || {
                                        if let Err(e) = this.unlock() {
                                            error!("unlock failed: {e}");
                                        }
                                    });
                                }
                                _ => {}
                            }
                        }
                        Some(msg) = rx.recv() => {
                            if write.write_all(format!("{msg}\n").as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }

    async fn publish(self: &Arc<Self>) -> Result<Snapshot> {
        let this = self.clone();
        let s = tokio::task::spawn_blocking(move || this.snapshot()).await??;
        let changed = {
            let mut st = self.st();
            let changed = s.locked != st.locked;
            st.locked = s.locked;
            changed
        };
        if changed {
            self.tell_auth(json!({"type": "locked", "locked": s.locked}));
        }
        if !s.locked {
            let this = self.clone();
            tokio::task::spawn_blocking(move || this.kbd_restore()).await??;
        }
        let (screen_off, unlocking_until) = {
            let mut st = self.st();
            if let Some(v) = s.screen.filter(|v| *v != 0) {
                st.screen_level = v;
            }
            if let Some(v) = s.keyboard.filter(|v| *v != 0) {
                st.kbd_level = v;
            }
            (st.screen_off, st.unlocking_until)
        };
        let (name, p) = (&self.name, &self.prefix);
        let on_off = |b: bool| if b { "on" } else { "off" };
        // device_class lock: on = unlocked
        self.post_state(&self.locked_entity, json!(on_off(!s.locked)),
            json!({"friendly_name": format!("{name} locked"), "device_class": "lock", "icon": "mdi:monitor-lock",
                   "unlocking": s.locked && now() < unlocking_until}))
            .await?;
        let idle = self.idle.load(Ordering::Relaxed);
        self.post_state(
            &format!("binary_sensor.{p}_active"),
            json!(on_off(!(s.locked || idle))),
            json!({"friendly_name": format!("{name} in use"), "device_class": "occupancy"}),
        )
        .await?;
        if let Some(plugged) = s.plugged {
            self.post_state(
                &format!("binary_sensor.{p}_plugged_in"),
                json!(on_off(plugged)),
                json!({"friendly_name": format!("{name} plugged in"), "device_class": "plug"}),
            )
            .await?;
        }
        if let Some((battery, battery_state)) = &s.battery {
            self.post_state(
                &format!("sensor.{p}_battery"),
                json!(battery),
                json!({"friendly_name": format!("{name} battery"), "device_class": "battery",
                       "unit_of_measurement": "%", "state_class": "measurement"}),
            )
            .await?;
            self.post_state(&format!("sensor.{p}_battery_state"), json!(battery_state),
                json!({"friendly_name": format!("{name} battery state"), "icon": "mdi:battery-charging"}))
                .await?;
        }
        let screen = if screen_off { Some(0) } else { s.screen };
        self.post_state(&format!("sensor.{p}_screen_brightness"), json!(screen),
            json!({"friendly_name": format!("{name} screen brightness"), "unit_of_measurement": "%"}))
            .await?;
        self.post_state(&format!("sensor.{p}_keyboard_brightness"), json!(s.keyboard),
            json!({"friendly_name": format!("{name} keyboard brightness"), "unit_of_measurement": "%"}))
            .await?;
        self.post_state(
            &format!("sensor.{p}_music"),
            json!(s.music),
            json!({"friendly_name": format!("{name} music"), "icon": "mdi:music",
                   "volume": s.volume, "artist": s.artist, "title": s.title}),
        )
        .await?;
        Ok(s)
    }

    async fn post_smc(&self) -> Result<()> {
        let hwmon = self.hwmon.clone();
        for (label, value) in tokio::task::spawn_blocking(move || smc(&hwmon)).await? {
            if let Some((entity, state, attrs)) =
                smc_entity(&self.prefix, &self.name, &label, value)
            {
                self.post_state(&entity, state, attrs).await?;
            }
        }
        Ok(())
    }

    async fn mirror_job(&self, active: bool) -> Result<()> {
        let (was, started) = {
            let st = self.st();
            (st.job_was_active, st.job_started)
        };
        if active != was && now() - started > 10.0 {
            if was {
                let out = run_timeout(
                    &[
                        "systemctl",
                        "--user",
                        "show",
                        "-p",
                        "Result",
                        "--value",
                        &self.job_unit,
                    ],
                    Duration::from_secs(10),
                )
                .await?;
                let mut result = String::from_utf8_lossy(&out.stdout).trim().to_owned();
                {
                    let mut st = self.st();
                    if st.job_cancelled {
                        result = "cancelled".into();
                    }
                    st.job_cancelled = false;
                }
                info!("{} finished: {result}", self.job_unit);
                if let Some(ns) = &self.notify_service {
                    self.service("notify", ns,
                                 json!({"title": format!("{} job", self.name), "message": format!("Finished: {result}")}))
                        .await?;
                }
            }
            self.st().job_was_active = active;
        }
        if now() - self.st().job_started > 10.0 || active {
            let r = self
                .http
                .get(format!("{}/api/states/{}", self.url, self.job_entity))
                .send()
                .await?;
            let on = r.status().as_u16() < 400 && r.json::<Value>().await?["state"] == "on";
            // While stopping, leave the toggle off instead of re-asserting it.
            if on != active && !(self.st().job_cancelled && active) {
                self.st().last_run.insert(self.job_entity.clone(), now());
                let verb = if active { "turn_on" } else { "turn_off" };
                self.service("input_boolean", verb, json!({"entity_id": self.job_entity}))
                    .await?;
            }
        }
        Ok(())
    }

    async fn sync_nuphy(self: Arc<Self>) {
        let (mut pushed, mut tried): (Option<i64>, Option<i64>) = (None, None);
        let mut tried_at = 0.0;
        loop {
            let level = percent(self.dev.kbd.as_deref());
            if level != pushed && (level != tried || now() - tried_at > 10.0) {
                (tried, tried_at) = (level, now());
                if tokio::task::spawn_blocking(move || nuphy_set(level))
                    .await
                    .unwrap_or(false)
                {
                    pushed = level;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn poll_once(self: &Arc<Self>, slow: &mut f64) -> Result<()> {
        let s = self.publish().await?;
        if now() - *slow > 30.0 {
            *slow = now();
            let (name, p) = (&self.name, &self.prefix);
            self.post_state(
                &format!("sensor.{p}_power"),
                json!(s.power),
                json!({"friendly_name": format!("{name} power draw"), "device_class": "power",
                       "unit_of_measurement": "W", "state_class": "measurement"}),
            )
            .await?;
            self.post_smc().await?;
            self.post_state(
                &format!("sensor.{p}_last_seen"),
                json!(utc_now_iso()),
                json!({"friendly_name": format!("{name} last seen"), "device_class": "timestamp"}),
            )
            .await?;
        }
        self.mirror_job(s.job).await
    }

    async fn poll(self: Arc<Self>) {
        let mut slow = 0.0;
        let mut last_error: Option<String> = None;
        loop {
            match self.poll_once(&mut slow).await {
                Ok(()) => last_error = None,
                Err(e) => {
                    let err = describe(&e);
                    if last_error.as_ref() != Some(&err) {
                        warn!("poll failed: {err}");
                    }
                    last_error = Some(err);
                }
            }
            if tokio::time::timeout(POLL_S, self.poll_now.notified())
                .await
                .is_ok()
            {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }

    async fn run_forever(self: Arc<Self>, to_auth: mpsc::UnboundedReceiver<Value>) {
        let (input_tx, mut input_rx) = mpsc::unbounded_channel();
        let this = self.clone();
        std::thread::spawn(move || {
            if let Err(e) = idle_watch(this, input_tx) {
                error!("idle watcher stopped: {e}");
            }
        });
        let this = self.clone();
        tokio::spawn(async move {
            while let Some(active) = input_rx.recv().await {
                this.presence(active);
            }
        });
        let (queue_tx, queue_rx) = mpsc::unbounded_channel();
        tokio::spawn(self.clone().poll());
        tokio::spawn(self.clone().commands(queue_rx));
        tokio::spawn(self.clone().auth_link(to_auth));
        if self.dev.kbd.is_some() {
            tokio::spawn(self.clone().sync_nuphy());
        }
        let mut delay = 1;
        loop {
            match self.listen(&queue_tx).await {
                Ok(()) => delay = 1,
                Err(e) => {
                    exit_if_fatal(&e);
                    warn!("disconnected: {e}{}", tailscale_note().await);
                }
            }
            tokio::time::sleep(Duration::from_secs(delay)).await;
            delay = (delay * 2).min(60);
        }
    }
}

/// Never the request headers: they carry the token.
fn describe(e: &ha_remote::Error) -> String {
    e.downcast_ref::<reqwest::Error>()
        .map_or_else(|| e.to_string(), http_error)
}

#[derive(Clone, Copy)]
enum Watch {
    Away,
    Touch,
}

struct IdleState {
    remote: Arc<Remote>,
    input: mpsc::UnboundedSender<bool>,
}

impl Dispatch<WlRegistry, GlobalListContents> for IdleState {
    fn event(
        _: &mut Self,
        _: &WlRegistry,
        _: <WlRegistry as wayland_client::Proxy>::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

delegate_noop!(IdleState: ignore WlSeat);
delegate_noop!(IdleState: ExtIdleNotifierV1);

impl Dispatch<ExtIdleNotificationV1, Watch> for IdleState {
    fn event(
        state: &mut Self,
        _: &ExtIdleNotificationV1,
        event: ext_idle_notification_v1::Event,
        watch: &Watch,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        let idled = matches!(event, ext_idle_notification_v1::Event::Idled);
        match watch {
            Watch::Away => state.remote.idle.store(idled, Ordering::Relaxed),
            Watch::Touch => {
                let _ = state.input.send(!idled);
            }
        }
    }
}

fn idle_watch(remote: Arc<Remote>, input: mpsc::UnboundedSender<bool>) -> Result<()> {
    let conn = Connection::connect_to_env()?;
    let (globals, mut queue) = registry_queue_init::<IdleState>(&conn)?;
    let qh = queue.handle();
    let seat: WlSeat = globals.bind(&qh, 1..=1, ())?;
    let notifier: ExtIdleNotifierV1 = globals.bind(&qh, 1..=2, ())?;
    // v2 ignores idle inhibitors, so a playing video does not count as presence.
    let make = |ms, watch| {
        if notifier.version() >= 2 {
            notifier.get_input_idle_notification(ms, &seat, &qh, watch)
        } else {
            notifier.get_idle_notification(ms, &seat, &qh, watch)
        }
    };
    let _away = make(IDLE_AFTER_MS, Watch::Away);
    let _touch = make(1000, Watch::Touch);
    let mut state = IdleState { remote, input };
    loop {
        queue.blocking_dispatch(&mut state)?;
    }
}

#[tokio::main]
async fn main() {
    let cfg = load_config();
    let (tx, rx) = mpsc::unbounded_channel();
    let remote = Arc::new(Remote::new(&cfg, tx));
    remote.run_forever(rx).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels() {
        assert_eq!(level(&json!({"percentage": "42.5"})), Ok(Some(42)));
        assert_eq!(level(&json!({"percentage": 0})), Ok(Some(1)));
        assert_eq!(
            level(&json!({"percentage": "None", "brightness": 255})),
            Ok(Some(100))
        );
        assert_eq!(level(&json!({"brightness": "128"})), Ok(Some(50)));
        assert_eq!(
            level(&json!({"percentage": "", "brightness": null})),
            Ok(None)
        );
        assert!(level(&json!({"percentage": "x"})).is_err());
    }

    #[test]
    fn smc_entities() {
        let (id, state, attrs) = smc_entity("mba", "MBA", "Fan 1", 2000).unwrap();
        assert_eq!((id.as_str(), state), ("sensor.mba_fan_1", json!(2000)));
        assert_eq!(attrs["friendly_name"], "MBA fan 1");
        let (id, state, _) = smc_entity("mba", "MBA", "CPU/GPU Temperature", 45850).unwrap();
        assert_eq!(
            (id.as_str(), state),
            ("sensor.mba_cpu_gpu_temp", json!(45.9))
        );
        let (id, state, _) = smc_entity("mba", "MBA", "Hotspot Temp", 45750).unwrap();
        assert_eq!(
            (id.as_str(), state),
            ("sensor.mba_hotspot_temp", json!(45.8))
        );
        assert!(smc_entity("mba", "MBA", "Total System Power", 1).is_none());
    }

    #[test]
    fn nuphy_frames() {
        let mut f = frame(0x0f, 0xd6, &[1, 1, 0, 1, 50]);
        checksum(&mut f);
        assert_eq!(
            &f[..9],
            &[0x55, 0xd6, 0, 0x76, 0x0e, 0x0e, 0x0f, 0x0e, 50 ^ 0x0f]
        );
        assert!(f[9..].iter().all(|b| *b == 0));
    }
}
