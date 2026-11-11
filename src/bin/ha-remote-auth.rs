use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use ha_remote::{Fatal, Result, Ws, exit_if_fatal, fatal, info, read_toml, tailscale_note, warn};
use ipnet::IpNet;
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::OwnedReadHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, watch};
use tokio::task::spawn_local;
use tokio::time::{Instant, sleep};

const CONFIG_PATH: &str = "/etc/ha-remote/auth.toml";
const DENY_EVENT: &str = "Deny";
const ACTION_EVENT: &str = "mobile_app_notification_action";
const SOCKET: &str = ha_remote::AUTH_SOCKET;
const PENDING: &str = "/var/lib/ha-remote/pending";
const HELPER: &str = "/usr/libexec/ha-remote/pam-helper";
const PAM_SERVICES: [&str; 4] = ["sudo", "sudo-i", "polkit-1", "login"];
const HOLD_MAX_S: f64 = 60.0;
const MAX_LINE: u64 = 65536;
const RATE_LIMIT: usize = 5;
const RATE_WINDOW: Duration = Duration::from_secs(60);

fn pam_files(etc: &Path, vendor: &Path) -> Vec<(PathBuf, PathBuf)> {
    PAM_SERVICES
        .iter()
        .map(|s| (etc.join(s), vendor.join(s)))
        .filter(|(path, vendor)| path.exists() || vendor.exists())
        .collect()
}

fn pam_lines(service: &str) -> Vec<String> {
    let finish = format!(
        "auth       sufficient   pam_exec.so quiet seteuid expose_authtok {HELPER} finish\n"
    );
    // The lock screen only runs PAM after a submit, so there is nothing to start early.
    if service == "login" {
        return vec![finish];
    }
    // noctalia's polkit panel does not make room for an info line.
    let options = if service.starts_with("sudo") {
        "seteuid stdout"
    } else {
        "seteuid"
    };
    // polkit's start can answer for the phone while the screen is locked.
    let control = if service == "polkit-1" {
        "sufficient"
    } else {
        "optional"
    };
    vec![
        format!("auth       {control:<13}pam_exec.so quiet {options} {HELPER} start\n"),
        finish,
    ]
}

fn first_auth(lines: &[String]) -> usize {
    lines
        .iter()
        .position(|l| l.split_whitespace().next() == Some("auth"))
        .unwrap_or(lines.len())
}

fn service_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
}

fn write_atomic(path: &Path, text: &str) -> io::Result<()> {
    let tmp = path.with_extension("ha-remote-tmp");
    std::fs::write(&tmp, text)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    std::fs::rename(&tmp, path)
}

fn enable(etc: &Path, vendor_dir: &Path) -> io::Result<()> {
    for (path, vendor) in pam_files(etc, vendor_dir) {
        let text = std::fs::read_to_string(if path.exists() { &path } else { &vendor })?;
        let mut lines: Vec<String> = text.split_inclusive('\n').map(String::from).collect();
        let wanted = pam_lines(service_name(&path));
        let at = first_auth(&lines);
        if lines.get(at..at + wanted.len()) == Some(&wanted[..]) {
            continue;
        }
        lines.retain(|l| !l.contains(HELPER));
        if let Some(last) = lines.last_mut().filter(|l| !l.ends_with('\n')) {
            last.push('\n');
        }
        let at = first_auth(&lines);
        lines.splice(at..at, wanted);
        write_atomic(&path, &lines.concat())?;
        println!("enabled {}", path.display());
    }
    Ok(())
}

fn disable(etc: &Path, vendor_dir: &Path) -> io::Result<()> {
    for (path, vendor) in pam_files(etc, vendor_dir) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if !text.contains(HELPER) {
            continue;
        }
        let text: String = text
            .split_inclusive('\n')
            .filter(|l| !l.contains(HELPER))
            .collect();
        if vendor.exists() && std::fs::read_to_string(&vendor)?.trim_end() == text.trim_end() {
            std::fs::remove_file(&path)?;
        } else {
            write_atomic(&path, &text)?;
        }
        println!("disabled {}", path.display());
    }
    Ok(())
}

struct Stat {
    comm: String,
    ppid: i32,
    tty_nr: i64,
}

fn proc_stat(pid: i32) -> Option<Stat> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (head, rest) = text.rsplit_once(')')?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    Some(Stat {
        comm: head.split_once('(')?.1.to_owned(),
        ppid: fields.get(1)?.parse().ok()?,
        tty_nr: fields.get(4)?.parse().ok()?,
    })
}

fn alive(pid: i32) -> bool {
    proc_stat(pid).is_some()
}

fn ancestors(mut pid: i32) -> Vec<(i32, String)> {
    let mut chain = Vec::new();
    while pid > 1 {
        let Some(stat) = proc_stat(pid) else { break };
        chain.push((pid, stat.comm));
        pid = stat.ppid;
    }
    chain
}

fn args(pid: i32) -> String {
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return String::new();
    };
    let raw = String::from_utf8_lossy(&raw).replace(|c: char| c.is_control() && c != '\0', " ");
    raw.split('\0')
        .skip(1)
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_owned()
}

fn proc_pids() -> impl Iterator<Item = (i32, PathBuf)> {
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| Some((e.file_name().to_str()?.parse().ok()?, e.path())))
}

fn real_uid(pid: i32) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn pkexec_commands() -> String {
    proc_pids()
        .filter(|(_, path)| {
            std::fs::read_link(path.join("exe")).is_ok_and(|e| e == Path::new("/usr/bin/pkexec"))
        })
        .map(|(pid, _)| args(pid))
        .filter(|a| !a.is_empty())
        .collect::<Vec<_>>()
        .join(" or ")
}

fn tty_of(pid: i32) -> Option<String> {
    let nr = proc_stat(pid).map_or(0, |s| s.tty_nr);
    let (major, minor) = ((nr >> 8) & 0xFFF, (nr & 0xFF) | ((nr >> 12) & 0xFFF00));
    match major {
        136 => Some(format!("/dev/pts/{minor}")),
        4 if 0 < minor && minor < 64 => Some(format!("/dev/tty{minor}")),
        _ => None,
    }
}

/// An address field of /proc/net/tcp{,6}: hex in host-order 32-bit words.
fn tcp_addr(field: &str) -> Option<IpAddr> {
    let hex = field.split(':').next()?;
    let raw: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect::<Option<_>>()?;
    let bytes: Vec<u8> = raw
        .chunks(4)
        .flat_map(|w| w.iter().rev().copied())
        .collect();
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?))),
        16 => {
            let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?);
            Some(v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4))
        }
        _ => None,
    }
}

fn ssh_peer(pid: i32) -> Option<IpAddr> {
    let fds = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
    let inodes: HashSet<String> = fds
        .map(|fd| {
            let link = std::fs::read_link(fd.ok()?.path()).ok()?;
            let link = link.to_string_lossy();
            Some(
                link.get(8..link.len().saturating_sub(1))
                    .unwrap_or_default()
                    .to_owned(),
            )
        })
        .collect::<Option<_>>()?;
    for name in ["tcp", "tcp6"] {
        let table = std::fs::read_to_string(format!("/proc/{pid}/net/{name}")).ok()?;
        for line in table.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() > 9 && inodes.contains(f[9]) && f[3] == "01" {
                return tcp_addr(f[2]);
            }
        }
    }
    None
}

fn sd_notify(msg: &[u8]) {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    let Some(addr) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let addr = addr.to_string_lossy();
    let addr = match addr.strip_prefix('@') {
        Some(name) => SocketAddr::from_abstract_name(name.as_bytes()),
        None => SocketAddr::from_pathname(&*addr),
    };
    if let (Ok(sock), Ok(addr)) = (UnixDatagram::unbound(), addr) {
        let _ = sock.send_to_addr(msg, &addr);
    }
}

fn press_enter(tty: &str) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(tty)?;
    let c = b'\n';
    // SAFETY: TIOCSTI reads one byte through the pointer, which outlives the call.
    if unsafe { libc::ioctl(f.as_raw_fd(), libc::TIOCSTI, &c) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn kill(pid: i32, sig: i32) -> io::Result<()> {
    // SAFETY: kill(2) takes plain integers.
    if unsafe { libc::kill(pid, sig) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn token_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    // SAFETY: buf is valid for n bytes.
    let got = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), n, 0) };
    assert_eq!(got, n as isize, "getrandom");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// `urllib.parse.quote(s, safe="")`
fn quote(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"_.-~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_owned();
    }
    s.chars().take(n - 1).chain(['…']).collect()
}

struct User {
    name: String,
    uid: u32,
}

fn getpwnam(name: &str) -> Option<User> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: called once at startup before any threads; the entry is copied out at once.
    let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
    // SAFETY: non-null getpwnam results point to a valid passwd.
    (!pw.is_null()).then(|| User {
        name: name.to_owned(),
        uid: unsafe { (*pw).pw_uid },
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    url: String,
    token: String,
    notify_service: String,
    approver_user_id: String,
    user: String,
    device_name: Option<String>,
    timeout_s: Option<toml::Value>,
    #[serde(default)]
    policy: Policy,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Policy {
    tap: Option<Vec<String>>,
    #[serde(default)]
    never: Vec<String>,
    #[serde(default)]
    ssh_from: Vec<String>,
}

/// `ipaddress.ip_network(s)`: strict, a bare address is a single host.
fn ip_network(s: &str) -> Option<IpNet> {
    let net = s
        .parse::<IpNet>()
        .ok()
        .or_else(|| s.parse::<IpAddr>().ok().map(IpNet::from))?;
    (net.trunc() == net).then_some(net)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Sudo,
    Polkit,
    Lockscreen,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Sudo => "sudo",
            Kind::Polkit => "polkit",
            Kind::Lockscreen => "lockscreen",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verdict {
    Pending,
    Approved,
    Denied,
    Cancelled,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Msg {
    Presence {
        active: bool,
    },
    Lockscreen,
    Locked {
        locked: bool,
    },
    Hold {
        s: f64,
    },
    Auth(AuthReq),
    #[serde(other)]
    Other,
}

#[derive(Deserialize, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum Stage {
    Start,
    Finish,
}

#[derive(Deserialize)]
struct AuthReq {
    stage: Stage,
    #[serde(default)]
    typed: bool,
    service: Option<String>,
    user: Option<String>,
    #[serde(default)]
    rhost: String,
}

struct Prompt {
    kind: Kind,
    what: String,
    app: i32,
}

struct Request {
    kind: Kind,
    what: String,
    app: i32,
    tty: Option<String>,
    nonce: String,
    verdict: watch::Sender<Verdict>,
    blocking: Cell<bool>,
    event: Option<String>,
    sub: Cell<Option<u64>>,
}

impl Request {
    fn verdict(&self) -> Verdict {
        *self.verdict.borrow()
    }

    fn done(&self) -> bool {
        self.verdict() != Verdict::Pending
    }

    fn approved(&self) -> bool {
        self.verdict() == Verdict::Approved
    }

    fn cancel(&self) {
        self.verdict.send_if_modified(|v| {
            let pending = *v == Verdict::Pending;
            if pending {
                *v = Verdict::Cancelled;
            }
            pending
        });
    }

    fn tag(&self) -> String {
        format!("ha-remote-{}", &self.nonce[..8])
    }
}

type Writer = mpsc::UnboundedSender<Vec<u8>>;

struct Auth {
    url: String,
    token: String,
    notify_service: String,
    approver: String,
    user: User,
    name: String,
    timeout: Duration,
    tap: HashSet<String>,
    never: Vec<Regex>,
    ssh_from: Vec<IpNet>,
    asked: RefCell<Vec<Instant>>,
    stale: RefCell<Vec<String>>,
    hold_until: Cell<Option<Instant>>,
    requests: RefCell<HashMap<i32, Rc<Request>>>,
    agent: RefCell<Option<(u64, Writer)>>,
    locked: Cell<bool>,
    connected: Cell<bool>,
    ws: RefCell<Option<mpsc::UnboundedSender<Value>>>,
    ids: Cell<u64>,
    conns: Cell<u64>,
    #[cfg_attr(test, allow(dead_code))]
    http: reqwest::Client,
    #[cfg(test)]
    calls: RefCell<Vec<(String, String, Value)>>,
}

impl Auth {
    fn new(cfg: Config) -> Auth {
        let policy = cfg.policy;
        let timeout = match &cfg.timeout_s {
            None => 60.0,
            Some(v) => v
                .as_float()
                .or_else(|| v.as_integer().map(|i| i as f64))
                .unwrap_or_else(|| fatal("timeout_s must be a number")),
        };
        let http = ha_remote::http_client(&cfg.token, Some(Duration::from_secs(10)), None);
        Auth {
            url: cfg.url.trim_end_matches('/').to_owned(),
            token: cfg.token,
            notify_service: cfg.notify_service,
            approver: cfg.approver_user_id,
            user: getpwnam(&cfg.user)
                .unwrap_or_else(|| fatal(&format!("no such user: {}", cfg.user))),
            name: cfg.device_name.unwrap_or_else(ha_remote::short_hostname),
            timeout: Duration::from_secs_f64(timeout.max(0.0)),
            tap: policy
                .tap
                .unwrap_or_else(|| ["sudo", "polkit", "lockscreen"].map(String::from).into())
                .into_iter()
                .collect(),
            never: policy
                .never
                .iter()
                .map(|p| Regex::new(p).unwrap_or_else(|e| fatal(&format!("policy.never: {e}"))))
                .collect(),
            ssh_from: policy
                .ssh_from
                .iter()
                .map(|n| {
                    ip_network(n)
                        .unwrap_or_else(|| fatal(&format!("policy.ssh_from: bad network {n}")))
                })
                .collect(),
            asked: RefCell::default(),
            stale: RefCell::new(
                std::fs::read_to_string(PENDING)
                    .map(|t| t.split_whitespace().map(String::from).collect())
                    .unwrap_or_default(),
            ),
            hold_until: Cell::new(None),
            requests: RefCell::default(),
            agent: RefCell::default(),
            locked: Cell::new(false),
            connected: Cell::new(false),
            ws: RefCell::default(),
            ids: Cell::new(4),
            conns: Cell::new(0),
            http,
            #[cfg(test)]
            calls: RefCell::default(),
        }
    }
}

impl Auth {
    fn describe(&self, pid: i32, uid: u32, req: &AuthReq) -> Option<Prompt> {
        self.describe_chain(&ancestors(pid), uid, req, real_uid)
    }

    fn describe_chain(
        &self,
        chain: &[(i32, String)],
        uid: u32,
        req: &AuthReq,
        real_uid: impl Fn(i32) -> Option<u32>,
    ) -> Option<Prompt> {
        if req.user.as_deref() != Some(&self.user.name) || !req.rhost.is_empty() {
            return None;
        }
        if chain.len() < 2 {
            return None;
        }
        let sshd: Vec<i32> = chain
            .iter()
            .filter(|(_, c)| c.starts_with("sshd"))
            .map(|&(p, _)| p)
            .collect();
        let mut via = String::new();
        if !sshd.is_empty() {
            let peer = sshd.into_iter().find_map(ssh_peer)?;
            if !self.ssh_from.iter().any(|net| net.contains(&peer)) {
                return None;
            }
            via = format!(" (ssh from {peer})");
        }
        let (app, ref app_comm) = chain[1];
        let service = req.service.as_deref();
        // Another local user's sudo or polkit helper may name us as PAM_USER.
        let asker_is_user = real_uid(app) == Some(self.user.uid);
        if uid == 0
            && asker_is_user
            && matches!(service, Some("sudo" | "sudo-i"))
            && app_comm == "sudo"
        {
            let what = args(app);
            let what = if what.is_empty() {
                "a shell".into()
            } else {
                what
            };
            return Some(Prompt {
                kind: Kind::Sudo,
                what: truncate(&what, 120) + &via,
                app,
            });
        }
        if uid == 0 && asker_is_user && service == Some("polkit-1") {
            let caller = chain
                .windows(2)
                .find(|w| w[0].1 == "pkttyagent")
                .map(|w| format!("{} {}", w[1].1, args(w[1].0)));
            let what = caller.or(Some(pkexec_commands()).filter(|s| !s.is_empty()));
            let what = what.unwrap_or_else(|| "a system action".into());
            return Some(Prompt {
                kind: Kind::Polkit,
                what: truncate(&what, 120) + &via,
                app,
            });
        }
        if uid == self.user.uid
            && service == Some("login")
            && chain.iter().any(|(_, c)| c == "noctalia")
        {
            // PAM runs in a forked child; key by the main process like ask_lockscreen.
            let app = chain.iter().rev().find(|(_, c)| c == "noctalia")?.0;
            return Some(Prompt {
                kind: Kind::Lockscreen,
                what: "unlock the screen".into(),
                app,
            });
        }
        None
    }

    async fn service(&self, domain: &str, name: &str, data: Value) -> Result<()> {
        #[cfg(test)]
        {
            self.calls
                .borrow_mut()
                .push((domain.into(), name.into(), data));
            Ok(())
        }
        #[cfg(not(test))]
        {
            self.http
                .post(format!("{}/api/services/{domain}/{name}", self.url))
                .json(&data)
                .timeout(Duration::from_secs(10))
                .send()
                .await?
                .error_for_status()?;
            Ok(())
        }
    }

    fn fire_url(event: &str, action: &str, cancel: Option<&str>) -> String {
        let mut q = format!("eventName={}&action={}", quote(event), quote(action));
        if let Some(c) = cancel {
            q += &format!("&x-cancel={}", quote(c));
        }
        format!("homeassistant://x-callback-url/fire_event?{q}")
    }

    async fn logbook(self: Rc<Self>, message: String) {
        let _ = self
            .service(
                "logbook",
                "log",
                json!({"name": self.name, "message": message}),
            )
            .await;
    }

    fn save(&self) {
        let tags: String = self
            .requests
            .borrow()
            .values()
            .map(|r| r.tag() + "\n")
            .collect();
        let _ = std::fs::write(PENDING, tags);
    }

    fn next_id(&self) -> u64 {
        let id = self.ids.get();
        self.ids.set(id + 1);
        id
    }

    fn ws_send(&self, msg: Value) {
        if let Some(ws) = &*self.ws.borrow() {
            let _ = ws.send(msg);
        }
    }

    fn subscribe(&self, request: &Request) {
        if self.ws.borrow().is_some()
            && let Some(event) = &request.event
        {
            let id = self.next_id();
            request.sub.set(Some(id));
            self.ws_send(json!({"id": id, "type": "subscribe_events", "event_type": event}));
        }
    }

    fn get(&self, app: i32) -> Option<Rc<Request>> {
        self.requests.borrow().get(&app).cloned()
    }

    fn is_current(&self, request: &Rc<Request>) -> bool {
        self.get(request.app)
            .is_some_and(|r| Rc::ptr_eq(&r, request))
    }

    async fn ask(self: &Rc<Self>, kind: Kind, what: &str, app: i32) -> Option<Rc<Request>> {
        let line = format!("{}: {what}", kind.as_str());
        if self.never.iter().any(|p| p.is_match(&line)) {
            info!("policy: password only for {}: {what}", kind.as_str());
            return None;
        }
        let now = Instant::now();
        self.asked.borrow_mut().retain(|&t| now - t < RATE_WINDOW);
        if self.asked.borrow().len() >= RATE_LIMIT {
            warn!("rate limited {}: {what}", kind.as_str());
            spawn_local(
                self.clone()
                    .logbook(format!("rate limited {}: {what}", kind.as_str())),
            );
            return None;
        }
        self.asked.borrow_mut().push(now);
        let tapped = self.tap.contains(kind.as_str());
        let request = Rc::new(Request {
            kind,
            what: what.to_owned(),
            app,
            tty: matches!(kind, Kind::Sudo | Kind::Polkit)
                .then(|| tty_of(app))
                .flatten(),
            nonce: token_hex(16),
            verdict: watch::Sender::new(Verdict::Pending),
            blocking: Cell::new(false),
            // The app's tap confirmation only shows the event name; HA caps it at 64.
            event: tapped.then(|| truncate(&line, 64)),
            sub: Cell::new(None),
        });
        self.requests.borrow_mut().insert(app, request.clone());
        self.save();
        info!("asking approval for {}: {what}", kind.as_str());
        let approve = format!("HAREMOTE_APPROVE_{}", request.nonce);
        let deny = format!("HAREMOTE_DENY_{}", request.nonce);
        let mut data =
            json!({"tag": request.tag(), "push": {"interruption-level": "time-sensitive"}});
        if let Some(event) = &request.event {
            let cancel = Self::fire_url(DENY_EVENT, &deny, None);
            data["url"] = Self::fire_url(event, &approve, Some(&cancel)).into();
        }
        data["actions"] = json!([
            {"action": approve, "title": "Approve", "authenticationRequired": true},
            {"action": deny, "title": "Deny", "destructive": true}]);
        self.subscribe(&request);
        let sent = self
            .service("notify", &self.notify_service, json!({
                "title": format!("{}: {}", self.name, kind.as_str()), "message": what, "data": data}))
            .await;
        if let Err(e) = sent {
            warn!("notify failed: {e}");
            self.discard(&request);
            return None;
        }
        spawn_local(self.clone().expire(request.clone()));
        Some(request)
    }

    fn discard(self: &Rc<Self>, request: &Rc<Request>) {
        if !self.is_current(request) {
            return;
        }
        self.requests.borrow_mut().remove(&request.app);
        self.save();
        request.cancel();
        if let Some(sub) = request.sub.get() {
            let id = self.next_id();
            self.ws_send(json!({"id": id, "type": "unsubscribe_events", "subscription": sub}));
        }
        spawn_local(self.clone().clear(request.tag()));
    }

    async fn clear(self: Rc<Self>, tag: String) {
        let _ = self
            .service(
                "notify",
                &self.notify_service,
                json!({"message": "clear_notification", "data": {"tag": tag}}),
            )
            .await;
    }

    async fn expire(self: Rc<Self>, request: Rc<Request>) {
        let deadline = Instant::now() + self.timeout;
        while self.is_current(&request) && Instant::now() < deadline {
            if !alive(request.app) {
                break;
            }
            sleep(Duration::from_secs(1)).await;
        }
        self.discard(&request);
    }

    async fn start(
        self: &Rc<Self>,
        prompt: Option<Prompt>,
        reader: &mut BufReader<OwnedReadHalf>,
        writer: &Writer,
    ) -> bool {
        let Some(Prompt { kind, what, app }) = prompt.filter(|_| self.connected.get()) else {
            return false;
        };
        let request = match self.get(app) {
            Some(r) => r,
            None => match self.ask(kind, &what, app).await {
                Some(r) => r,
                None => return false,
            },
        };
        let _ = writer.send(b"{\"asking\": true}\n".to_vec());
        // The lock screen covers the polkit panel, so nothing could submit it.
        if kind == Kind::Polkit && self.locked.get() {
            return self.wait(&request, reader).await;
        }
        false
    }

    async fn finish(
        self: &Rc<Self>,
        prompt: Option<Prompt>,
        typed: bool,
        reader: &mut BufReader<OwnedReadHalf>,
        writer: &Writer,
    ) -> bool {
        let Some(Prompt { kind, what, app }) = prompt else {
            return false;
        };
        let request = self.get(app);
        if let Some(r) = &request
            && (r.approved() || typed)
        {
            self.discard(r);
            return r.approved();
        }
        if typed || !self.connected.get() {
            return false;
        }
        // Submitted empty: wait here for the phone.
        let request = match request {
            Some(r) => r,
            None => {
                let Some(r) = self.ask(kind, &what, app).await else {
                    return false;
                };
                let _ = writer.send(b"{\"asking\": true}\n".to_vec());
                r
            }
        };
        self.wait(&request, reader).await
    }

    async fn wait(
        self: &Rc<Self>,
        request: &Rc<Request>,
        reader: &mut BufReader<OwnedReadHalf>,
    ) -> bool {
        request.blocking.set(true);
        let mut verdict = request.verdict.subscribe();
        let mut byte = [0u8; 1];
        tokio::select! {
            _ = verdict.wait_for(|v| *v != Verdict::Pending) => {}
            _ = reader.read(&mut byte) => {}
        }
        self.discard(request);
        Self::log_verdict(request);
        request.approved()
    }

    fn log_verdict(request: &Request) {
        let outcome = match request.verdict() {
            Verdict::Approved => "approved",
            Verdict::Denied => "denied",
            Verdict::Pending | Verdict::Cancelled => "not approved",
        };
        info!("{} {outcome}", request.kind.as_str());
    }

    fn agent_write(&self, msg: Value) {
        if let Some((_, w)) = &*self.agent.borrow() {
            let _ = w.send(format!("{msg}\n").into_bytes());
        }
    }

    /// Answers the open password prompt; finish sees the verdict.
    fn submit(&self, request: &Request) -> io::Result<()> {
        Self::log_verdict(request);
        if !alive(request.app) {
            return Ok(());
        }
        let approved = request.approved();
        // A blocking wait already answers PAM; a denial must still dismiss the prompt.
        if approved && request.blocking.get() {
            return Ok(());
        }
        let has_agent = self.agent.borrow().is_some();
        if request.kind == Kind::Sudo || request.tty.is_some() {
            match (&request.tty, approved) {
                (Some(tty), true) => press_enter(tty)?,
                (_, false) => kill(request.app, libc::SIGINT)?,
                _ => {}
            }
        } else if request.kind == Kind::Polkit && has_agent {
            self.agent_write(json!({"type": "polkit", "submit": approved}));
        } else if request.kind == Kind::Lockscreen && approved && has_agent {
            self.agent_write(json!({"type": "unlock"}));
        }
        Ok(())
    }

    fn holding(&self) -> bool {
        self.hold_until.get().is_some_and(|t| Instant::now() < t)
    }

    async fn ask_lockscreen(self: Rc<Self>) {
        let uid = self.user.uid;
        let app = proc_pids().find(|(pid, path)| {
            proc_stat(*pid).is_some_and(|s| s.comm == "noctalia")
                && std::fs::metadata(path).is_ok_and(|m| m.uid() == uid)
                && args(*pid).is_empty()
        });
        if let Some((app, _)) = app
            && self.get(app).is_none()
            && self.connected.get()
            && !self.holding()
        {
            self.ask(Kind::Lockscreen, "unlock the screen", app).await;
        }
    }

    fn abandon(&self) {
        for request in self.requests.borrow().values() {
            if request.blocking.get() {
                request.cancel();
            }
        }
    }

    async fn handle(self: Rc<Self>, stream: UnixStream) {
        let Ok(cred) = stream.peer_cred() else { return };
        let (pid, uid) = (cred.pid().unwrap_or(0), cred.uid());
        let owner = uid == self.user.uid;
        if uid != 0 && !owner {
            return;
        }
        let conn = self.conns.get() + 1;
        self.conns.set(conn);
        let (read, mut write) = stream.into_split();
        let (writer, mut outbox) = mpsc::unbounded_channel::<Vec<u8>>();
        spawn_local(async move {
            while let Some(bytes) = outbox.recv().await {
                if write.write_all(&bytes).await.is_err() {
                    break;
                }
            }
        });
        let mut reader = BufReader::new(read);
        if let Err(e) = self
            .serve(pid, uid, owner, conn, &mut reader, &writer)
            .await
        {
            warn!("client {pid}: {e}");
        }
        if self
            .agent
            .borrow()
            .as_ref()
            .is_some_and(|(id, _)| *id == conn)
        {
            self.agent.replace(None);
            self.locked.set(false);
        }
    }

    async fn serve(
        self: &Rc<Self>,
        pid: i32,
        uid: u32,
        owner: bool,
        conn: u64,
        reader: &mut BufReader<OwnedReadHalf>,
        writer: &Writer,
    ) -> Result<()> {
        let mut line = String::new();
        loop {
            line.clear();
            if (&mut *reader).take(MAX_LINE).read_line(&mut line).await? == 0 {
                return Ok(());
            }
            match serde_json::from_str(&line)? {
                Msg::Presence { active } if owner => {
                    self.agent.replace(Some((conn, writer.clone())));
                    if active && !self.holding() {
                        // Input at the laptop: drop a blocking phone wait so the password prompt returns.
                        self.abandon();
                    }
                }
                Msg::Lockscreen if owner => {
                    spawn_local(self.clone().ask_lockscreen());
                }
                Msg::Locked { locked } if owner => self.locked.set(locked),
                Msg::Hold { s } if owner => {
                    let s = Duration::from_secs_f64(s.clamp(0.0, HOLD_MAX_S));
                    self.hold_until.set(Some(Instant::now() + s));
                }
                Msg::Auth(req) => {
                    let prompt = self.describe(pid, uid, &req);
                    let ok = if req.stage == Stage::Start {
                        self.start(prompt, reader, writer).await
                    } else {
                        self.finish(prompt, req.typed, reader, writer).await
                    };
                    let _ = writer.send(format!("{}\n", json!({"ok": ok})).into_bytes());
                    return Ok(());
                }
                _ => {}
            }
        }
    }

    fn on_action(self: &Rc<Self>, event: &Value) {
        let action = event["data"]["action"].as_str().unwrap_or_default();
        let (verb, nonce) = action.rsplit_once('_').unwrap_or(("", action));
        let request = self
            .requests
            .borrow()
            .values()
            .find(|r| ct_eq(&r.nonce, nonce))
            .cloned();
        let Some(request) = request else {
            return;
        };
        if request.done() || !matches!(verb, "HAREMOTE_APPROVE" | "HAREMOTE_DENY") {
            return;
        }
        let user_id = &event["context"]["user_id"];
        if user_id.as_str() != Some(&self.approver) {
            warn!(
                "ignoring {verb} from user {}",
                user_id.as_str().unwrap_or("None")
            );
            return;
        }
        let approved = verb == "HAREMOTE_APPROVE";
        let event_type = event["event_type"].as_str();
        // The Deny event's confirmation reads "Deny", so it must never approve.
        if approved && event_type != Some(ACTION_EVENT) && event_type != request.event.as_deref() {
            warn!(
                "ignoring approve from event {}",
                event_type.unwrap_or("None")
            );
            return;
        }
        request.verdict.send_replace(if approved {
            Verdict::Approved
        } else {
            Verdict::Denied
        });
        let outcome = if approved { "approved" } else { "denied" };
        spawn_local(self.clone().logbook(format!(
            "{outcome} {}: {}",
            request.kind.as_str(),
            request.what
        )));
        if let Err(e) = self.submit(&request) {
            warn!("submit failed: {e}");
        }
    }

    async fn handshake(&self, ws: &mut Ws) -> Result<()> {
        ws.auth(&self.token).await?;
        ws.send(&json!({"id": 1, "type": "auth/current_user"}))
            .await?;
        let me = ws.recv_some().await?;
        let id = me["result"]["id"]
            .as_str()
            .ok_or("auth/current_user returned no user id")?;
        if id == self.approver {
            return Err(Fatal(
                "token belongs to the approver; use a token of a separate HA user".into(),
            )
            .into());
        }
        ws.send(&json!({"id": 2, "type": "subscribe_events", "event_type": ACTION_EVENT}))
            .await?;
        ws.send(&json!({"id": 3, "type": "subscribe_events", "event_type": DENY_EVENT}))
            .await?;
        let mut ok = true;
        for _ in 0..2 {
            ok &= ws.recv_some().await?["success"] == true;
        }
        if !ok {
            return Err(
                Fatal("subscribe failed; the token's HA user must be an admin".into()).into(),
            );
        }
        Ok(())
    }

    async fn on_connect(&self) {
        let stale = self.stale.take();
        for tag in stale {
            let _ = self
                .service(
                    "notify",
                    &self.notify_service,
                    json!({"message": "clear_notification", "data": {"tag": tag}}),
                )
                .await;
        }
        self.save();
        let requests: Vec<_> = self.requests.borrow().values().cloned().collect();
        for request in requests {
            self.subscribe(&request);
        }
    }

    async fn listen(self: &Rc<Self>, delay: &mut u64) -> Result<()> {
        let mut ws = Ws::connect(&self.url, true).await?;
        self.handshake(&mut ws).await?;
        *delay = 1;
        let (tx, mut outbox) = mpsc::unbounded_channel();
        self.ws.replace(Some(tx));
        self.connected.set(true);
        info!("connected");
        let result = async {
            self.on_connect().await;
            loop {
                tokio::select! {
                    msg = ws.recv() => match msg? {
                        None => return Ok(()),
                        Some(data) if data["type"] == "event" => self.on_action(&data["event"]),
                        Some(_) => {}
                    },
                    Some(out) = outbox.recv() => ws.send(&out).await?,
                }
            }
        }
        .await;
        self.connected.set(false);
        self.ws.replace(None);
        result
    }

    async fn check(&self) -> bool {
        let mut failed = false;
        let mut report = |ok: bool, what: &str| {
            println!("{} {what}", if ok { "ok  " } else { "FAIL" });
            failed |= !ok;
        };
        for (path, _) in pam_files(Path::new("/etc/pam.d"), Path::new("/usr/lib/pam.d")) {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let ok = pam_lines(service_name(&path))
                .iter()
                .all(|l| text.contains(l.as_str()));
            report(ok, &format!("PAM {}", path.display()));
        }
        let is_socket = std::fs::metadata(SOCKET).is_ok_and(|m| m.file_type().is_socket());
        report(is_socket, &format!("daemon socket {SOCKET}"));
        let http = ha_remote::http_client(&self.token, None, Some(Duration::from_secs(15)));
        let ha = async {
            let mut ws =
                tokio::time::timeout(Duration::from_secs(15), Ws::connect(&self.url, false))
                    .await
                    .map_err(|_| "timed out")??;
            if let Err(e) = self.handshake(&mut ws).await {
                if e.downcast_ref::<Fatal>().is_some() {
                    return Ok(Err(e.to_string()));
                }
                return Err(e);
            }
            let mut checks = vec![(true, "HA token, user and event subscriptions".to_owned())];
            ws.send(&json!({"id": 4, "type": "config/auth/list"}))
                .await?;
            let users = ws.recv_some().await?;
            let known = users["result"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|u| u["id"] == self.approver.as_str());
            checks.push((known, format!("approver user {}", self.approver)));
            let services: Value = http
                .get(format!("{}/api/services", self.url))
                .send()
                .await?
                .json()
                .await?;
            let has_notify = services.as_array().into_iter().flatten().any(|s| {
                s["domain"] == "notify" && s["services"].get(&self.notify_service).is_some()
            });
            checks.push((has_notify, format!("notify.{}", self.notify_service)));
            Ok::<_, ha_remote::Error>(Ok(checks))
        };
        match ha.await {
            Ok(Ok(checks)) => checks.iter().for_each(|(ok, what)| report(*ok, what)),
            Ok(Err(fatal)) => {
                report(false, &fatal);
                return false;
            }
            Err(e) => report(false, &format!("HA at {}: {e}", self.url)),
        }
        !failed
    }

    async fn run(self: Rc<Self>) {
        let _ = std::fs::remove_file(SOCKET);
        let listener =
            UnixListener::bind(SOCKET).unwrap_or_else(|e| fatal(&format!("{SOCKET}: {e}")));
        let _ = std::fs::set_permissions(SOCKET, std::fs::Permissions::from_mode(0o666));
        sd_notify(b"READY=1");
        spawn_local(async {
            loop {
                sd_notify(b"WATCHDOG=1");
                sleep(Duration::from_secs(10)).await;
            }
        });
        let me = self.clone();
        spawn_local(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        spawn_local(me.clone().handle(stream));
                    }
                    Err(e) => {
                        warn!("accept: {e}");
                        sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
        let mut delay = 1;
        loop {
            if let Err(e) = self.listen(&mut delay).await {
                exit_if_fatal(&e);
                warn!("disconnected: {e}{}", tailscale_note().await);
            }
            sleep(Duration::from_secs(delay)).await;
            delay = (delay * 2).min(60);
        }
    }
}

fn main() {
    let command = std::env::args().nth(1).unwrap_or_else(|| "run".into());
    let (etc, vendor) = (Path::new("/etc/pam.d"), Path::new("/usr/lib/pam.d"));
    match command.as_str() {
        "enable" => return enable(etc, vendor).unwrap_or_else(|e| fatal(&e.to_string())),
        "disable" => return disable(etc, vendor).unwrap_or_else(|e| fatal(&e.to_string())),
        _ => {}
    }
    let mode = std::fs::metadata(CONFIG_PATH)
        .unwrap_or_else(|e| fatal(&format!("{CONFIG_PATH}: {e}")))
        .mode();
    if mode & 0o077 != 0 {
        fatal(&format!("{CONFIG_PATH} holds a token: chmod 600 it"));
    }
    let auth = Rc::new(Auth::new(read_toml(Path::new(CONFIG_PATH))));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let local = tokio::task::LocalSet::new();
    if command == "check" {
        let ok = local.block_on(&rt, auth.check());
        std::process::exit(if ok { 0 } else { 1 });
    }
    local.block_on(&rt, auth.run());
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use std::os::unix::process::CommandExt;
    use tokio::task::LocalSet;
    use tokio_tungstenite::tungstenite::Message;

    fn auth(extra: &str) -> Auth {
        let cfg = format!(
            "url = \"\"\ntoken = \"\"\nnotify_service = \"\"\napprover_user_id = \"\"\nuser = \"root\"\n{extra}"
        );
        let a = Auth::new(toml::from_str(&cfg).unwrap());
        a.stale.take();
        a
    }

    fn make(extra: &str) -> Rc<Auth> {
        Rc::new(auth(extra))
    }

    fn last_data(a: &Auth) -> Value {
        a.calls.borrow().last().unwrap().2["data"].clone()
    }

    fn pair() -> (BufReader<OwnedReadHalf>, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        (BufReader::new(a.into_split().0), b)
    }

    async fn start(locked: bool, verdict: impl FnOnce(&Rc<Auth>, &Rc<Request>)) -> bool {
        let a = make("");
        a.connected.set(true);
        a.locked.set(locked);
        let (mut reader, _peer) = pair();
        let (writer, _outbox) = mpsc::unbounded_channel();
        let task = {
            let a = a.clone();
            spawn_local(async move {
                let prompt = Prompt {
                    kind: Kind::Polkit,
                    what: "true".into(),
                    app: 1,
                };
                a.start(Some(prompt), &mut reader, &writer).await
            })
        };
        sleep(Duration::from_millis(10)).await;
        if !task.is_finished() {
            verdict(&a, &a.get(1).unwrap());
        }
        task.await.unwrap()
    }

    fn action(verb: &str, r: &Request, event_type: &str, user: &str) -> Value {
        json!({"event_type": event_type, "data": {"action": format!("HAREMOTE_{verb}_{}", r.nonce)},
               "context": {"user_id": user}})
    }

    #[tokio::test]
    async fn actions() {
        LocalSet::new()
            .run_until(async {
                let mut a = auth("");
                a.approver = "phone".into();
                let a = Rc::new(a);
                let r = a.ask(Kind::Sudo, "true", 1).await.unwrap();
                a.on_action(&action("APPROVE", &r, ACTION_EVENT, "intruder"));
                a.on_action(
                    &json!({"event_type": ACTION_EVENT, "data": {"action": "HAREMOTE_APPROVE_0"},
                                    "context": {"user_id": "phone"}}),
                );
                a.on_action(&action("APPROVE", &r, DENY_EVENT, "phone"));
                assert_eq!(r.verdict(), Verdict::Pending);
                a.on_action(&action("APPROVE", &r, "sudo: true", "phone"));
                assert_eq!(r.verdict(), Verdict::Approved);
            })
            .await;
    }

    #[tokio::test]
    async fn finish_consumes_once() {
        LocalSet::new()
            .run_until(async {
                let a = make("");
                let (mut reader, _peer) = pair();
                let (writer, _outbox) = mpsc::unbounded_channel();
                let prompt = || {
                    Some(Prompt {
                        kind: Kind::Sudo,
                        what: "true".into(),
                        app: 1,
                    })
                };
                let r = a.ask(Kind::Sudo, "true", 1).await.unwrap();
                r.verdict.send_replace(Verdict::Approved);
                assert!(a.finish(prompt(), false, &mut reader, &writer).await);
                assert!(!a.finish(prompt(), false, &mut reader, &writer).await);
                a.ask(Kind::Sudo, "true", 1).await.unwrap();
                assert!(!a.finish(prompt(), true, &mut reader, &writer).await);
                assert!(a.get(1).is_none());
            })
            .await;
    }

    #[test]
    fn describe_gating() {
        let a = make("");
        let chain = |c: &[&str]| -> Vec<(i32, String)> {
            c.iter().zip(10..).map(|(c, p)| (p, (*c).into())).collect()
        };
        let req = |user: &str, rhost: &str| AuthReq {
            stage: Stage::Start,
            typed: false,
            service: Some("sudo".into()),
            user: Some(user.into()),
            rhost: rhost.into(),
        };
        let sudo = chain(&["pam-helper", "sudo", "bash"]);
        let d = |chain: &[(i32, String)], uid, req: &AuthReq, ruid| {
            a.describe_chain(chain, uid, req, |_| Some(ruid))
                .map(|p| p.kind)
        };
        assert_eq!(d(&sudo, 0, &req("root", ""), 0), Some(Kind::Sudo));
        assert_eq!(d(&sudo, 1000, &req("root", ""), 0), None);
        assert_eq!(d(&sudo, 0, &req("other", ""), 0), None);
        assert_eq!(d(&sudo, 0, &req("root", "host"), 0), None);
        assert_eq!(d(&sudo, 0, &req("root", ""), 1000), None);
        let ssh = chain(&["pam-helper", "sudo", "bash", "sshd-session"]);
        assert_eq!(d(&ssh, 0, &req("root", ""), 0), None);
    }

    fn deny_while_blocking(a: &Rc<Auth>, r: &Rc<Request>) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        a.agent.replace(Some((0, tx)));
        a.on_action(&action("DENY", r, ACTION_EVENT, ""));
        let sent: Value = serde_json::from_slice(&rx.try_recv().unwrap()).unwrap();
        assert_eq!(sent, json!({"type": "polkit", "submit": false}));
    }

    #[tokio::test]
    async fn start_paths() {
        LocalSet::new()
            .run_until(async {
                let approve = |_: &Rc<Auth>, r: &Rc<Request>| {
                    r.verdict.send_replace(Verdict::Approved);
                };
                assert!(!start(false, approve).await);
                assert!(start(true, approve).await);
                assert!(
                    !start(true, |_, r| {
                        r.verdict.send_replace(Verdict::Denied);
                    })
                    .await
                );
                assert!(!start(true, |a, _| a.abandon()).await);
                assert!(!start(true, deny_while_blocking).await);
            })
            .await;
    }

    #[tokio::test]
    async fn resubscribe() {
        LocalSet::new()
            .run_until(async {
                let a = make("");
                a.stale.replace(vec!["ha-remote-old".into()]);
                let r = a.ask(Kind::Sudo, "true", 1).await.unwrap();
                assert_eq!(r.sub.get(), None);
                let (tx, mut rx) = mpsc::unbounded_channel();
                a.ws.replace(Some(tx));
                a.on_connect().await;
                assert_eq!(last_data(&a)["tag"], "ha-remote-old");
                let sent = rx.try_recv().unwrap();
                assert_eq!(sent, json!({"id": r.sub.get().unwrap(), "type": "subscribe_events", "event_type": "sudo: true"}));
                assert!(rx.try_recv().is_err());
            })
            .await;
    }

    #[tokio::test]
    async fn expire() {
        LocalSet::new()
            .run_until(async {
                let a = make("timeout_s = 0");
                let r = a.ask(Kind::Sudo, "true", 1).await.unwrap();
                sleep(Duration::from_millis(10)).await;
                assert!(a.requests.borrow().is_empty());
                assert_eq!(last_data(&a)["tag"], r.tag());
            })
            .await;
    }

    #[tokio::test]
    async fn rate_limit() {
        LocalSet::new()
            .run_until(async {
                let a = make("");
                for app in 0..RATE_LIMIT as i32 {
                    assert!(a.ask(Kind::Sudo, "true", app).await.is_some());
                }
                assert!(a.ask(Kind::Sudo, "true", 99).await.is_none());
            })
            .await;
    }

    #[tokio::test]
    async fn policy() {
        LocalSet::new()
            .run_until(async {
                let a = make("[policy]\ntap = [\"lockscreen\"]\nnever = [\"^sudo: rm \"]");
                assert!(a.ask(Kind::Sudo, "rm -rf /", 1).await.is_none());
                assert!(a.ask(Kind::Polkit, "true", 2).await.is_some());
                assert!(last_data(&a).get("url").is_none());
                assert!(a.ask(Kind::Lockscreen, "unlock", 3).await.is_some());
                assert!(last_data(&a).get("url").is_some());
            })
            .await;
    }

    async fn fake_ha(approve: bool) {
        let mut a = auth("");
        a.approver = "phone".into();
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let (actions, mut action_rx) = mpsc::unbounded_channel::<String>();
        let ha = tokio::spawn(async move {
            let (tcp, _) = server.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let send = |v: Value| Message::text(v.to_string());
            ws.send(send(json!({"type": "auth_required"})))
                .await
                .unwrap();
            ws.next().await;
            ws.send(send(json!({"type": "auth_ok"}))).await.unwrap();
            ws.next().await;
            ws.send(send(
                json!({"id": 1, "type": "result", "result": {"id": "ha-remote"}}),
            ))
            .await
            .unwrap();
            for i in [2, 3] {
                ws.next().await;
                ws.send(send(json!({"id": i, "type": "result", "success": true})))
                    .await
                    .unwrap();
            }
            let action = action_rx.recv().await.unwrap();
            let event = json!({"type": "event", "event": {"event_type": ACTION_EVENT,
                "data": {"action": action}, "context": {"user_id": "phone"}}});
            ws.send(send(event)).await.unwrap();
            ws.next().await;
        });
        a.url = format!("http://127.0.0.1:{port}");
        let a = Rc::new(a);
        // A live process without a terminal, so submit neither types into one nor signals the test.
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("30");
        // SAFETY: setsid is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let mut child = cmd.spawn().unwrap();
        let listener = {
            let a = a.clone();
            spawn_local(async move { a.listen(&mut 1).await })
        };
        while !a.connected.get() {
            sleep(Duration::from_millis(10)).await;
        }
        let r = a.ask(Kind::Sudo, "true", child.id() as i32).await.unwrap();
        let verb = if approve { "APPROVE" } else { "DENY" };
        actions
            .send(format!("HAREMOTE_{verb}_{}", r.nonce))
            .unwrap();
        let mut verdict = r.verdict.subscribe();
        let v = *verdict.wait_for(|v| *v != Verdict::Pending).await.unwrap();
        assert_eq!(
            v,
            if approve {
                Verdict::Approved
            } else {
                Verdict::Denied
            }
        );
        listener.abort();
        ha.abort();
        let _ = child.kill();
        let _ = child.wait();
    }

    #[tokio::test]
    async fn fake_ha_roundtrip() {
        LocalSet::new()
            .run_until(async {
                fake_ha(true).await;
                fake_ha(false).await;
            })
            .await;
    }

    #[test]
    fn lockscreen_key() {
        let a = make("");
        let chain: Vec<(i32, String)> = [
            (9, "pam-helper"),
            (8, "noctalia"),
            (7, "noctalia"),
            (2, "systemd"),
        ]
        .map(|(p, c)| (p, c.into()))
        .into();
        let req = AuthReq {
            stage: Stage::Finish,
            typed: false,
            service: Some("login".into()),
            user: Some("root".into()),
            rhost: String::new(),
        };
        let p = a.describe_chain(&chain, 0, &req, |_| None).unwrap();
        assert_eq!(p.app, 7);
    }

    #[test]
    fn pam_matches_python() {
        let golden: Value =
            serde_json::from_str(include_str!("../../tests/pam-golden.json")).unwrap();
        let dir = std::env::temp_dir().join(format!("ha-remote-pam-{}", std::process::id()));
        for (name, case) in golden.as_object().unwrap() {
            let (etc, vendor) = (dir.join(name).join("etc"), dir.join(name).join("ven"));
            for (d, files) in [(&etc, &case["etc"]), (&vendor, &case["ven"])] {
                std::fs::create_dir_all(d).unwrap();
                for (f, text) in files.as_object().unwrap() {
                    std::fs::write(d.join(f), text.as_str().unwrap()).unwrap();
                }
            }
            let read = || -> Value {
                std::fs::read_dir(&etc)
                    .unwrap()
                    .map(|e| e.unwrap())
                    .map(|e| {
                        (
                            e.file_name().into_string().unwrap(),
                            std::fs::read_to_string(e.path()).unwrap().into(),
                        )
                    })
                    .collect::<serde_json::Map<_, _>>()
                    .into()
            };
            enable(&etc, &vendor).unwrap();
            assert_eq!(read(), case["enabled"], "{name} enabled");
            disable(&etc, &vendor).unwrap();
            assert_eq!(read(), case["disabled"], "{name} disabled");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn tcp_addrs() {
        let s = |f| tcp_addr(f).unwrap().to_string();
        assert_eq!(s("0100007F:0016"), "127.0.0.1");
        assert_eq!(s("0000000000000000FFFF00000100007F:0016"), "127.0.0.1");
        assert_eq!(s("B80D0120000000000000000001000000:0016"), "2001:db8::1");
    }

    #[test]
    fn fire_url_quoting() {
        assert_eq!(
            Auth::fire_url("sudo: rm a/b", "X_1", Some("y&z")),
            "homeassistant://x-callback-url/fire_event?eventName=sudo%3A%20rm%20a%2Fb&action=X_1&x-cancel=y%26z"
        );
    }

    #[test]
    fn networks() {
        assert!(ip_network("10.0.0.0/8").is_some());
        assert!(ip_network("100.64.0.1").is_some());
        assert!(ip_network("10.0.0.1/8").is_none());
    }
}
