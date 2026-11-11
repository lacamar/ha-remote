use std::path::PathBuf;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep_until};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

pub const AUTH_SOCKET: &str = "/run/ha-remote/auth.sock";

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

#[macro_export]
macro_rules! info { ($($t:tt)*) => { eprintln!("INFO {}", format_args!($($t)*)) } }
#[macro_export]
macro_rules! warn { ($($t:tt)*) => { eprintln!("WARNING {}", format_args!($($t)*)) } }
#[macro_export]
macro_rules! error { ($($t:tt)*) => { eprintln!("ERROR {}", format_args!($($t)*)) } }

/// Ends the process like Python's SystemExit: message on stderr, exit 1.
#[derive(Debug)]
pub struct Fatal(pub String);

impl std::fmt::Display for Fatal {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Fatal {}

pub fn exit_if_fatal(e: &Error) {
    if let Some(Fatal(msg)) = e.downcast_ref() {
        eprintln!("{msg}");
        std::process::exit(1);
    }
}

#[derive(Deserialize)]
pub struct Config {
    pub prefix: Option<String>,
    pub device_name: Option<String>,
    #[serde(default)]
    pub player: String,
    #[serde(default)]
    pub job_unit: String,
    #[serde(default = "default_hwmon")]
    pub hwmon: String,
    pub ha: HaConfig,
}

#[derive(Deserialize)]
pub struct HaConfig {
    pub url: String,
    pub notify_service: Option<String>,
    pub person: Option<String>,
}

fn default_hwmon() -> String {
    "macsmc_hwmon".into()
}

pub fn config_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config"));
    base.join("ha-remote/config.toml")
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

pub fn read_toml<T: DeserializeOwned>(path: &std::path::Path) -> T {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| fatal(&format!("{}: {e}", path.display())));
    // Not the error's Display: it quotes the offending line, which may hold the token.
    toml::from_str(&text).unwrap_or_else(|e| {
        let line = e
            .span()
            .map_or(0, |s| text[..s.start].matches('\n').count() + 1);
        fatal(&format!("{} line {line}: {}", path.display(), e.message()))
    })
}

pub fn load_config() -> Config {
    read_toml(&config_path())
}

pub fn fatal(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}

pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .trim()
        .to_owned()
}

pub fn short_hostname() -> String {
    hostname().split('.').next().unwrap_or_default().to_owned()
}

impl Config {
    pub fn prefix(&self) -> String {
        let raw = match self.prefix.as_deref() {
            Some(p) if !p.is_empty() => p.to_owned(),
            _ => short_hostname().to_lowercase(),
        };
        slug(&raw)
    }

    pub fn name(&self) -> String {
        self.device_name
            .clone()
            .unwrap_or_else(|| self.prefix().to_uppercase())
    }

    pub fn url(&self) -> String {
        self.ha.url.trim_end_matches('/').to_owned()
    }
}

/// `re.sub(r"[^a-z0-9]+", "_", s).strip("_")`
fn slug(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_owned()
}

pub fn secret(key: &str) -> String {
    let out = std::process::Command::new("secret-tool")
        .args(["lookup", "service", "ha-remote", "key", key])
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .trim_end_matches('\n')
            .to_owned(),
        _ => fatal(&format!(
            "secret missing: secret-tool store --label='ha-remote {key}' service ha-remote key {key}"
        )),
    }
}

/// Runs a command with a timeout, like `subprocess.run(..., capture_output=True, timeout=...)`.
pub async fn run_timeout(cmd: &[&str], timeout: Duration) -> std::io::Result<std::process::Output> {
    let child = tokio::process::Command::new(cmd[0])
        .args(&cmd[1..])
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    tokio::time::timeout(timeout, child).await.map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("{} timed out", cmd[0]),
        )
    })?
}

pub async fn tailscale_note() -> String {
    let Ok(out) = run_timeout(&["tailscale", "status", "--json"], Duration::from_secs(5)).await
    else {
        return String::new();
    };
    let Ok(v) = serde_json::from_slice::<Value>(&out.stdout) else {
        return String::new();
    };
    match v.get("BackendState") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) if s == "Running" => String::new(),
        Some(Value::String(s)) => format!(" (tailscale {s}: run tailscale up)"),
        Some(other) => format!(" (tailscale {other}: run tailscale up)"),
    }
}

pub fn http_client(
    token: &str,
    connect_timeout: Option<Duration>,
    total: Option<Duration>,
) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    let mut auth = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
        .unwrap_or_else(|_| fatal("token is not a valid header value"));
    auth.set_sensitive(true);
    headers.insert(reqwest::header::AUTHORIZATION, auth);
    let mut b = reqwest::Client::builder().default_headers(headers);
    if let Some(t) = connect_timeout {
        b = b.connect_timeout(t);
    }
    if let Some(t) = total {
        b = b.timeout(t);
    }
    b.build().expect("TLS backend")
}

/// The path of an HTTP error, never the request headers (they carry the token).
pub fn http_error(e: &reqwest::Error) -> String {
    match (e.status(), e.url()) {
        (Some(s), Some(u)) => format!(
            "{} {} {}",
            s.as_u16(),
            s.canonical_reason().unwrap_or(""),
            u.path()
        ),
        _ => e.to_string(),
    }
}

const HEARTBEAT: Duration = Duration::from_secs(30);

pub struct Ws {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    last_rx: Instant,
    pinged: bool,
    heartbeat: bool,
}

impl Ws {
    pub async fn connect(base: &str, heartbeat: bool) -> Result<Ws> {
        let url = format!("{base}/api/websocket")
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        let (stream, _) = tokio::time::timeout(
            Duration::from_secs(10),
            tokio_tungstenite::connect_async(url),
        )
        .await
        .map_err(|_| "connect timed out")??;
        Ok(Ws {
            stream,
            last_rx: Instant::now(),
            pinged: false,
            heartbeat,
        })
    }

    pub async fn send(&mut self, v: &Value) -> Result<()> {
        Ok(self.stream.send(Message::text(v.to_string())).await?)
    }

    /// Next JSON message; None once the server closes. Like aiohttp's heartbeat,
    /// pings after 30 s of silence and fails if nothing answers in another 15 s.
    pub async fn recv(&mut self) -> Result<Option<Value>> {
        loop {
            let wait = if self.pinged {
                HEARTBEAT + HEARTBEAT / 2
            } else {
                HEARTBEAT
            };
            tokio::select! {
                msg = self.stream.next() => {
                    self.last_rx = Instant::now();
                    self.pinged = false;
                    match msg {
                        None | Some(Ok(Message::Close(_) | Message::Binary(_))) => return Ok(None),
                        Some(Err(e)) => return Err(e.into()),
                        Some(Ok(Message::Text(t))) => return Ok(Some(serde_json::from_str(&t)?)),
                        Some(Ok(_)) => {}
                    }
                }
                _ = sleep_until(self.last_rx + wait), if self.heartbeat => {
                    if self.pinged {
                        return Ok(None);
                    }
                    self.pinged = true;
                    self.stream.send(Message::Ping(Default::default())).await?;
                }
            }
        }
    }

    pub async fn recv_some(&mut self) -> Result<Value> {
        self.recv().await?.ok_or_else(|| "websocket closed".into())
    }

    pub async fn auth(&mut self, token: &str) -> Result<()> {
        self.recv_some().await?;
        self.send(&json!({"type": "auth", "access_token": token}))
            .await?;
        if self.recv_some().await?["type"] != "auth_ok" {
            return Err(Fatal("HA rejected the token".into()).into());
        }
        Ok(())
    }
}

/// `datetime.now(UTC).isoformat(timespec="seconds")`
pub fn utc_now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    iso_utc(secs)
}

fn iso_utc(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}+00:00",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Python's `round()`: ties to even.
pub fn py_round(x: f64) -> i64 {
    x.round_ties_even() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_matches_python() {
        assert_eq!(slug("My-Laptop"), "y_aptop");
        assert_eq!(slug("--mba13--"), "mba13");
        assert_eq!(slug("a..b"), "a_b");
    }

    #[test]
    fn iso() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00+00:00");
        assert_eq!(iso_utc(1_793_000_000), "2026-10-26T07:33:20+00:00");
        assert_eq!(iso_utc(951_782_400), "2000-02-29T00:00:00+00:00");
    }

    #[test]
    fn rounding() {
        assert_eq!(py_round(2.5), 2);
        assert_eq!(py_round(3.5), 4);
        assert_eq!(py_round(-0.5), 0);
    }
}
