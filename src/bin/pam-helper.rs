use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::exit;
use std::time::Duration;

use serde_json::{Value, json};

fn main() {
    let stage = std::env::args().nth(1).unwrap_or_else(|| "finish".into());
    let typed = stage == "finish" && {
        let mut input = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut input);
        input.iter().any(|&b| b != 0 && b != b'\n')
    };
    let env = |k| std::env::var(k).ok();
    let req = json!({"type": "auth", "stage": stage, "typed": typed, "service": env("PAM_SERVICE"),
                     "user": env("PAM_USER"), "rhost": env("PAM_RHOST").unwrap_or_default()});
    exit(ask(&stage, &req).unwrap_or(1))
}

fn ask(stage: &str, req: &Value) -> std::io::Result<i32> {
    let mut s = UnixStream::connect(ha_remote::AUTH_SOCKET)?;
    s.set_read_timeout(Some(Duration::from_secs(300)))?;
    s.set_write_timeout(Some(Duration::from_secs(300)))?;
    s.write_all(format!("{req}\n").as_bytes())?;
    for line in BufReader::new(s).lines() {
        let reply: Value = serde_json::from_str(&line?)?;
        if reply["asking"] == true {
            println!(
                "{}",
                if stage == "start" {
                    "Approve on your phone, or enter the password."
                } else {
                    "Approve on your phone."
                }
            );
        } else if let Some(ok) = reply.get("ok") {
            return Ok(if ok.as_bool() == Some(true) { 0 } else { 1 });
        }
    }
    Ok(1)
}
