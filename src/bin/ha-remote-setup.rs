use std::time::Duration;

use ha_remote::{Result, Ws, http_client, load_config, secret};
use serde_json::{Value, json};

const HELPERS: [(&str, &str, &str); 4] = [
    ("job", "Job", "mdi:package-variant-closed"),
    ("suspend", "Suspend", "mdi:power-sleep"),
    ("power_off", "Power off", "mdi:power"),
    ("next_track", "Next track", "mdi:skip-next"),
];

struct Setup {
    url: String,
    prefix: String,
    name: String,
    person: Option<String>,
    token: String,
    http: reqwest::Client,
}

/// Python's `print()` of a JSON value; dicts and lists print as JSON, not repr.
fn py(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn or_empty(v: &Value) -> String {
    match v {
        Value::Null | Value::Bool(false) => String::new(),
        Value::String(s) if s.is_empty() => String::new(),
        Value::Object(m) if m.is_empty() => String::new(),
        Value::Array(a) if a.is_empty() => String::new(),
        other => py(other),
    }
}

fn event(target: &str, cmd: &str, key: Option<&str>) -> Value {
    let mut data = json!({"target": target, "cmd": cmd});
    if let Some(key) = key {
        data[key] = json!(format!("{{{{ {key} }}}}"));
    }
    json!([{"event": "ha_remote_cmd", "event_data": data}])
}

impl Setup {
    fn e(&self, domain: &str, obj: &str) -> String {
        format!("{domain}.{}_{obj}", self.prefix)
    }

    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let mut req = self
            .http
            .request(
                reqwest::Method::from_bytes(method.as_bytes())?,
                format!("{}{path}", self.url),
            )
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        if let Some(body) = body {
            req = req.body(body.to_string());
        }
        let r = req.send().await?;
        let status = r.status();
        let raw = r.text().await?;
        if status.is_client_error() || status.is_server_error() {
            return Ok(
                json!({"type": format!("HTTP {}", status.as_u16()), "errors": raw.chars().take(300).collect::<String>()}),
            );
        }
        Ok(if raw.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&raw)?
        })
    }

    async fn exists(&self, entity_id: &str) -> Result<bool> {
        let v = self
            .call("GET", &format!("/api/states/{entity_id}"), None)
            .await?;
        Ok(!or_empty(&v["entity_id"]).is_empty())
    }

    async fn ws(&self, commands: &[Value]) -> Result<Vec<Value>> {
        if commands.is_empty() {
            return Ok(vec![]);
        }
        let mut ws = Ws::connect(&self.url, false).await?;
        ws.recv_some().await?;
        ws.send(&json!({"type": "auth", "access_token": self.token}))
            .await?;
        ws.recv_some().await?;
        let mut results = vec![];
        for (i, command) in commands.iter().enumerate() {
            let mut msg = json!({"id": i + 1});
            msg.as_object_mut()
                .unwrap()
                .extend(command.as_object().cloned().unwrap_or_default());
            ws.send(&msg).await?;
            results.push(ws.recv_some().await?);
        }
        Ok(results)
    }

    async fn flow(&self, handler: &str, steps: &[Value]) -> Result<Value> {
        let mut result = self
            .call(
                "POST",
                "/api/config/config_entries/flow",
                Some(json!({"handler": handler})),
            )
            .await?;
        for step in steps {
            let id = result["flow_id"]
                .as_str()
                .ok_or_else(|| format!("flow {handler}: {result}"))?
                .to_owned();
            result = self
                .call(
                    "POST",
                    &format!("/api/config/config_entries/flow/{id}"),
                    Some(step.clone()),
                )
                .await?;
        }
        Ok(result)
    }

    async fn template(&self, kind: &str, obj: &str, mut data: Value) -> Result<()> {
        let entity_id = self.e(kind, obj);
        if self.exists(&entity_id).await? {
            println!("exists {entity_id}");
            return Ok(());
        }
        // HA derives the entity id from the name, so create it prefixed and shorten the name afterwards.
        data["name"] = json!(format!("{} {obj}", self.prefix));
        let result = self
            .flow("template", &[json!({"next_step_id": kind}), data])
            .await?;
        println!(
            "{entity_id} {} {}",
            py(&result["type"]),
            or_empty(&result["errors"])
        );
        Ok(())
    }

    async fn helpers(&self) -> Result<()> {
        let mut create = vec![];
        for (obj, _, icon) in HELPERS {
            if !self.exists(&self.e("input_boolean", obj)).await? {
                create.push(json!({"type": "input_boolean/create", "name": format!("{} {obj}", self.prefix), "icon": icon}));
            }
        }
        for (command, result) in create.iter().zip(self.ws(&create).await?) {
            let status = if result["success"].as_bool() == Some(true) {
                "created".into()
            } else {
                py(&result["error"])
            };
            println!("{} {status}", py(&command["name"]));
        }
        Ok(())
    }

    fn light(&self, target: &str) -> Value {
        let sensor = self.e("sensor", &format!("{target}_brightness"));
        json!({
            "state": format!("{{{{ states('{sensor}')|float(0) > 0 }}}}"),
            "level": format!("{{{{ (states('{sensor}')|float(0) * 2.55)|round }}}}"),
            "turn_on": event(target, "on", None), "turn_off": event(target, "off", None),
            "set_level": event(target, "level", Some("brightness"))})
    }

    async fn templates(&self) -> Result<()> {
        for target in ["screen", "keyboard"] {
            self.template("light", target, self.light(target)).await?;
        }
        let music = self.e("sensor", "music");
        self.template(
            "fan",
            "music",
            json!({
            "speed_count": 100,
            "state": format!("{{{{ is_state('{music}','Playing') }}}}"),
            "percentage": format!("{{{{ state_attr('{music}','volume')|int(0) }}}}"),
            "turn_on": event("music", "on", None), "turn_off": event("music", "off", None),
            "set_percentage": event("music", "level", Some("percentage"))}),
        )
        .await?;
        let locked = self.e("binary_sensor", "locked");
        self.template("lock", "session", json!({
            // device_class lock: on = unlocked
            "state": format!("{{{{ 'unlocked' if is_state('{locked}','on') else 'unlocking' if state_attr('{locked}','unlocking') else 'locked' }}}}"),
            "lock": event("session", "lock", None), "unlock": event("session", "unlock", None)})).await?;
        self.template("binary_sensor", "online", json!({
            "device_class": "connectivity",
            "state": format!("{{{{ as_timestamp(now()) - as_timestamp(states('{}'), 0) < 120 }}}}", self.e("sensor", "last_seen"))})).await
    }

    async fn names_and_area(&self) -> Result<()> {
        let areas = self
            .ws(&[json!({"type": "config/area_registry/list"})])
            .await?
            .remove(0);
        let found = areas["result"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|a| a["name"] == self.name.as_str());
        let area = match found {
            Some(a) => a["area_id"].clone(),
            None => {
                let created = self.ws(&[json!({"type": "config/area_registry/create", "name": self.name, "icon": "mdi:laptop"})]).await?;
                created[0]["result"]["area_id"].clone()
            }
        };
        let mut named: Vec<(&str, &str, &str)> = HELPERS
            .iter()
            .map(|(obj, name, _)| ("input_boolean", *obj, *name))
            .collect();
        named.extend([
            ("lock", "session", "Lock"),
            ("light", "screen", "Screen"),
            ("light", "keyboard", "Keyboard"),
            ("fan", "music", "Music"),
            ("binary_sensor", "online", "Online"),
        ]);
        let updates: Vec<Value> = named.iter()
            .map(|(domain, obj, name)| json!({"type": "config/entity_registry/update", "entity_id": self.e(domain, obj), "name": name, "area_id": area}))
            .collect();
        for (command, result) in updates.iter().zip(self.ws(&updates).await?) {
            if result["success"].as_bool() != Some(true) {
                println!("{} {}", py(&command["entity_id"]), py(&result["error"]));
            }
        }
        Ok(())
    }

    async fn automations(&self) -> Result<()> {
        let online = json!({"condition": "state", "entity_id": self.e("binary_sensor", "online"), "state": "on"});
        let Some(person) = self.person.as_deref().filter(|p| !p.is_empty()) else {
            return Ok(());
        };
        let key = format!("{}_lock_on_leave", self.prefix);
        let lock = self.e("lock", "session");
        let result = self
            .call(
                "POST",
                &format!("/api/config/automation/config/{key}"),
                Some(json!({
            "alias": format!("{}: lock when I leave home", self.name), "mode": "single",
            "triggers": [{"trigger": "state", "entity_id": person, "from": "home"}],
            "conditions": [online, {"condition": "state", "entity_id": lock, "state": "unlocked"}],
            "actions": [{"action": "lock.lock", "target": {"entity_id": lock}}]})),
            )
            .await?;
        println!("{key} {}", py(&result));
        Ok(())
    }

    async fn homekit_entries(&self) -> Result<Vec<(String, String)>> {
        let v = self
            .call(
                "GET",
                "/api/config/config_entries/entry?domain=homekit",
                None,
            )
            .await?;
        let entries = v
            .as_array()
            .ok_or_else(|| format!("homekit entries: {v}"))?;
        Ok(entries
            .iter()
            .map(|x| (py(&x["entry_id"]), py(&x["title"])))
            .collect())
    }

    async fn homekit_lock(&self) -> Result<()> {
        let lock = self.e("lock", "session");
        let before = self.homekit_entries().await?;
        for (entry_id, _) in &before {
            let diag = self
                .call(
                    "GET",
                    &format!("/api/diagnostics/config_entry/{entry_id}"),
                    None,
                )
                .await?;
            let included = &diag["data"]["config-entry"]["options"]["filter"]["include_entities"];
            if included
                .as_array()
                .is_some_and(|a| a.iter().any(|x| x == lock.as_str()))
            {
                println!("exists homekit {lock}");
                return Ok(());
            }
        }
        // HA only pairs locks as their own accessory, spawned by adding a bridge with the lock domain.
        let flow = self
            .flow(
                "homekit",
                &[json!({"include_domains": ["lock"]}), json!({})],
            )
            .await?;
        let bridge = flow["result"]["entry_id"]
            .as_str()
            .ok_or_else(|| format!("homekit flow: {flow}"))?
            .to_owned();
        tokio::time::sleep(Duration::from_secs(3)).await;
        let state = self
            .call("GET", &format!("/api/states/{lock}"), None)
            .await?;
        let name = py(&state["attributes"]["friendly_name"]);
        for (entry_id, title) in self.homekit_entries().await? {
            if !before.iter().any(|(id, _)| *id == entry_id)
                && (entry_id == bridge || !title.starts_with(&format!("{name}:")))
            {
                self.call(
                    "DELETE",
                    &format!("/api/config/config_entries/entry/{entry_id}"),
                    None,
                )
                .await?;
            }
        }
        println!("homekit {lock} created; pair it with the code in HA's notifications");
        Ok(())
    }

    async fn dashboard(&self) -> Result<()> {
        let path = format!("{}-remote", self.prefix);
        let list = self
            .ws(&[json!({"type": "lovelace/dashboards/list"})])
            .await?;
        if !list[0]["result"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|d| d["url_path"] == path.as_str())
        {
            self.ws(&[json!({"type": "lovelace/dashboards/create", "url_path": path, "title": self.name, "icon": "mdi:laptop",
                             "show_in_sidebar": true, "require_admin": false})]).await?;
        }
        let mut controls = vec![self.e("lock", "session")];
        controls.extend(HELPERS.iter().map(|(o, _, _)| self.e("input_boolean", o)));
        controls.extend([
            self.e("light", "screen"),
            self.e("light", "keyboard"),
            self.e("fan", "music"),
        ]);
        let status: Vec<String> = [
            ("binary_sensor", "online"),
            ("binary_sensor", "locked"),
            ("binary_sensor", "active"),
            ("sensor", "battery"),
            ("sensor", "battery_state"),
            ("binary_sensor", "plugged_in"),
            ("sensor", "power"),
            ("sensor", "music"),
        ]
        .iter()
        .map(|(d, o)| self.e(d, o))
        .collect();
        let view = json!({"title": self.name, "path": "0", "cards": [
            {"type": "entities", "title": "Controls", "entities": controls},
            {"type": "entities", "title": "Status", "entities": status}]});
        let saved = self.ws(&[json!({"type": "lovelace/config/save", "url_path": path, "config": {"views": [view]}})]).await?;
        println!("dashboard {}", py(&saved[0]["success"]));
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cfg = load_config();
    let token = secret("token");
    let s = Setup {
        url: cfg.url(),
        prefix: cfg.prefix(),
        name: cfg.name(),
        person: cfg.ha.person.clone(),
        http: http_client(&token, None, Some(Duration::from_secs(30))),
        token,
    };
    s.helpers().await?;
    s.templates().await?;
    s.names_and_area().await?;
    s.automations().await?;
    s.homekit_lock().await?;
    s.dashboard().await?;
    println!(
        "Done. Expose input_boolean in HA's HomeKit Bridge for the {} switches.",
        s.name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads() {
        assert_eq!(
            event("screen", "level", Some("brightness")),
            json!([{"event": "ha_remote_cmd", "event_data": {"target": "screen", "cmd": "level", "brightness": "{{ brightness }}"}}])
        );
        let s = Setup {
            url: String::new(),
            prefix: "mba".into(),
            name: "MBA".into(),
            person: None,
            token: String::new(),
            http: reqwest::Client::new(),
        };
        let light = s.light("screen");
        assert_eq!(
            light["state"],
            "{{ states('sensor.mba_screen_brightness')|float(0) > 0 }}"
        );
        assert_eq!(
            light["level"],
            "{{ (states('sensor.mba_screen_brightness')|float(0) * 2.55)|round }}"
        );
        assert_eq!(
            light["turn_off"],
            json!([{"event": "ha_remote_cmd", "event_data": {"target": "screen", "cmd": "off"}}])
        );
    }
}
