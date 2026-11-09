# ha-remote

- Rust crate, one binary each in `src/bin/`: `ha-remote` (user daemon, HA remote/keyboard), `ha-remote-auth` (root daemon, phone approval for sudo/polkit/lock screen), `pam-helper` (pam_exec client), `ha-remote-setup`; shared code in `src/lib.rs`
- Test offline: `cargo test` (fake HA websocket in `ha-remote-auth`); live: `./dev-deploy` installs a release build and tails both journals
- `just lint` / `just test` (fmt + clippy, `cargo test`) run via `.githooks`
- COPR: `lacamar/arm64-misc`
- Release: bump `%global tag` + `%changelog` in `ha-remote.spec`, commit, tag `v<tag>`, push, then `./release` (COPR build, waits for the repo, upgrades)
- Notes on noctalia, iOS notifications, HA users: `bd memories`
