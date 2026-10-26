# ha-remote

- Files: `ha-remote` (user daemon, HA remote/keyboard), `ha-remote-auth` (root daemon, phone approval for sudo/polkit/lock screen), `pam-helper` (pam_exec client), `haremote.py` (shared), `ha-remote-setup`
- Test offline: `python3 test_auth.py` (fake HA websocket); live: `./dev-deploy` installs the working tree and tails both journals
- `just lint` / `just test` (`ruff check .`, `test_auth.py`) run via `.githooks`
- COPR: `lacamar/arm64-misc`
- Release: bump `%global tag` + `%changelog` in `ha-remote.spec`, commit, tag `v<tag>`, push, then `./release` (COPR build, waits for the repo, upgrades)
- Notes on noctalia, iOS notifications, HA users: `bd memories`
