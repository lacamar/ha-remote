# ha-remote

Control a niri + noctalia laptop from Home Assistant and Apple Home: lock, screen and keyboard
brightness, music, suspend, power off, a job toggle, presence and hardware sensors, and typing the
login password into sudo, polkit and the lock screen only after approval on your phone.

The agent connects out to HA over WebSocket, so it needs no broker and no inbound port.

## Install

    sudo dnf copr enable lacamar/arm64-misc
    sudo dnf install ha-remote

Or from a checkout: copy `ha-remote` and `ha-remote-setup` to your PATH, `ha-remote.service` to
`~/.config/systemd/user/`, and generate the Wayland bindings:

    mkdir -p ~/.local/share/ha-remote/protocols/hrproto && touch $_/__init__.py
    python3 -m pywayland.scanner -o ~/.local/share/ha-remote/protocols/hrproto \
        -i /usr/share/wayland/wayland.xml /usr/share/wayland-protocols/staging/ext-idle-notify/ext-idle-notify-v1.xml

## Set up

1. In HA, create a long-lived access token (profile > Security).
2. Store the secrets in your keyring:

        secret-tool store --label='ha-remote token' service ha-remote key token
        secret-tool store --label='ha-remote unlock' service ha-remote key unlock

3. `cp /usr/share/ha-remote/config.example.toml ~/.config/ha-remote/config.toml` and edit it.
4. `ha-remote-setup` creates the helpers, template entities, automations and a dashboard in HA.
5. `systemctl --user enable --now ha-remote`
6. For Apple Home, add `input_boolean` to the domains your HomeKit Bridge exposes.

## Password approval

A sudo or polkit prompt, or any input on the lock screen, sends a push with Approve and Deny.
The request carries a one-time code, is only accepted from the configured HA user, and is
re-verified against the exact prompt right before typing. The "Type password" switch in Apple
Home only sends the request; nothing types without the phone.
