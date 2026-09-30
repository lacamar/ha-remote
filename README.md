# ha-remote

Control a niri + noctalia laptop from Home Assistant and Apple Home: lock, screen and keyboard
brightness, music, suspend, power off, a job toggle, presence and hardware sensors, and approving
sudo, polkit and lock screen authentication from your phone.

The agent connects out to HA over WebSocket, so it needs no broker and no inbound port.

## Install

    sudo dnf copr enable lacamar/arm64-misc
    sudo dnf install ha-remote

Or from a checkout: copy `ha-remote`, `ha-remote-setup` and `haremote.py` to your PATH,
`ha-remote.service` to `~/.config/systemd/user/`, and generate the Wayland bindings:

    mkdir -p ~/.local/share/ha-remote/protocols/hrproto && touch $_/__init__.py
    python3 -m pywayland.scanner -o ~/.local/share/ha-remote/protocols/hrproto \
        -i /usr/share/wayland/wayland.xml /usr/share/wayland-protocols/staging/ext-idle-notify/ext-idle-notify-v1.xml

## Set up

1. In HA, create a dedicated admin user for ha-remote (not the one your phone app logs in as),
   log in as it and create a long-lived access token (profile > Security).
2. `secret-tool store --label='ha-remote token' service ha-remote key token`
3. `cp /usr/share/ha-remote/config.example.toml ~/.config/ha-remote/config.toml` and edit it.
4. `ha-remote-setup` creates the helpers, template entities, automations and a dashboard in HA.
5. `systemctl --user enable --now ha-remote`
6. For Apple Home, add `input_button` and `input_boolean` to the domains your HomeKit Bridge exposes.

## Phone approval

    sudo install -m600 /usr/share/ha-remote/auth.example.toml /etc/ha-remote/auth.toml   # then edit
    sudo systemctl enable --now ha-remote-auth
    sudo ha-remote-auth enable

`enable` puts `pam_exec` in front of the password for `sudo`, `sudo-i`, `polkit-1` and `login`
(`disable` undoes it). When you are away from the keyboard, a prompt pushes Approve and Deny to
the phone; approving authenticates without a password, anything else falls back to the password.
While you are at the keyboard nothing is sent. ssh sessions and other users are never approved.

For the lock screen set `allow_empty_password = true` under `[lockscreen]` in noctalia. The
Unlock button submits the empty lock screen, which then waits for the phone.

The root service holds its own token and checks that every tap came from the approver's HA user
with a one-time code. The token must not belong to the approver, or anything holding it could
forge a tap.
