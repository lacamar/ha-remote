# ha-remote

Control a niri + noctalia laptop from Home Assistant and Apple Home: lock, screen and keyboard
brightness, music, suspend, power off, a job toggle, presence and hardware sensors, and approving
sudo, polkit and lock screen authentication from your phone.

The agent connects out to HA over WebSocket, so it needs no broker and no inbound port.

## Install

    sudo dnf copr enable lacamar/arm64-misc
    sudo dnf install ha-remote

## Set up

1. In HA, create a dedicated admin user for ha-remote (not the one your phone app logs in as),
   log in as it and create a long-lived access token (profile > Security).
2. `secret-tool store --label='ha-remote token' service ha-remote key token`
3. `cp /usr/share/ha-remote/config.example.toml ~/.config/ha-remote/config.toml` and edit it.
4. `ha-remote-setup` creates the helpers, template entities, automations and a dashboard in HA.
5. `systemctl --user enable --now ha-remote`
6. For Apple Home, add `input_boolean` to the domains your HomeKit Bridge exposes. The Lock is its
   own HomeKit accessory: pair it with the code setup leaves in HA's notifications.

A NuPhy keyboard (NuPhy IO models, wired only) follows the laptop's keyboard
backlight; the packaged udev rule opens only its vendor HID interface to the seat user.

## Phone approval

    sudo install -m600 /usr/share/ha-remote/auth.example.toml /etc/ha-remote/auth.toml   # then edit
    sudo systemctl enable --now ha-remote-auth
    sudo ha-remote-auth enable

`enable` puts `pam_exec` in front of the password for `sudo`, `sudo-i`, `polkit-1` and `login`
(`disable` undoes it). A sudo or polkit prompt pushes Approve and Deny to the phone while the
password prompt stays open: approving submits the prompt for you, typing the password cancels the
request. While the screen is locked, approving a polkit prompt authenticates it directly. Other
users are never approved, and ssh sessions only from networks listed in `[policy] ssh_from`.
Tapping the notification approves too, after the app's confirmation; `[policy] tap` limits that
to some kinds and `never` keeps matching commands password-only. More than five prompts a minute
fall back to the password. Verdicts go to the HA logbook.

`sudo ha-remote-auth check` tests the PAM setup, the token and the notify service.

Set the polkit panel to floating in noctalia (`polkit_placement = "floating"`): an attached panel
sits under fullscreen windows and cannot be submitted.

For the lock screen set `allow_empty_password = true` under `[lockscreen]` in noctalia. Touching
the keyboard or mouse there asks the phone, and approving unlocks. Submitting it empty, or
unlocking the Lock from HA or Apple Home, waits for the phone; a typed password unlocks as usual and clears the request.

The root service holds its own token and checks that every tap came from the approver's HA user
with a one-time code. The token must not belong to the approver, or anything holding it could
forge a tap.
