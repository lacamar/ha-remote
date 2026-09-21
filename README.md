# ha-remote

Control this laptop from Home Assistant and Apple Home. Connects out to HA over WebSocket; needs no broker and no inbound port.

    ./install
    secret-tool store --label='ha-remote token' service ha-remote key token     # HA long-lived token
    secret-tool store --label='ha-remote unlock' service ha-remote key unlock   # login password
    $EDITOR ~/.config/ha-remote/config.toml
    ./ha-setup                                                                  # helpers, template entities, automations
    systemctl --user start ha-remote

Needs python3-aiohttp, python3-pywayland, wtype, brightnessctl, playerctl, niri, noctalia.
