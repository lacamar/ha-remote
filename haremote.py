import os
import re
import socket
import subprocess
import tomllib
from pathlib import Path

CONFIG_PATH = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "ha-remote" / "config.toml"
AUTH_SOCKET = "/run/ha-remote/auth.sock"


def load_config():
    with open(CONFIG_PATH, "rb") as f:
        return tomllib.load(f)


def prefix(cfg):
    return re.sub(r"[^a-z0-9]+", "_", cfg.get("prefix") or socket.gethostname().split(".")[0].lower()).strip("_")


def secret(key):
    proc = subprocess.run(["secret-tool", "lookup", "service", "ha-remote", "key", key], capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"secret missing: secret-tool store --label='ha-remote {key}' service ha-remote key {key}")
    return proc.stdout.rstrip("\n")
