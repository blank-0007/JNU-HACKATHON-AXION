"""The monitored machine's files, as seen through the shared volumes, plus the demo scenarios.

Attacks (turn the dashboard red):
  apply_config_hack()   rewrite config.json         -> CONFIG mismatch
  replace_binary()      patch the service binary    -> BINARY mismatch
  tamper_memory()       ask the agent to simulate an in-RAM compromise -> MEMORY mismatch
Operator actions:
  apply_dev_update()    the approved release (after authorizeUpdate on-chain) -> BLUE
  restore_all()         roll everything back to the trusted state -> GREEN
"""
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

TARGET = Path("/target")
CONFIG_PATH = TARGET / "config.json"
SERVICE_BIN = TARGET / "bin" / "checkout-service"
SHARED = Path("/shared")
CONTROL_DIR = SHARED / "control"
SNAPSHOT_PATH = SHARED / "trusted_config.json"  # last config whose hash is the on-chain reference

BASELINE_CONFIG = {
    "service": "checkout-api",
    "version": "2.4.1",
    "environment": "production",
    "last_deployed": "2026-09-30T09:00:00Z",
    "payments": {
        "gateway_url": "https://payments.internal.example.com/v2",
        "currency": "USD",
        "max_transaction": 10000,
    },
    "auth": {"require_mfa": True, "session_timeout_min": 30, "admin_users": ["alice"]},
    "features": {"new_checkout_flow": False, "fraud_detection": True},
    "logging": {"level": "INFO", "debug_mode": False},
}


def read_config(path=CONFIG_PATH):
    return json.loads(Path(path).read_text())


def write_config(data, path=CONFIG_PATH):
    """Atomic write (temp file + rename), so the agent never hashes a half-written file."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    os.replace(tmp, path)


def write_baseline():
    write_config(BASELINE_CONFIG)


def _atomic_copy(src, dst):
    tmp = Path(dst).with_name(f".{Path(dst).name}.tmp")
    shutil.copyfile(src, tmp)
    os.replace(tmp, dst)


def save_snapshot():
    _atomic_copy(CONFIG_PATH, SNAPSHOT_PATH)


def send_control(name):
    """Drop a request file for the agent's demo control channel."""
    CONTROL_DIR.mkdir(parents=True, exist_ok=True)
    (CONTROL_DIR / name).touch()


# ---------------------------------------------------------------------- attacks
def apply_config_hack():
    cfg = read_config()
    cfg["payments"]["gateway_url"] = "https://payments-verify.attacker.net/collect"
    cfg["auth"]["require_mfa"] = False
    if "backdoor" not in cfg["auth"]["admin_users"]:
        cfg["auth"]["admin_users"].append("backdoor")
    write_config(cfg)


def replace_binary():
    """Trojanize the executable: same program, extra payload bytes appended."""
    with open(SERVICE_BIN, "ab") as f:
        f.write(b"\n# injected: exfiltrate card numbers to payments-verify.attacker.net\n")


def tamper_memory():
    send_control("tamper_memory")


# --------------------------------------------------------------------- operator
def apply_dev_update():
    cfg = read_config()
    major, minor, patch = (int(x) for x in cfg["version"].split("."))
    cfg["version"] = f"{major}.{minor}.{patch + 1}"
    cfg["last_deployed"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cfg["features"]["new_checkout_flow"] = not cfg["features"]["new_checkout_flow"]
    write_config(cfg)
    return cfg["version"]


def restore_all():
    if SNAPSHOT_PATH.exists():
        _atomic_copy(SNAPSHOT_PATH, CONFIG_PATH)
    else:
        write_baseline()
    send_control("restore_binary")
    send_control("restore_memory")


# ------------------------------------------------------------------------ diffs
def _flatten(obj, prefix=""):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out.update(_flatten(v, f"{prefix}{k}."))
        return out
    return {prefix[:-1]: json.dumps(obj)}


def config_diff():
    """(key, old, new) between the trusted config snapshot and the live file."""
    try:
        old, new = _flatten(read_config(SNAPSHOT_PATH)), _flatten(read_config())
    except (OSError, ValueError):
        return []
    keys = sorted(set(old) | set(new))
    return [(k, old.get(k, "—"), new.get(k, "—")) for k in keys if old.get(k) != new.get(k)]
