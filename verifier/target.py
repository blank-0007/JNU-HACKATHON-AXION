"""The monitored machine's files, as seen through the shared volumes, plus the demo scenarios.

Attacks (turn the dashboard red):
  apply_config_hack()   rewrite config.json         -> CONFIG mismatch
  replace_binary()      patch the service binary    -> BINARY mismatch
  tamper_memory()       ask the agent to simulate an in-RAM compromise -> MEMORY mismatch
Operator actions:
  apply_dev_update()    the approved release (after authorizeUpdate on-chain) -> BLUE
  restore_all()         roll everything back to the trusted state -> GREEN
"""
import hashlib
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
SNAPSHOT_DIR = SHARED / "trusted_target"        # directory snapshot of all trusted target files

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


def _target_files():
    """Return sorted list of all monitored files in TARGET, excluding the service binary."""
    files = []
    if not TARGET.exists():
        return files
    for p in sorted(TARGET.rglob("*")):
        if p.is_file() and not p.name.startswith(".") and not p.name.endswith(".tmp"):
            try:
                if p.resolve() == SERVICE_BIN.resolve() or p == SERVICE_BIN:
                    continue
            except OSError:
                if p == SERVICE_BIN:
                    continue
            files.append(p)
    return files


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
    if SNAPSHOT_DIR.exists():
        shutil.rmtree(SNAPSHOT_DIR)
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    for p in _target_files():
        try:
            rel = p.relative_to(TARGET)
            dst = SNAPSHOT_DIR / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(p, dst)
        except OSError:
            pass


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

    # Restore snapshot files and delete extraneous files
    if SNAPSHOT_DIR.exists():
        snap_files = {p.relative_to(SNAPSHOT_DIR): p for p in SNAPSHOT_DIR.rglob("*")
                      if p.is_file() and not p.name.startswith(".")}
        for p in _target_files():
            try:
                rel = p.relative_to(TARGET)
                if rel != Path("config.json") and rel not in snap_files:
                    p.unlink(missing_ok=True)
            except OSError:
                pass
        for rel, src in snap_files.items():
            if rel != Path("config.json"):
                dst = TARGET / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dst)
    else:
        for p in _target_files():
            if p != CONFIG_PATH:
                try:
                    p.unlink(missing_ok=True)
                except OSError:
                    pass

    send_control("restore_binary")
    send_control("restore_memory")


# ------------------------------------------------------------------------ user data & diffs
def write_user_data(rel_path, content):
    """Write user-provided data to target_system/<rel_path>."""
    rel_path = rel_path.strip().lstrip("/\\")
    if not rel_path or ".." in rel_path:
        rel_path = "user_data.txt"
    p = TARGET / rel_path
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.tmp")
    tmp.write_text(content)
    os.replace(tmp, p)
    return rel_path


def remove_target_file(rel_path):
    """Remove a target_system file."""
    rel_path = rel_path.strip().lstrip("/\\")
    p = TARGET / rel_path
    if p.exists() and p.is_file() and rel_path != "bin/checkout-service":
        p.unlink(missing_ok=True)
        return True
    return False


def list_target_files():
    """List metadata for all files currently in TARGET."""
    results = []
    for p in _target_files():
        try:
            rel = str(p.relative_to(TARGET))
            stat = p.stat()
            size = f"{stat.st_size} B" if stat.st_size < 1024 else f"{stat.st_size / 1024:.1f} KB"
            mtime = datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime("%H:%M:%S")
            h = hashlib.sha256(p.read_bytes()).hexdigest()[:8]
            results.append({"path": rel, "size": size, "mtime": mtime, "hash": h})
        except OSError:
            pass
    return results


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


def target_diff():
    """Detects differences across all target_system files between snapshot and live."""
    diffs = []
    diffs.extend(config_diff())

    live_map = {}
    for p in _target_files():
        if p.name != "config.json":
            live_map[p.relative_to(TARGET)] = p

    snap_map = {}
    if SNAPSHOT_DIR.exists():
        for p in SNAPSHOT_DIR.rglob("*"):
            if p.is_file() and not p.name.startswith(".") and not p.name.endswith(".tmp") and p.name != "config.json":
                snap_map[p.relative_to(SNAPSHOT_DIR)] = p

    all_keys = sorted(set(live_map.keys()) | set(snap_map.keys()))
    for rel in all_keys:
        rel_str = str(rel)
        if rel in live_map and rel not in snap_map:
            p = live_map[rel]
            try:
                txt = p.read_text(errors="replace").strip()
                preview = (txt[:45] + "…") if len(txt) > 45 else (txt or "(empty)")
            except Exception:
                preview = f"{p.stat().st_size} bytes"
            diffs.append((f"target_system/{rel_str}", "[absent]", f"created: {preview}"))
        elif rel in snap_map and rel not in live_map:
            diffs.append((f"target_system/{rel_str}", "present", "[deleted]"))
        else:
            p_live = live_map[rel]
            p_snap = snap_map[rel]
            try:
                if p_live.read_bytes() != p_snap.read_bytes():
                    txt = p_live.read_text(errors="replace").strip()
                    preview = (txt[:45] + "…") if len(txt) > 45 else (txt or "(empty)")
                    diffs.append((f"target_system/{rel_str}", "original", f"modified: {preview}"))
            except Exception:
                pass
    return diffs
