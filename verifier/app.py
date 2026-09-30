"""Verifier dashboard: independent view of the agent's signed, on-chain measurements.

It trusts nothing the agent says directly. It reads the ledger, re-verifies each
measurement's signature off-chain, compares it with the golden references, and
watches the heartbeat. Display states:

  VERIFIED                all three components match their on-chain reference
  AUTHORIZED UPDATE       a component changed, the developer approved it first -> reference adopted
  UNAUTHORIZED MOD        a component changed without approval -> TamperDetected on-chain
  AGENT SILENT            no signed measurement within the heartbeat timeout
"""
import hashlib
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape

import streamlit as st

import styles
import target
from ledger import COMPONENTS, DEPLOYMENT_FILE, ChainOffline, Ledger, NotDeployed, mask_names

POLL_SECONDS = 1.0
HEARTBEAT_TIMEOUT = 7     # seconds without a signed measurement -> agent presumed compromised
BLUE_HOLD_SECONDS = 6
CONFIG_BIT = 2

st.set_page_config(page_title="Runtime Integrity Engine", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="auto")
st.markdown(styles.CSS, unsafe_allow_html=True)


@st.cache_resource(show_spinner=False)
def _cached_ledger(deployment_stamp):
    return Ledger()


def get_ledger():
    stamp = DEPLOYMENT_FILE.stat().st_mtime if DEPLOYMENT_FILE.exists() else 0
    try:
        return _cached_ledger(stamp), None
    except ChainOffline:
        return None, "offline"
    except NotDeployed:
        return None, "undeployed"
    except Exception:
        return None, "offline"


def utc(ts=None):
    return datetime.fromtimestamp(ts or time.time(), timezone.utc).strftime("%H:%M:%S")


def short(h):
    h = h[2:] if h and h.startswith("0x") else h
    return h[:8] if h else "—"


# ------------------------------------------------------------------- verification
@dataclass
class Status:
    state: str                       # verified | authorized | tamper | silent | waiting
    refs: tuple = ()
    last: object = None              # latest Measurement
    signer_ok: bool = False
    age: float = 0.0
    trail: list = field(default_factory=list)
    event: object = None             # trail entry explaining the state
    changes: list = field(default_factory=list)
    approved: int = 0


def verify(ledger):
    refs = ledger.references()
    measurements = ledger.recent_measurements()
    trail = ledger.trail()
    approved = ledger.approved_mask()
    last = measurements[-1] if measurements else None
    if last is None:
        return Status("waiting", refs, trail=trail, approved=approved)

    age = max(0.0, time.time() - last.timestamp)
    signer_ok = ledger.signer_of(last) == ledger.agent
    s = Status("verified", refs, last, signer_ok, age, trail, approved=approved)

    if age > HEARTBEAT_TIMEOUT or not signer_ok:
        s.state = "silent"
    elif last.mismatch:
        s.state = "tamper"
        s.event = next((e for e in reversed(trail) if e.kind == "tamper"), None)
        if last.mismatch & CONFIG_BIT:
            s.changes = target.target_diff()
    else:
        updates = [e for e in trail if e.kind == "updated"]
        latest = updates[-1] if updates else None
        if latest and len(updates) > 1 and time.time() - latest.timestamp < BLUE_HOLD_SECONDS:
            s.state, s.event = "authorized", latest
            s.changes = st.session_state.get("release_diff", [])

    # Keep snapshot of trusted target files for Reset and diffing.
    try:
        if not last.mismatch and s.state == "verified":
            target.save_snapshot()
    except Exception:
        pass
    return s


# --------------------------------------------------------------------- HTML pieces
def html_header(online):
    live = (f'<div class="live"><span class="dot"></span>Live <span class="mono">{utc()}</span></div>'
            if online else '<div class="live off"><span class="dot"></span>Offline</div>')
    return ('<div class="topbar"><div><div class="title">Runtime integrity engine</div>'
            '<div class="subtitle">Signed binary, config and memory measurements anchored on a blockchain</div></div>'
            f'{live}</div>')


def html_changes(changes, limit=4):
    rows = "".join(
        f'<div class="change"><span class="k">{escape(k)}</span> '
        f'<span class="old">{escape(old)}</span> → <span class="new">{escape(new)}</span></div>'
        for k, old, new in changes[:limit])
    return f'<div class="changes">{rows}</div>' if rows else ""


def _banner(cls, icon, title, msg, meta, extra=""):
    return (f'<div class="status {cls}">{icon}<div style="min-width:0">'
            f'<div class="status-title">{title}</div><div class="status-msg">{msg}</div>'
            f'<div class="status-meta">{meta}</div>{extra}</div></div>')


def _names(mask):
    names = mask_names(mask)
    return ", ".join(names[:-1]) + " and " + names[-1] if len(names) > 1 else names[0]


def html_status(s):
    if s.state == "waiting":
        return _banner("s-offline", styles.ICON_OFFLINE, "Waiting for the agent",
                       "No signed measurement on-chain yet. Enrollment happens on the first one.",
                       "Start it with: docker compose up agent")
    if s.state == "silent":
        why = ("signature does not match the enrolled agent key" if not s.signer_ok
               else f"last signed measurement {int(s.age)}s ago")
        return _banner("s-tamper", styles.ICON_TAMPER, "Agent silent",
                       "The agent stopped attesting. A killed or hijacked agent is treated as compromised.",
                       f"Heartbeat lost: {why}")
    if s.state == "tamper":
        e = s.event
        meta = (f"Tamper alert written on-chain in block {e.block} at {utc(e.timestamp)} UTC"
                if e else "Tamper alert pending")
        return _banner("s-tamper", styles.ICON_TAMPER, "Unauthorized modification",
                       f"{_names(s.last.mismatch).capitalize()} no longer "
                       f"{'match' if bin(s.last.mismatch).count('1') > 1 else 'matches'} "
                       "the on-chain reference, and no update was authorized.",
                       meta, html_changes(s.changes))
    if s.state == "authorized":
        e = s.event
        return _banner("s-authorized", styles.ICON_AUTHORIZED, "Authorized update",
                       f"Developer approval found on-chain. New {_names(e.mask)} fingerprint adopted; approval consumed.",
                       f"Reference updated in block {e.block} at {utc(e.timestamp)} UTC",
                       html_changes(s.changes))
    meta = f"Last signed measurement {utc(s.last.timestamp)} UTC · verified on-chain and off-chain"
    if s.approved:
        meta += f" · update window open for {_names(s.approved)}"
    return _banner("s-verified", styles.ICON_VERIFIED, "Verified",
                   "Binary, config and memory all match the on-chain cryptographic reference.", meta)


def html_problem(problem):
    if problem == "undeployed":
        title, msg = "Contract not deployed", "The chain is up, but IntegrityLedger isn't deployed yet."
        cmd = "docker compose restart verifier"
    else:
        title, msg = "Blockchain offline", "Can't reach the chain container."
        cmd = "docker compose up"
    return _banner("s-offline", styles.ICON_OFFLINE, title, msg, "Retrying every second",
                   f'<div class="cmd">{cmd}</div>')


_COMPONENT_INFO = {
    "binary": ("Binary", "bin/checkout-service + agent code"),
    "config": ("Target Files", "target_system/ files & config"),
    "memory": ("Memory", "security policy + code objects in RAM"),
}


def html_components(s):
    updated_mask = s.event.mask if s.state == "authorized" and s.event else 0
    rows = []
    for i, (key, bit) in enumerate(COMPONENTS):
        name, desc = _COMPONENT_INFO[key]
        measured, ref = s.last.hashes[i], s.refs[i]
        if s.last.mismatch & bit:
            pill, cls = "Modified", "bad"
        elif updated_mask & bit:
            pill, cls = "Updated", "upd"
        else:
            pill, cls = "Match", "ok"
        rows.append(
            f'<div class="comp {cls}"><div class="comp-name"><div>{name}</div>'
            f'<div class="comp-desc">{desc}</div></div>'
            f'<div class="comp-hash measured"><div class="comp-k">Measured</div><div class="mono">{short(measured)}</div></div>'
            f'<div class="comp-hash"><div class="comp-k">Reference</div><div class="mono">{short(ref)}</div></div>'
            f'<div class="pill {cls}">{pill}</div></div>')
    return (f'<div class="card"><div class="card-head"><span>Measured components</span>'
            f'<span class="mono">SHA-256</span></div>{"".join(rows)}</div>')


def html_attestation(s, ledger):
    m = s.last
    sig = "0x" + m.signature.hex()
    beat_cls = "ok" if s.age <= HEARTBEAT_TIMEOUT else "bad"
    items = [
        ("Sequence", f'<span class="mono">#{m.seq}</span>'),
        ("Signer", f'<span class="mono">{ledger.agent[:10]}…{ledger.agent[-4:]}</span>'),
        ("Signature", f'<span class="{"ok" if s.signer_ok else "bad"}">'
                      f'{"Valid" if s.signer_ok else "Invalid"}</span> · ECDSA secp256k1'),
        ("Heartbeat", f'<span class="{beat_cls}">{int(s.age)}s ago</span> · block {m.block}'),
        ("Measurement cost", f'<span class="mono">{m.cost_us / 1000:.2f} ms</span> per cycle'),
        ("Raw signature", f'<span class="mono">{sig[:18]}…{sig[-6:]}</span>'),
    ]
    cells = "".join(f'<div class="kv"><div class="kv-k">{k}</div><div class="kv-v">{v}</div></div>' for k, v in items)
    return (f'<div class="card"><div class="card-head"><span>Signed attestation</span>'
            f'<span class="mono">every 2s</span></div><div class="kv-grid">{cells}</div></div>')


def _trail_label(e, first_update_block):
    if e.kind == "registered":
        return "Agent enrolled", "st-authorized", "key registered"
    if e.kind == "authorized":
        return "Approved", "st-authorized", _names(e.mask)
    if e.kind == "updated":
        if e.block == first_update_block:
            return "Baseline anchored", "st-anchored", "all components"
        return "Reference updated", "st-anchored", _names(e.mask)
    return "Tamper detected", "st-tamper", _names(e.mask)


def html_trail(s, ledger, max_blocks=4, max_rows=8):
    updates = [e for e in s.trail if e.kind == "updated"]
    first_update_block = updates[0].block if updates else None

    per_block = {ledger.deploy_block: ("Deploy", "")}
    for e in s.trail:
        label, _, detail = _trail_label(e, first_update_block)
        kind = {"tamper": "tamper", "authorized": "authorized", "registered": "authorized"}.get(e.kind, "")
        per_block[e.block] = ("⚠ " + detail if e.kind == "tamper" else label, kind)
    if s.last:
        per_block[s.last.block] = (f"Heartbeat #{str(s.last.seq)[-4:]}", "beat")
    recent = sorted(per_block.items())[-max_blocks:]
    cards = f'<div class="chain-link">{styles.ICON_LINK}</div>'.join(
        f'<div class="blk {kind}"><div class="blk-n">Block {n}</div><div class="blk-v">{escape(label)}</div></div>'
        for n, (label, kind) in recent)

    rows = []
    for e in list(reversed(s.trail))[:max_rows]:
        label, cls, detail = _trail_label(e, first_update_block)
        rows.append(f'<tr><td class="mono">{utc(e.timestamp)}</td><td class="{cls}">{label}</td>'
                    f'<td>{escape(detail)}</td><td>{ledger.label(e.by)}</td></tr>')

    addr = f"{ledger.address[:10]}...{ledger.address[-4:]}"
    return (f'<div class="card"><div class="card-head"><span>Blockchain audit trail</span>'
            f'<span class="mono">{addr}</span></div><div class="blocks">{cards}</div>'
            '<div class="table-wrap"><table class="trail"><thead><tr><th>Time (UTC)</th><th>Event</th>'
            f'<th>Components</th><th>By</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div></div>')


# ------------------------------------------------------------------ sidebar: demo panel
ledger, problem = get_ledger()

with st.sidebar:
    st.html('<div class="side-title">Demo panel</div><div class="side-sub">Attack the remote agent live</div>'
            '<div class="side-label">Attacks</div>')
    hack_config = st.button("Tamper config", icon=":material/edit_document:", key="btn_hack", width="stretch")
    hack_data = st.button("Inject data file", icon=":material/note_add:", key="btn_inject_data", width="stretch")
    hack_binary = st.button("Replace binary", icon=":material/deployed_code:", key="btn_binary", width="stretch")
    hack_memory = st.button("Patch memory", icon=":material/memory:", key="btn_memory", width="stretch")
    st.html('<div class="side-label">Operator</div>')
    approve = st.button("Approve update", icon=":material/signature:", key="btn_approve", width="stretch")
    reset = st.button("Reset", icon=":material/refresh:", key="btn_reset", width="stretch")

try:
    if hack_config:
        target.apply_config_hack()
        st.toast("Attacker rewrote config.json", icon=":material/edit_document:")
    if hack_data:
        target.write_user_data("custom_payload.txt", "INJECTED_UNAUTHORIZED_PAYLOAD: 0x8a9b21f\n")
        st.toast("Injected custom_payload.txt into target_system", icon=":material/note_add:")
    if hack_binary:
        target.replace_binary()
        st.toast("Attacker appended a payload to the service binary", icon=":material/deployed_code:")
    if hack_memory:
        target.tamper_memory()
        st.toast("Agent's in-memory policy rewritten and payment check hooked", icon=":material/memory:")
    if approve:
        if ledger is None:
            st.toast("Blockchain offline", icon=":material/cloud_off:")
        else:
            try:
                ledger.authorize_update(CONFIG_BIT)  # developer key opens a one-shot window for CONFIG
            except Exception as exc:
                found = re.search(r"IntegrityLedger: ([^'\"]+)", str(exc))
                reason = found.group(1) if found else type(exc).__name__
                st.toast(f"Refused on-chain: {reason}", icon=":material/block:")
            else:
                st.session_state["release_diff"] = []
                version = target.apply_dev_update()
                st.session_state["release_diff"] = target.target_diff()
                st.toast(f"Developer approved config on-chain, release v{version} applied", icon=":material/signature:")
    if reset:
        target.restore_all()
        st.toast("Restored config, target files, binary and memory to the trusted state", icon=":material/refresh:")
except OSError as exc:
    st.toast(f"Couldn't touch the target files: {exc}", icon=":material/error:")

with st.sidebar:
    chain = f"Hardhat, chain {ledger.chain_id}" if ledger else "Hardhat, offline"
    agent = f"{ledger.agent[:8]}…{ledger.agent[-4:]}" if ledger else "—"
    st.html(f'<div class="side-info">Agent-01 (Docker)<br><span class="mono">{agent}</span><br>{chain}</div>')


# ------------------------------------------------------------- main: live dashboard
@st.fragment(run_every=POLL_SECONDS)
def dashboard():
    ledger, problem = get_ledger()
    status = None
    if ledger:
        try:
            status = verify(ledger)
        except Exception:
            _cached_ledger.clear()
            problem = "offline"

    st.html(html_header(online=status is not None))
    if status is None:
        st.html(html_problem(problem))
        return
    st.html(html_status(status))
    if status.last:
        st.html(html_components(status))
        st.html(html_attestation(status, ledger))
    st.html(html_trail(status, ledger))


dashboard()


# ------------------------------------------------------------- user data entry section
def render_data_entry_section():
    st.html("""
    <div class="entry-card">
      <div class="entry-title">
        <span>Target System Data Entry & Live File Injection</span>
        <span class="mono" style="color:var(--blue);font-size:.85rem;">target_system/</span>
      </div>
      <div class="entry-desc">
        Enter any custom data, payload, or file to write into <code style="color:var(--blue)">target_system/</code>. Any addition, modification, or removal is measured by the agent and flagged as an on-chain tamper alert within 2 seconds.
      </div>
    </div>
    """)

    with st.container():
        c1, c2 = st.columns([1.3, 2.7])
        with c1:
            file_preset = st.selectbox(
                "Target File",
                ["user_data.txt", "payload.json", "notes.txt", "config.json", "Custom path..."],
                key="sel_file_preset"
            )
            if file_preset == "Custom path...":
                target_filename = st.text_input("Relative File Path", value="data/sample.txt", key="inp_custom_file")
            else:
                target_filename = file_preset

            action_type = st.radio("Operation", ["Write / Inject", "Delete File"], horizontal=True, key="rad_file_action")

        with c2:
            default_content = (
                '{\n  "injected_data": "simulated_payload",\n  "status": "unauthorized"\n}'
                if target_filename.endswith(".json")
                else "CONFIDENTIAL_DATA=987654321\nBACKDOOR_KEY=0x9f7a8b12\n"
            )
            user_content = st.text_area(
                f"Data content for target_system/{target_filename}",
                value=default_content,
                height=115,
                disabled=(action_type == "Delete File"),
                key="txt_user_data"
            )

        btn_c1, btn_c2, _ = st.columns([1.6, 1.6, 3])
        with btn_c1:
            if action_type == "Write / Inject":
                if st.button("Apply to target_system", type="primary", use_container_width=True, key="btn_apply_user_data"):
                    try:
                        saved = target.write_user_data(target_filename, user_content)
                        st.toast(f"Wrote target_system/{saved}! Agent will flag this on-chain within 2s.", icon=":material/save:")
                        st.rerun()
                    except Exception as err:
                        st.toast(f"Error: {err}", icon=":material/error:")
            else:
                if st.button("Delete Target File", type="primary", use_container_width=True, key="btn_delete_user_data"):
                    try:
                        deleted = target.remove_target_file(target_filename)
                        if deleted:
                            st.toast(f"Deleted target_system/{target_filename}! Agent will detect missing file.", icon=":material/delete:")
                        else:
                            st.toast(f"File {target_filename} not found or protected.", icon=":material/warning:")
                        st.rerun()
                    except Exception as err:
                        st.toast(f"Error: {err}", icon=":material/error:")
        with btn_c2:
            if st.button("Refresh File List", use_container_width=True, key="btn_refresh_target_files"):
                st.rerun()

        # Display list of monitored files in target_system/
        current_files = target.list_target_files()
        if current_files:
            file_rows = "".join(
                f'<div class="file-row">'
                f'<span class="f-name">target_system/{f["path"]}</span> '
                f'<span class="f-meta">{f["size"]} · sha256:{f["hash"]} · {f["mtime"]} UTC</span>'
                f'</div>'
                for f in current_files
            )
            st.html(f'<div class="file-list">'
                    f'<div style="color:var(--muted);font-size:.8rem;font-weight:600;margin-bottom:.35rem;text-transform:uppercase;letter-spacing:.06em;">'
                    f'Files Monitored in target_system ({len(current_files)})'
                    f'</div>{file_rows}</div>')


render_data_entry_section()
