"""Dashboard look: dark theme CSS + SVG mask icons (no external assets besides Google Fonts)."""
import base64

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
  --bg: #0f1217; --panel: #14181e; --panel-2: #11151a; --line: #262c34;
  --text: #e6e8eb; --muted: #8b949e;
  --green: #4ade80; --green-bg: rgba(34,197,94,.08); --green-line: rgba(74,222,128,.40);
  --blue: #60a5fa;  --blue-bg: rgba(59,130,246,.10);  --blue-line: rgba(96,165,250,.50);
  --red: #ff5f5f;   --red-bg: rgba(239,68,68,.11);    --red-line: rgba(255,95,95,.60);
  --amber: #fbbf24; --amber-bg: rgba(251,191,36,.08); --amber-line: rgba(251,191,36,.40);
  --mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
}
.stApp { background: var(--bg); font-family: 'Inter', system-ui, -apple-system, sans-serif; }

/* ---- hide Streamlit chrome (the toolbar stays: it holds the reopen-sidebar button) */
header[data-testid="stHeader"] { background: transparent; }
[data-testid="stToolbarActions"], [data-testid="stMainMenu"], [data-testid="stAppDeployButton"], [data-testid="stDecoration"], [data-testid="stStatusWidget"], footer { display: none !important; }
[data-testid="stMainBlockContainer"] { padding: 2rem 1.75rem 3rem; max-width: 1080px; }

/* ---- sidebar = demo panel */
section[data-testid="stSidebar"] { background: #161a20; border-right: 1px solid var(--line); width: 256px !important; min-width: 256px !important; }
[data-testid="stSidebarHeader"] { height: 1rem; min-height: 1rem; padding: 0; }
[data-testid="stSidebarUserContent"] { padding: 1rem 1rem 2rem; }
.side-title { font-weight: 600; font-size: 1.05rem; color: var(--text); }
.side-sub { color: var(--muted); font-size: .95rem; margin-top: .1rem; }
.side-info { color: var(--muted); font-size: .92rem; line-height: 1.6; margin-top: .75rem; }

.side-label { color: var(--muted); font-size: .75rem; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; margin: 1rem 0 -.25rem; }
.side-info .mono { color: var(--text); font-size: .85rem; }

/* every demo button: [class*="st-key-btn_"] matches the keyed element containers */
[class*="st-key-btn_"] button {
  min-height: 52px; border-radius: 10px; background: transparent; padding: .45rem 1rem;
  justify-content: flex-start; transition: background .15s, border-color .15s, transform .05s;
}
[class*="st-key-btn_"] button > div { justify-content: flex-start; gap: .65rem; }
[class*="st-key-btn_"] button p { font-size: 1.05rem; line-height: 1.25; text-align: left; font-weight: 500; }
[class*="st-key-btn_"] button [data-testid="stIconMaterial"] { font-size: 1.3rem; }
[class*="st-key-btn_"] button:active { transform: scale(.98); }
[class*="st-key-btn_"] button:focus:not(:active) { box-shadow: none; }

.st-key-btn_hack button, .st-key-btn_binary button, .st-key-btn_memory button, .st-key-btn_inject_data button { border: 1px solid rgba(248,113,113,.55); color: #f87171; }
.st-key-btn_hack button:hover, .st-key-btn_binary button:hover, .st-key-btn_memory button:hover, .st-key-btn_inject_data button:hover { border-color: #f87171; background: rgba(248,113,113,.08); color: #fca5a5; }
.st-key-btn_approve button { border: 1px solid rgba(96,165,250,.55); color: var(--blue); }
.st-key-btn_approve button:hover { border-color: var(--blue); background: rgba(96,165,250,.08); color: #93c5fd; }
.st-key-btn_reset button { border: 1px solid var(--line); color: var(--text); }
.st-key-btn_reset button:hover { border-color: #3a424d; background: rgba(255,255,255,.03); color: var(--text); }

/* ---- header */
.topbar { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; margin-bottom: .25rem; }
.title { font-size: 1.75rem; font-weight: 600; color: var(--text); letter-spacing: -.01em; line-height: 1.2; }
.subtitle { color: var(--muted); font-size: 1rem; margin-top: .2rem; }
.live { display: flex; align-items: center; gap: .45rem; color: var(--muted); font-size: 1rem; white-space: nowrap; padding-top: .35rem; }
.live .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--green); box-shadow: 0 0 8px rgba(74,222,128,.7); }
.live.off .dot { background: var(--red); box-shadow: 0 0 8px rgba(255,95,95,.7); }
.live .mono { color: var(--text); }
.mono { font-family: var(--mono); }

/* ---- status banner */
.status { display: flex; align-items: center; gap: 1.4rem; padding: 1.5rem 1.75rem; border: 1px solid; border-radius: 14px; }
.status-title { font-size: 1.9rem; font-weight: 700; line-height: 1.15; letter-spacing: -.01em; }
.status-msg { font-size: 1.08rem; font-weight: 500; margin-top: .3rem; }
.status-meta { color: var(--muted); font-size: .95rem; margin-top: .35rem; }
.s-verified   { background: var(--green-bg); border-color: var(--green-line); color: var(--green); }
.s-authorized { background: var(--blue-bg);  border-color: var(--blue-line);  color: var(--blue); }
.s-tamper     { background: var(--red-bg);   border-color: var(--red-line);   color: var(--red); animation: alarm 1.6s ease-in-out infinite; }
.s-offline    { background: var(--amber-bg); border-color: var(--amber-line); color: var(--amber); }
@keyframes alarm {
  0%, 100% { box-shadow: 0 0 0 0 rgba(255,95,95,0); }
  50%      { box-shadow: 0 0 0 5px rgba(255,95,95,.14), 0 0 36px rgba(255,95,95,.22); }
}
.changes { margin-top: .8rem; display: grid; gap: .3rem; font-family: var(--mono); font-size: .86rem; }
.change { color: var(--text); overflow-wrap: anywhere; }
.change .k { color: var(--muted); }
.change .old { color: var(--muted); text-decoration: line-through; }
.s-tamper .change .new { color: #fca5a5; }
.s-authorized .change .new { color: #bfdbfe; }
.cmd { font-family: var(--mono); font-size: .9rem; color: var(--text); background: rgba(0,0,0,.25); border-radius: 8px; padding: .6rem .8rem; margin-top: .7rem; line-height: 1.7; }

/* ---- cards */
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 1.2rem 1.35rem; }
.card-head { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; flex-wrap: wrap; color: var(--muted); font-size: 1.02rem; margin-bottom: 1rem; }
.card-head .mono { font-size: .95rem; }
.hash-row + .hash-row { margin-top: 1rem; }
.hash-label { color: var(--muted); font-size: .98rem; margin-bottom: .3rem; }
.hash { font-family: var(--mono); font-size: 1.05rem; color: var(--text); word-spacing: .3em; overflow-wrap: anywhere; }
.hash .bad { color: var(--red); }
.hash.pending { color: var(--blue); }

/* ---- audit trail */
.blocks { display: flex; align-items: center; gap: .6rem; margin-bottom: 1.2rem; }
.blk { flex: 1 1 0; min-width: 0; background: var(--panel-2); border: 1px solid var(--line); border-radius: 10px; padding: .75rem 1rem; }
.blk-n { color: var(--muted); font-size: .95rem; }
.blk-v { font-family: var(--mono); font-size: 1.02rem; margin-top: .2rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--text); }
.blk.authorized { border-color: rgba(96,165,250,.35); } .blk.authorized .blk-v { color: var(--blue); }
.blk.tamper { border-color: rgba(255,95,95,.45); }      .blk.tamper .blk-v { color: var(--red); }
.chain-link { color: var(--muted); flex: none; display: flex; }
.table-wrap { overflow-x: auto; }
table.trail { width: 100%; border-collapse: collapse; font-size: .98rem; }
.trail th { text-align: left; color: var(--muted); font-weight: 400; padding: .55rem .75rem .55rem 0; border-bottom: 1px solid var(--line); }
.trail td { padding: .7rem .75rem .7rem 0; color: var(--text); border-bottom: 1px solid rgba(38,44,52,.55); white-space: nowrap; }
.trail tr:last-child td { border-bottom: 0; }
.trail .mono { font-size: .95rem; }
.trail .st-anchored { color: var(--green); } .trail .st-authorized { color: var(--blue); } .trail .st-tamper { color: var(--red); font-weight: 500; }


/* ---- measured components */
.comp { display: grid; grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr) minmax(0, 1fr) auto; align-items: center; gap: 1rem;
  padding: .8rem 1rem; border: 1px solid var(--line); border-radius: 10px; background: var(--panel-2); }
.comp + .comp { margin-top: .6rem; }
.comp-name { color: var(--text); font-weight: 500; font-size: 1.02rem; min-width: 0; }
.comp-desc { color: var(--muted); font-weight: 400; font-size: .88rem; margin-top: .1rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.comp-k { color: var(--muted); font-size: .8rem; }
.comp-hash .mono { color: var(--text); font-size: .98rem; }
.comp.bad { border-color: rgba(255,95,95,.55); background: rgba(239,68,68,.07); }
.comp.bad .measured .mono { color: var(--red); }
.comp.upd { border-color: rgba(96,165,250,.5); }
.pill { min-width: 5.6rem; text-align: center; font-size: .85rem; font-weight: 500; padding: .2rem .65rem; border-radius: 999px; white-space: nowrap; }
.pill.ok { color: var(--green); background: rgba(74,222,128,.10); }
.pill.bad { color: var(--red); background: rgba(255,95,95,.14); }
.pill.upd { color: var(--blue); background: rgba(96,165,250,.14); }

/* ---- attestation */
.kv-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: .9rem 1.25rem; }
.kv-k { color: var(--muted); font-size: .85rem; }
.kv-v { color: var(--text); font-size: .98rem; margin-top: .15rem; overflow-wrap: anywhere; }
.kv-v .ok { color: var(--green); } .kv-v .bad { color: var(--red); font-weight: 500; }
.blk.beat { border-style: dashed; } .blk.beat .blk-v { color: var(--muted); }

@media (max-width: 760px) {
  .comp { grid-template-columns: minmax(0, 1fr) auto; }
  .comp-hash { display: none; }
  .kv-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

/* ---- data entry & target file management */
.entry-card { background: var(--panel); border: 1px solid var(--line); border-radius: 14px; padding: 1.2rem 1.35rem; margin-top: 1rem; margin-bottom: 1rem; }
.entry-title { font-size: 1.15rem; font-weight: 600; color: var(--text); display: flex; align-items: center; justify-content: space-between; }
.entry-desc { color: var(--muted); font-size: .92rem; margin-top: .3rem; margin-bottom: 1rem; }
.file-list { margin-top: .9rem; border-top: 1px solid var(--line); padding-top: .8rem; }
.file-row { display: flex; justify-content: space-between; align-items: center; padding: .35rem 0; font-family: var(--mono); font-size: .88rem; color: var(--text); }
.file-row .f-name { color: var(--blue); }
.file-row .f-meta { color: var(--muted); font-size: .82rem; }

@media (max-width: 640px) {
  [data-testid="stMainBlockContainer"] { padding: 1.25rem 1rem 2rem; }
  .topbar { flex-direction: column; gap: .25rem; }
  .status { padding: 1.1rem; gap: 1rem; }
  .status-title { font-size: 1.5rem; }
  .blocks { flex-wrap: wrap; }
  .blk { flex-basis: calc(50% - .3rem); }
  .chain-link { display: none; }
}
</style>
"""

_SHIELD = ('<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1'
           'c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>')

# st.html sanitizes inline <svg>, so icons are CSS masks: the SVG only supplies the shape and
# `background: currentColor` paints it, so every icon picks up its banner's state color.
_ICONS = {
    "verified": _SHIELD + '<path d="m9 12 2 2 4-4"/>',
    "authorized": _SHIELD + '<path d="M12 15.5V9"/><path d="m9.2 11.6 2.8-2.8 2.8 2.8"/>',
    "tamper": _SHIELD + '<path d="M12 8v4.5"/><path d="M12 16h.01"/>',
    "offline": _SHIELD + '<path d="m14.5 9.5-5 5"/><path d="m9.5 9.5 5 5"/>',
    "link": '<path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 1 1 0 10h-2"/><line x1="8" x2="16" y1="12" y2="12"/>',
}


def _mask_rule(name, paths):
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" '
           f'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">{paths}</svg>')
    uri = "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode()
    return f'.ico-{name} {{ -webkit-mask-image: url("{uri}"); mask-image: url("{uri}"); }}'


CSS = CSS.replace("</style>", """
.ico { display: inline-block; flex: none; background: currentColor;
  -webkit-mask-repeat: no-repeat; mask-repeat: no-repeat; -webkit-mask-size: contain; mask-size: contain; }
.ico.big { width: 60px; height: 60px; }
.chain-link .ico { width: 18px; height: 18px; }
@media (max-width: 640px) { .ico.big { width: 44px; height: 44px; } }
""" + "\n".join(_mask_rule(n, p) for n, p in _ICONS.items()) + "\n</style>")

ICON_VERIFIED = '<span class="ico big ico-verified"></span>'
ICON_AUTHORIZED = '<span class="ico big ico-authorized"></span>'
ICON_TAMPER = '<span class="ico big ico-tamper"></span>'
ICON_OFFLINE = '<span class="ico big ico-offline"></span>'
ICON_LINK = '<span class="ico ico-link"></span>'
