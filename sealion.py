#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import re
import platform
import subprocess
import sys
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from shutil import which

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
        result = subprocess.run(
            ["git", "-C", str(PROJECT_ROOT), "pull", "--ff-only", REPO_URL, "main"],
            capture_output=True, text=True, timeout=15,
        )
        out = result.stdout.strip()
        if out and "Already up to date" not in out:
            print(f"\033[92m[update]\033[0m {out.splitlines()[-1]}")
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


def render_markdown(text: str) -> None:
    try:
        from rich.console import Console
        from rich.markdown import Markdown
        console = Console()
        console.print(Markdown(text))
    except ImportError:
        print(text)


def print_banner() -> None:
    print(load_logo())
    print(f"\n{APP_NAME} — personal tool vault\n")


def _read_sealsay_message(argv: list[str]) -> str:
    if argv:
        return " ".join(argv).strip()

    if not sys.stdin.isatty():
        piped = sys.stdin.read().strip()
        if piped:
            return piped

    return "SeaLion"


def _build_sealsay_bubble(message: str) -> list[str]:
    lines = message.splitlines() or [""]
    width = max(len(line) for line in lines)
    bubble: list[str] = []
    bubble.append(f" .{'─' * (width + 2)}.")
    if len(lines) == 1:
        bubble.append(f"│  {lines[0].ljust(width)} │")
    else:
        for line in lines:
            bubble.append(f"│  {line.ljust(width)} │")
    bubble.append(f" '{'─' * (width + 2)}'")
    bubble.append(f"/")
    return bubble


def print_sealsay(message: str) -> None:
    art_lines = load_sealsay_art().splitlines()
    bubble_lines = _build_sealsay_bubble(message)

    art_width = max(len(l) for l in art_lines) if art_lines else 0
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
    print("  sealsay [testo]   Stampa un messaggio in stile cowsay con il sealion")
    print("  list               Elenca i tool disponibili")
    print("  search <query>     Cerca tool per nome o testo")
    print("  use <nome|num>     Seleziona un tool")
    print("  install [nome]     Installa il tool selezionato o specificato")
    print("  vuln <protocollo>  Mostra vulnerabilità e tool per un protocollo")
    print("  vuln list          Elenca i protocolli disponibili")
    print("  vuln *             Elenca i protocolli disponibili")
    print("  notes <argomento>  Mostra una nota/guida (es. footprinting)")
    print("  notes list         Elenca le note disponibili")
    print("  find <parola>      Cerca un testo in vuln, tool e notes")
    print("  help               Mostra questo aiuto")
    print("  back               Torna alla console principale")
    print("  exit               Esci da " + APP_NAME)


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
    return parser


def parse_console_command(line: str) -> list[str]:
    tokens = shlex.split(line)
    if tokens and tokens[0].lower() in {"slconsole", "sealion", "sealionconsole"}:
        return tokens[1:]
    return tokens


def setup_readline() -> None:
    if readline is None:
        return
    try:
        readline.parse_and_bind("tab: complete")
        readline.parse_and_bind("set editing-mode emacs")
    except Exception:
        pass


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
    }
    handler = handlers.get(args.command)
    if handler is None:
        print_help_text()
        return 1
    return handler(args, state)


def run_console() -> int:
    setup_readline()
    state = ConsoleState()
    print_banner()
    print("Digita 'help' per i comandi, 'exit' per uscire.")
    while True:
        try:
            prompt = f"\033[94mConsole({state.current_tool.name})> \033[0m" if state.current_tool else f"\033[94mslconsole({state.current_vuln})> \033[0m" if state.current_vuln else "\033[94mslconsole> \033[0m"
            line = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

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

        known_commands = {"sealsay", "list", "install", "use", "search", "vuln", "notes", "find", "back", "help", "?", "--version", "-h", "--help"}
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
}

NOTES_NAMES: dict[str, str] = {
    "footprinting": "Footprinting — Metodologia di Enumerazione",
    "info-gathering": "Information Gathering — Ricognizione",
    "shells": "Shell & Post-Exploitation — Reverse, Bind, Web Shell, PrivEsc",
    "password-cracking": "Password Cracking — JtR & Hashcat",
    "network-services": "Network Services — WinRM, SSH, RDP, SMB",
    "ssh-notes": "SSH — Note Operative",
    "impacket-notes": "Impacket — Toolkit Python per reti Windows",
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
    """Print markdown text with query highlighted in blue."""
    lower_q = query.lower()
    for line in text.splitlines():
        idx = line.lower().find(lower_q)
        if idx >= 0:
            ql = len(query)
            highlighted = line[:idx] + f"\033[94;1m{line[idx:idx+ql]}\033[0m" + line[idx+ql:]
            print(highlighted)
        else:
            print(line)


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
