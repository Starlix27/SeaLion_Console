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
PROJECT_ROOT = Path(__file__).resolve().parent
TOOL_ROOT = PROJECT_ROOT / "tool"
VULN_ROOT = PROJECT_ROOT / "vuln"
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
    last_search_results: list[ToolEntry] = field(default_factory=list)


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
    print("  search <query>     Cerca tool per nome o testo")
    print("  use <nome|num>     Seleziona un tool")
    print("  install [nome]     Installa il tool selezionato o specificato")
    print("  vuln <protocollo>  Mostra vulnerabilità e tool per un protocollo")
    print("  vuln list          Elenca i protocolli disponibili")
    print("  vuln *             Elenca i protocolli disponibili") 
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

    if target.isdigit():
        tools = discover_tools()
        if state is not None and state.last_search_results:
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
        "list": cmd_list,
        "install": cmd_install,
        "use": cmd_use,
        "back": cmd_back,
        "search": cmd_search,
        "vuln": cmd_vuln,
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
            prompt = f"\033[94mConsole({state.current_tool.name})> \033[0m" if state.current_tool else "\033[94mslconsole> \033[0m"
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

        known_commands = {"list", "install", "use", "search", "vuln", "back", "help", "?", "--version", "-h", "--help"}
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
    print_tool_context(tool)
    return 0


def cmd_back(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    if state is None:
        return 0
    state.current_tool = None
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


def discover_vulns() -> list[str]:
    if not VULN_ROOT.is_dir():
        return []
    return sorted(p.stem for p in VULN_ROOT.glob("*.md"))


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

    render_markdown(vuln_file.read_text(encoding="utf-8", errors="replace"))
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


if __name__ == "__main__":
    raise SystemExit(main())
