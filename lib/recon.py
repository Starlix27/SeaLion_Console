from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from shutil import which

from sealion import PROJECT_ROOT
from http_server import get_web_url as _serve_get_url


SLRECON_SCRIPT = PROJECT_ROOT / "static" / "slrecon.sh"


def _wl(path: str, *fallbacks: str) -> str:
    """Risolve il path di una wordlist; se manca, prova le alternative."""
    if os.path.isfile(path):
        return path
    try:
        from lib import wordlists as _wlsearch
        for cand in (path, *fallbacks):
            hit = _wlsearch.find_wordlist(cand)
            if hit:
                return hit
    except Exception:
        pass
    return path


def _is_ip(host: str | None) -> bool:
    if not host:
        return False
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# I comandi mostrati da 'recon -i' (senza -v): pochi ma essenziali
_RECON_ESSENTIAL = (
    "rustscan -g",             # port discovery TCP
    "-sV -sC",                 # versioni + script default (rustscan → nmap)
    "-sU --top-ports",         # scan UDP (nmap: rustscan è TCP-only)
    "feroxbuster -u",          # directory scan (preferito)
    "gobuster dir",            # directory scan (fallback)
    "ffuf -u",                 # vhost fuzzing
    "wpscan",                  # se WordPress
    " --wordlists",            # worker wordlist in parallelo
)


def _print_recon_info(profile: str, target: str | None, phase: str | None = None,
                      verbose: bool = False) -> None:
    """Mostra i comandi per replicare la recon a mano (-v: tutti, spiegati)."""
    from lib.linseal import render_explained

    shown_target = shlex.quote(target) if target else "<target>"
    vhost_domain = "<dominio.htb>" if _is_ip(target) else shown_target
    selected_phase = phase or ("wordlists" if profile == "wordlists" else "all")

    if profile == "fast":
        summary = "top 1000 TCP, web base, niente UDP o service follow-up"
    elif profile == "medium":
        summary = "top 10000 TCP, top 20 UDP, wordlist complete in shell separata, follow-up servizi"
    elif profile == "wordlists":
        summary = "solo discovery web basata su wordlist"
    else:
        summary = "tutte le 65535 TCP, top 50 UDP, wordlist complete, follow-up servizi"

    sections: list[tuple[str, list[tuple[str, str | None]]]] = []

    if selected_phase == "all" and profile in {"medium", "full"}:
        sections.append(("AVVIO IMMEDIATO / SHELL SEPARATA", [
            ("Le scansioni con wordlist partono PRIMA di nmap, in parallelo:\n"
             "durano molto e non dipendono dalle porte. INVIO le ferma tutte;\n"
             "il report finale aspetta il worker e ne allega l'output",
             f"recon {shown_target} --wordlists"),
        ]))

    if selected_phase in {"all", "ports"} and profile != "wordlists":
        if profile == "fast":
            discovery = f"rustscan -g --top -a {shown_target}"
            discovery_why = "Top 1000 porte TCP (RustScan): veloce, trova subito i servizi esposti"
        elif profile == "medium":
            discovery = f"rustscan -g -r 1-10000 -a {shown_target}"
            discovery_why = "Porte 1-10000 TCP (RustScan): buon compromesso copertura/tempo"
        else:
            discovery = f"rustscan -g -a {shown_target}"
            discovery_why = "TUTTE le 65535 porte TCP in secondi (RustScan): nessun servizio nascosto sfugge"

        port_items: list[tuple[str, str | None]] = [
            ("Verifica che l'host sia vivo; rustscan non pinga:\n"
             "-Pn serve solo ai passi nmap (NSE, UDP, fallback)",
             f"ping -c 1 -W 2 {shown_target}"),
            (discovery_why, discovery),
            ("Fallback se rustscan non è installato",
             f"nmap [-Pn] -p- -T4 --open --min-rate 1000 {shown_target}"),
            ("Versioni + script default: rustscan passa le porte trovate a nmap\n"
             "(dopo `--` i flag sono di nmap). È qui che escono banner,\n"
             "titoli HTTP, OS e vulnerabilità ovvie",
             f"rustscan -a {shown_target} -p <porte_tcp> -- [-Pn] -sV -sC"),
            ("Script NSE mirati (nmap-only) in base al servizio trovato:",
             f"nmap [-Pn] --script <script_mirati> -p <porta> --stats-every 10s {shown_target}"),
            ("21: ftp-anon,ftp-syst", None),
            ("25: smtp-commands,smtp-enum-users,smtp-open-relay", None),
            ("53: dns-zone-transfer,dns-nsid", None),
            ("web: http-enum,http-headers,http-methods,http-robots.txt", None),
            ("110/143: pop3-capabilities / imap-capabilities", None),
            ("111/2049: rpcinfo,nfs-ls,nfs-showmount,nfs-statfs", None),
            ("139/445: smb-enum-shares,smb-enum-users,smb-os-discovery,smb-vuln-ms17-010", None),
            ("389/636: ldap-rootdse,ldap-search", None),
            ("3306: mysql-info,mysql-enum,mysql-empty-password", None),
            ("3389: rdp-enum-encryption,rdp-ntlm-info", None),
            ("5432: pgsql-brute", None),
            ("5900/5901: vnc-info", None),
            ("6379: redis-info", None),
            ("8009: ajp-methods", None),
            ("27017: mongodb-info,mongodb-databases", None),
        ]
        if profile != "fast":
            udp_count = 20 if profile == "medium" else 50
            port_items.insert(0, ("Lo scan UDP richiede root: prendi sudo una volta sola",
                                  "sudo -v"))
            port_items.insert(1, ("Rinnova sudo in automatico ogni 50s mentre scanni",
                                  "sudo -n -v"))
            port_items.append(
                (f"Top {udp_count} porte UDP (nmap: rustscan è TCP-only): DNS, SNMP, NTP... lenti ma spesso decisivi",
                 f"sudo -n nmap [-Pn] -sU --top-ports {udp_count} -T4 --stats-every 10s {shown_target}"))
        sections.append(("PORT DISCOVERY", port_items))

    if selected_phase in {"all", "web", "wordlists"}:
        web_items: list[tuple[str, str | None]] = []
        if _is_ip(target):
            web_items.append(
                ("Il target è un IP: il vhost fuzzing viene saltato —\n"
                 "esporta SLRECON_VHOST_DOMAIN=<dominio.htb> per abilitarlo", None))
        if selected_phase == "wordlists" or profile == "wordlists":
            web_items.extend([
                ("Trova su quali porte comuni risponde un servizio web",
                 f"nc -z -w 2 {shown_target} <80|443|8080|8443|8000|3000|8888>"),
                ("Rileva WordPress (poi lancia wpscan)", "curl -sk -m 5 <base>/"),
            ])
        else:
            web_items.extend([
                ("Trova le porte web anche se nmap non le ha identificate come HTTP",
                 f"nc -z -w 2 {shown_target} <porte_web_comuni>"),
                ("C'è un WAF davanti? Se sì, calibra wordlist e thread",
                 "timeout -k 5s 20s wafw00f <base>"),
                ("Header HTTP: server, tecnologie, cookie", "curl -skI -m 5 <base>/"),
                ("Cipher SSL/TLS deboli o scaduti", f"nmap --script ssl-enum-ciphers -p <porta_web> [-Pn] {shown_target}"),
                ("Path nascosti lasciati dai crawler", "curl -sk -m 5 <base>/robots.txt"),
                ("Sitemap: elenco delle pagine note", "curl -sk -m 5 <base>/sitemap.xml"),
                ("CMS, framework e commenti nel body", "curl -sk -m 5 <base>/"),
                ("Backup dimenticati dei file sensibili (.bak, .old, ~, .zip...)",
                 "curl -sk -m 3 <base>/<file><estensione_backup>"),
                ("Nei JS si nascondono endpoint API e segreti hardcoded",
                 "curl -sk -m 5 <file.js>"),
            ])

        if profile != "fast":
            if profile == "medium":
                directory_wordlist = _wl("/usr/share/seclists/Discovery/Web-Content/common.txt")
                vhost_wordlist = _wl("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                                     "/usr/share/seclists/Discovery/DNS/namelist.txt")
                wp_enum = "vp,u"
                arjun_limit = 15
                nikto_limit = 30
            else:
                directory_wordlist = _wl("/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
                                         "/usr/share/seclists/Discovery/Web-Content/common.txt")
                vhost_wordlist = _wl("/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
                                     "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                                     "/usr/share/seclists/Discovery/DNS/namelist.txt")
                wp_enum = "vp,vt,u"
                arjun_limit = 30
                nikto_limit = 60
            if profile == "wordlists" or (
                selected_phase == "all" and profile in {"medium", "full"}
            ):
                directory_wordlist = _wl("/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
                                         "/usr/share/seclists/Discovery/Web-Content/common.txt")
                vhost_wordlist = _wl("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                                     "/usr/share/seclists/Discovery/DNS/namelist.txt")
                wp_enum = "vp,vt,u"
                arjun_limit = 30
                nikto_limit = 60
                web_items.extend([
                    ("Se è WordPress: plugin, temi e utenti enumerabili",
                     f"timeout -k 5s 60s wpscan --url <base> --enumerate {wp_enum} --no-banner"),
                    ("Directory/file nascosti, ricorsivo, si auto-calibra sugli errori:\n"
                     "è lo scanner principale. Output con prefisso [tool:porta],\n"
                     "INVIO ferma l'intero gruppo e la recon continua",
                     f"feroxbuster -u <base> -w {directory_wordlist} -t 15 -d 2 -k --auto-tune -C 404 [--filter-size <size>]"),
                    ("Alternativa a feroxbuster se non è installato",
                     f"gobuster dir -u <base> -w {directory_wordlist} -t 15 [--exclude-length <size>]"),
                    ("Sottodomini/virtual host sullo stesso IP: spesso rivela\n"
                     "applicazioni nascoste. Thread ridotti per non disturbare gli altri scan",
                     f"ffuf -u <base>/ -H 'Host: FUZZ.{vhost_domain}' -w {vhost_wordlist} -ac -mc 200,302,301,401,403 -t 15 -c -s"),
                    ("Scopre parametri GET/POST nascosti (?id=, ?file=...)",
                     f"timeout -k 5s {arjun_limit}s arjun -u <base>/ -q -t 10"),
                    ("Misconfigurazioni e file pericolosi noti sul server web",
                     f"timeout -k 5s {nikto_limit}s nikto -h <base> -nointeractive -maxtime {nikto_limit}s -Tuning 123bde"),
                    ("Mirror del sito per analisi offline:\n"
                     "grep password, commenti HTML, path interni",
                     f"httrack <base> -O loot/recon/{shown_target}/mirror -r4 --quiet -%e0"),
                ])
            else:
                web_items.extend([
                    ("Se è WordPress: plugin, temi e utenti enumerabili",
                     f"timeout -k 5s 60s wpscan --url <base> --enumerate {wp_enum} --no-banner"),
                    ("Calibrazione: dimensione della risposta a una pagina inesistente,\n"
                     "serve per filtrare i falsi positivi",
                     "curl -sk -o /dev/null -w '%{size_download}' -m 2 <base>/slr_cal_<casuale>"),
                    ("Directory/file nascosti. Output live, INVIO ferma e continua",
                     f"gobuster dir -u <base> -w {directory_wordlist} -t 50 [--exclude-length <size>]"),
                    ("Baseline: dimensione risposta con Host inesistente",
                     "curl -sk -m 5 -H 'Host: nonexistent.xyz' <base>/"),
                    ("Virtual host nascosti, filtrando la dimensione della baseline.\n"
                     "Output live, INVIO ferma e continua",
                     f"ffuf -u <base>/ -H 'Host: FUZZ.{vhost_domain}' -w {vhost_wordlist} -fs <size> -mc 200,302,301,401,403 -t 50 -c -s"),
                    ("Scopre parametri GET/POST nascosti (?id=, ?file=...)",
                     f"timeout -k 5s {arjun_limit}s arjun -u <base>/ -q -t 10"),
                    ("Misconfigurazioni e file pericolosi noti sul server web",
                     f"timeout -k 5s {nikto_limit}s nikto -h <base> -nointeractive -maxtime {nikto_limit}s -Tuning 123bde"),
                ])
        sections.append(("WEB / WORDLIST", web_items))

    if selected_phase in {"all", "services"} and profile not in {"fast", "wordlists"}:
        kerberos_limit = 60 if profile == "medium" else 120
        snmp_wordlist = _wl("/usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt")
        kerb_wordlist = _wl("/usr/share/seclists/Usernames/xato-net-10-million-usernames-nt.txt",
                            "/usr/share/seclists/Usernames/Names/names.txt")
        kerb_fallback = _wl("/usr/share/seclists/Usernames/Names/names.txt")
        service_items: list[tuple[str, str | None]] = [
            ("FTP anonimo: spesso contiene file dimenticati",
             f"curl -sS -m 10 ftp://{shown_target}/ --user anonymous:anonymous"),
            ("Configurazione SSH: algoritmi deboli, versione, banner",
             f"timeout -k 5s 60s ssh-audit {shown_target}"),
            ("SMTP VRFY: verifica se un utente esiste",
             f"printf 'VRFY root\\n' | nc -w 3 {shown_target} 25"),
            ("Se VRFY è attivo: enumera tutti gli utenti",
             f"timeout -k 5s 60s smtp-user-enum -M VRFY -U <names.txt> -t {shown_target}"),
            ("Zone transfer DNS: ti regala TUTTI i record del dominio",
             f"timeout -k 2s 15s dig @{shown_target} axfr {shown_target}"),
            ("Enum DNS completa: record, sottodomini, server",
             f"timeout -k 5s 60s dnsenum --dnsserver {shown_target} {shown_target} --noreverse"),
            ("Export NFS montabili", f"timeout -k 2s 15s showmount -e {shown_target}"),
            ("Enum SMB completa: share, utenti, policy, OS",
             f"timeout -k 5s 120s enum4linux-ng -A {shown_target}"),
            ("Share SMB con accesso anonimo, con permessi", f"timeout -k 2s 30s smbmap -H {shown_target} -u '' -p ''"),
            ("Share SMB (alternativa veloce)", f"timeout -k 2s 30s smbclient -L //{shown_target} -N"),
            ("LDAP anonymous bind: rootDSE espone naming context e domino",
             f"timeout -k 2s 20s ldapsearch -x -H ldap://{shown_target} -b '' -s base '(objectclass=*)'"),
            ("Se il bind anonimo funziona: enumera gli utenti",
             f"timeout -k 5s 60s ldapsearch -x -H ldap://{shown_target} -b <baseDN> '(objectclass=person)' cn uid sAMAccountName description"),
            ("Sicurezza RDP: NLA, encryption, certificato", f"timeout -k 2s 30s rdp-sec-check {shown_target}"),
            ("RDP NTLM info: nome dominio e macchina", f"timeout -k 2s 30s nmap [-Pn] --script rdp-ntlm-info -p 3389 {shown_target}"),
            ("MySQL con credenziali deboli/vuote",
             f"timeout -k 2s 8s mysql --connect-timeout=5 -h {shown_target} -u <root|mysql|admin> --password=<vuota|root|mysql|password|toor> -e 'SELECT VERSION();'"),
            ("Dopo un login riuscito: elenca i database", "mysql ... -e 'SHOW DATABASES;'"),
            ("PostgreSQL con credenziali deboli",
             f"PGPASSWORD=<vuota|postgres|password|admin> timeout -k 2s 8s psql -w -h {shown_target} -U <postgres|admin> -c 'SELECT version();'"),
            ("Dopo un login riuscito: elenca i database", "psql ... -c '\\l'"),
            ("Redis senza autenticazione: info sul server",
             f"printf 'INFO server\\r\\nQUIT\\r\\n' | nc -w 5 {shown_target} 6379"),
            ("Se Redis è no-auth: puoi leggere TUTTE le chiavi",
             f"printf 'KEYS *\\r\\nQUIT\\r\\n' | nc -w 5 {shown_target} 6379"),
            ("MongoDB no-auth: elenca i database",
             f"timeout -k 2s 20s mongosh --host {shown_target} --eval \"db.adminCommand('listDatabases')\" --quiet"),
            ("Community string SNMP via wordlist (UDP 161)",
             f"timeout -k 5s 60s onesixtyone -c {snmp_wordlist} {shown_target}"),
            ("Fallback: solo le community più comuni",
             f"printf 'public\\nprivate\\ncommunity\\n' | timeout -k 5s 20s onesixtyone -c /dev/stdin {shown_target}"),
            ("Con la community trovata: info di sistema", f"timeout -k 5s 30s snmpwalk -v2c -c <community> {shown_target} 1.3.6.1.2.1.1"),
            ("Interfacce di rete (IP interni, altre reti)", f"timeout -k 5s 30s snmpwalk -v2c -c <community> {shown_target} 1.3.6.1.2.1.2.2.1.2"),
            ("Processi in esecuzione (a volte con credenziali nella cmdline)", f"timeout -k 5s 30s snmpwalk -v2c -c <community> {shown_target} 1.3.6.1.2.1.25.4.2.1"),
            ("Software installato → versioni → exploit", f"timeout -k 5s 30s snmpwalk -v2c -c <community> {shown_target} 1.3.6.1.2.1.25.6.3.1.2"),
            ("Utenti locali della macchina", f"timeout -k 5s 30s snmpwalk -v2c -c <community> {shown_target} 1.3.6.1.4.1.77.1.2.25"),
            ("Enum utenti Kerberos/AD via wordlist (utenti validi senza password)",
             f"timeout -k 5s {kerberos_limit}s kerbrute userenum -d {shown_target} --dc {shown_target} {kerb_wordlist}"),
            (f"fallback wordlist: {kerb_fallback}", None),
        ]
        sections.append(("SERVICE FOLLOW-UP (read-only)", service_items))

    if selected_phase in {"all", "report", "ports", "web", "services", "wordlists"}:
        report_items = [("Parsing porte TCP/UDP e versioni servizi", None)]
        if selected_phase == "all" and profile in {"medium", "full"}:
            report_items.append(("Attesa del worker wordlist e allegato wordlist_scan.txt", None))
        report_items.extend([
            ("Riepilogo finding, warning, timeout, tool mancanti e copertura incompleta", None),
            ("Timer totale T+hh:mm:ss e suggerimenti successivi", None),
        ])
        sections.append(("REPORT", report_items))

    render_explained(
        f"RECON {profile.upper()} — replicare lo scan a mano" + (" (verbose)" if verbose else ""),
        [f"Target:  \033[96m{shown_target}\033[0m",
         f"Fase:    \033[96m{selected_phase}\033[0m",
         f"Profilo: {summary}",
         "Questa modalità è solo informativa: nessun comando viene eseguito."],
        sections,
        verbose=verbose,
        essential=_RECON_ESSENTIAL,
    )


def cmd_recon(args: argparse.Namespace, state=None) -> int:
    target = getattr(args, "target", None)

    if target in {"help", "-h", "--help"}:
        print(
            "\n  \033[1mrecon\033[0m — Reconnaissance automatica\n\n"
            "  \033[93mrecon <target>\033[0m              Scan completo\n"
            "  \033[93mrecon <target> -s\033[0m           Apri in nuova finestra del terminale\n"
            "  \033[93mrecon <target> -o\033[0m           Salva output in loot/recon/<target>/\n"
            "  \033[93mrecon <target> -lo\033[0m          Salva + upload a loot\n"
            "  \033[93mrecon <target> -slo <name>\033[0m  Shell separata + salva in loot/recon/<name>/\n"
            "  \033[93mrecon <target> --medium\033[0m     Bilanciata + wordlist completa in shell separata\n"
            "  \033[93mrecon <target> --wordlists\033[0m  Solo dir scan, VHost, wpscan, nikto, arjun\n"
            "  \033[93mrecon <target> --fast\033[0m       Solo top ports + web base\n"
            "  \033[93mrecon <target> --phase web\033[0m  Solo una fase (ports/web/services/report)\n"
            "  \033[93mrecon <target> --no-ping\033[0m    Salta il ping check (-Pn sui passi nmap)\n"
            "  \033[93mrecon medium -i\033[0m            I comandi essenziali di MEDIUM, pronti da copiare\n"
            "  \033[93mrecon <target> --medium -i\033[0m Essenziali già risolti per il target\n"
            "  \033[93mrecon <target> -vi\033[0m          TUTTI i comandi con spiegazioni (verbose)\n"
            "  \033[93mrecon status\033[0m                Mostra scan in corso\n"
            "  \033[93mrecon report <target>\033[0m       Rimostra ultimo report\n"
        )
        return 0

    if getattr(args, "info", False):
        method = target.lower() if isinstance(target, str) else ""
        info_target = target
        phase = getattr(args, "phase", None)
        if method in {"fast", "medium", "full", "wordlist", "wordlists"}:
            profile = "wordlists" if method == "wordlist" else method
            info_target = None
        elif method in {"ports", "web", "services", "report"}:
            profile = "full"
            phase = method
            info_target = None
        elif getattr(args, "wordlists", False):
            profile = "wordlists"
            phase = "wordlists"
        elif getattr(args, "fast", False):
            profile = "fast"
        elif getattr(args, "medium", False):
            profile = "medium"
        else:
            profile = "full"
        _print_recon_info(profile, info_target, phase,
                          verbose=getattr(args, "verbose", False))
        return 0

    if target == "status":
        print("  \033[93m[*]\033[0m Controlla il terminale per il progresso dello scan.")
        return 0

    if target == "report":
        extra = getattr(args, "phase", None) or getattr(args, "target", None)
        # try second positional
        report_target = None
        for a in sys.argv:
            if a != "recon" and a != "report" and not a.startswith("-"):
                report_target = a
        if report_target:
            report_file = Path(f"loot/recon/{report_target}/report.txt")
            if report_file.exists():
                print(report_file.read_text(encoding="utf-8", errors="replace"))
            else:
                print(f"  Nessun report trovato per {report_target}")
                print(f"  Cercato in: {report_file}")
        else:
            print("  Uso: recon report <target>")
        return 0

    if not target:
        print("  Uso: \033[93mrecon <target>\033[0m | \033[93mrecon help\033[0m")
        return 0

    if not SLRECON_SCRIPT.exists():
        print(f"  \033[91mScript non trovato: {SLRECON_SCRIPT}\033[0m")
        return 1

    # Build command
    cmd_parts = ["sh", str(SLRECON_SCRIPT), target]
    if getattr(args, "save", False):
        cmd_parts.append("-o")
    if getattr(args, "loot", False):
        cmd_parts.append("-l")
    if getattr(args, "fast", False):
        cmd_parts.append("--fast")
    if getattr(args, "medium", False):
        cmd_parts.append("--medium")
    if getattr(args, "no_ping", False):
        cmd_parts.append("--no-ping")
    phase = getattr(args, "phase", None)
    if getattr(args, "wordlists", False):
        phase = "wordlists"
    if phase:
        cmd_parts.extend(["--phase", phase])
    name = getattr(args, "name", None)
    if name:
        cmd_parts.extend(["--name", name])

    # Inject LHOST
    url = _serve_get_url()
    if url:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.hostname:
            cmd_parts.extend(["-L", parsed.hostname])

    # Quote only for terminal launch/display; direct execution uses argv so a
    # hostname can never be interpreted as shell syntax.
    recon_cmd = shlex.join(cmd_parts)
    separate = getattr(args, "separate", False)

    if separate and os.environ.get("TMUX"):
        subprocess.run(
            ["tmux", "split-window", "-h", "-l", "50%", recon_cmd],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        print(f"  Recon avviato su \033[1m{target}\033[0m in pane tmux")
        print(f"  \033[93m$ {recon_cmd}\033[0m")
    elif separate:
        title_esc = f"printf '\\033]0;SLRecon: %s\\007' {shlex.quote(target)}"
        shell_cmd = title_esc + '; ' + recon_cmd + '; echo; echo "\\033[92m[✓] Scan completato. Premi INVIO per chiudere.\\033[0m"; read _'
        launched = False
        if os.environ.get("WSL_DISTRO_NAME") or os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"):
            # Windows ri-parsa la command line e rompe i doppi apici annidati
            # (errore 0x80070002): verso wsl.exe passa solo il path di uno script.
            from lib import windows_terminal_argv
            argv = windows_terminal_argv(f"SLRecon: {target}", shell_cmd)
            if argv:
                subprocess.Popen(
                    argv,
                    start_new_session=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                launched = True
        if not launched:
            for term in ("x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "xterm"):
                term_path = which(term)
                if term_path:
                    if term == "gnome-terminal":
                        subprocess.Popen(
                            [term_path, "--title", f"SLRecon: {target}", "--", "sh", "-c", shell_cmd],
                            start_new_session=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                    elif term == "konsole":
                        subprocess.Popen(
                            [term_path, "--title", f"SLRecon: {target}", "-e", "sh", "-c", shell_cmd],
                            start_new_session=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                    else:
                        subprocess.Popen(
                            [term_path, "-e", "sh", "-c", shell_cmd],
                            start_new_session=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                    launched = True
                    break
        if not launched:
            print("  \033[91mNessun terminale trovato.\033[0m Eseguo qui:")
            print(f"  \033[93m$ {recon_cmd}\033[0m\n")
            completed = subprocess.run(cmd_parts)
            return completed.returncode
        print(f"  Recon avviato su \033[1m{target}\033[0m in nuova finestra")
        print(f"  \033[93m$ {recon_cmd}\033[0m")
        if getattr(args, "save", False) or getattr(args, "loot", False):
            _outname = name or target
            print(f"  Output in: \033[96mloot/recon/{_outname}/\033[0m")
    else:
        print(f"  Recon avviato su \033[1m{target}\033[0m")
        print(f"  \033[93m$ {recon_cmd}\033[0m\n")
        completed = subprocess.run(cmd_parts)
        return completed.returncode

    return 0


# ── Pet ──────────────────────────────────────────────────────────────────────
