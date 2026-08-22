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


def _print_recon_info(profile: str, target: str | None, phase: str | None = None) -> None:
    """Print the resolved recon pipeline without executing it."""
    shown_target = shlex.quote(target) if target else "<target>"
    nmap_target = f"[-Pn] {shown_target}"
    selected_phase = phase or ("wordlists" if profile == "wordlists" else "all")

    if profile == "fast":
        summary = "top 1000 TCP, web base, niente UDP o service follow-up"
    elif profile == "medium":
        summary = "top 10000 TCP, top 20 UDP, wordlist complete in shell separata, follow-up servizi"
    elif profile == "wordlists":
        summary = "solo discovery web basata su wordlist"
    else:
        summary = "tutte le 65535 TCP, top 50 UDP, wordlist complete, follow-up servizi"

    groups: list[tuple[str, list[str]]] = []

    if selected_phase == "all" and profile in {"medium", "full"}:
        groups.append(("AVVIO IMMEDIATO / SHELL SEPARATA", [
            f"recon {shown_target} --wordlists                 # parte prima di sudo e Nmap",
            "  ↳ gira in parallelo all'intera recon; INVIO ferma tutti gli scanner wordlist",
            "  ↳ il report finale aspetta il worker e ne allega l'output",
        ]))

    if selected_phase in {"all", "ports"} and profile != "wordlists":
        if profile == "fast":
            discovery = f"nmap [-Pn] -T4 --open --stats-every 10s {shown_target}"
        elif profile == "medium":
            discovery = f"nmap [-Pn] --top-ports 10000 -T4 --open --stats-every 10s {shown_target}"
        else:
            discovery = f"nmap [-Pn] -p- -T4 --open --min-rate 1000 --stats-every 10s {shown_target}"

        port_commands = [
            f"ping -c 1 -W 2 {shown_target}                         # se fallisce, aggiunge -Pn",
            discovery,
            f"nmap [-Pn] -sV -sC -p <porte_tcp> --stats-every 10s {shown_target}",
            f"nmap [-Pn] --script <script_mirati> -p <porta> --stats-every 10s {shown_target}",
            "  21: ftp-anon,ftp-syst",
            "  25: smtp-commands,smtp-enum-users,smtp-open-relay",
            "  53: dns-zone-transfer,dns-nsid",
            "  web: http-enum,http-headers,http-methods,http-robots.txt",
            "  110/143: pop3-capabilities / imap-capabilities",
            "  111/2049: rpcinfo,nfs-ls,nfs-showmount,nfs-statfs",
            "  139/445: smb-enum-shares,smb-enum-users,smb-os-discovery,smb-vuln-ms17-010",
            "  389/636: ldap-rootdse,ldap-search",
            "  3306: mysql-info,mysql-enum,mysql-empty-password",
            "  3389: rdp-enum-encryption,rdp-ntlm-info",
            "  5432: pgsql-brute",
            "  5900/5901: vnc-info",
            "  6379: redis-info",
            "  8009: ajp-methods",
            "  27017: mongodb-info,mongodb-databases",
        ]
        if profile != "fast":
            udp_count = 20 if profile == "medium" else 50
            port_commands.insert(0, "sudo -v                                  # richiesto una volta e mantenuto valido")
            port_commands.insert(1, "sudo -n -v                               # rinnovo automatico ogni 50 secondi")
            port_commands.append(
                f"sudo -n nmap [-Pn] -sU --top-ports {udp_count} -T4 --stats-every 10s {shown_target}"
            )
        groups.append(("PORT DISCOVERY", port_commands))

    if selected_phase in {"all", "web", "wordlists"}:
        web_commands: list[str] = []
        if selected_phase == "wordlists" or profile == "wordlists":
            web_commands.extend([
                f"nc -z -w 2 {shown_target} <80|443|8080|8443|8000|3000|8888>",
                f"curl -sk -m 5 <base>/                    # rilevamento WordPress",
            ])
        else:
            web_commands.extend([
                f"nc -z -w 2 {shown_target} <porte_web_comuni>       # fallback se nmap non identifica HTTP",
                "timeout -k 5s 20s wafw00f <base>",
                "curl -skI -m 5 <base>/",
                f"nmap --script ssl-enum-ciphers -p <porta_web> {nmap_target}",
                "curl -sk -m 5 <base>/robots.txt",
                "curl -sk -m 5 <base>/sitemap.xml",
                "curl -sk -m 5 <base>/                    # CMS, header e body analysis",
                "curl -sk -m 3 <base>/<file><estensione_backup>",
                "curl -sk -m 5 <file.js>                  # endpoint e secret extraction",
            ])

        if profile != "fast":
            if profile == "medium":
                directory_wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
                vhost_wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
                wp_enum = "vp,u"
                arjun_limit = 15
                nikto_limit = 30
            else:
                directory_wordlist = "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
                vhost_wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
                wp_enum = "vp,vt,u"
                arjun_limit = 30
                nikto_limit = 60
            if profile == "wordlists" or (
                selected_phase == "all" and profile in {"medium", "full"}
            ):
                # FULL and MEDIUM launch the same standalone wordlist profile;
                # MEDIUM remains reduced only for its main scan pipeline.
                directory_wordlist = "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
                vhost_wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
                wp_enum = "vp,vt,u"
                arjun_limit = 30
                nikto_limit = 60
                web_commands.extend([
                    f"timeout -k 5s 60s wpscan --url <base> --enumerate {wp_enum} --no-banner  # se WordPress",
                    f"feroxbuster -u <base> -w {directory_wordlist} -t 15 -d 2 -k --auto-tune -C 404 [--filter-size <size>]",
                    "  ↳ preferito; ricorsivo; auto-calibra dimensione errore",
                    f"gobuster dir -u <base> -w {directory_wordlist} -t 15 [--exclude-length <size>]  # fallback",
                    f"ffuf -u <base>/ -H 'Host: FUZZ.{shown_target}' -w {vhost_wordlist} -ac -mc 200,302,301,401,403 -t 15 -c -s",
                    "  ↳ auto-calibration; thread ridotti per concorrenza",
                    f"timeout -k 5s {arjun_limit}s arjun -u <base>/ -q -t 10",
                    f"timeout -k 5s {nikto_limit}s nikto -h <base> -nointeractive -maxtime {nikto_limit}s -Tuning 123bde",
                    "  ↳ output con prefisso [tool:porta]",
                    "  ↳ INVIO ferma l'intero gruppo e continua la recon",
                ])
            else:
                web_commands.extend([
                    f"timeout -k 5s 60s wpscan --url <base> --enumerate {wp_enum} --no-banner  # se WordPress",
                    "curl -sk -o /dev/null -w '%{size_download}' -m 2 <base>/slr_cal_<casuale>  # calibrazione",
                    f"gobuster dir -u <base> -w {directory_wordlist} -t 50 [--exclude-length <size>]",
                    "  ↳ nessun limite globale; output live; INVIO ferma e continua",
                    "curl -sk -m 5 -H 'Host: nonexistent.xyz' <base>/  # baseline VHost",
                    f"ffuf -u <base>/ -H 'Host: FUZZ.{shown_target}' -w {vhost_wordlist} -fs <size> -mc 200,302,301,401,403 -t 50 -c -s",
                    "  ↳ nessun limite globale; output live; INVIO ferma e continua",
                    f"timeout -k 5s {arjun_limit}s arjun -u <base>/ -q -t 10",
                    f"timeout -k 5s {nikto_limit}s nikto -h <base> -nointeractive -maxtime {nikto_limit}s -Tuning 123bde",
                ])
        groups.append(("WEB / WORDLIST", web_commands))

    if selected_phase in {"all", "services"} and profile not in {"fast", "wordlists"}:
        kerberos_limit = 60 if profile == "medium" else 120
        service_commands = [
            f"curl -sS -m 10 ftp://{shown_target}/ --user anonymous:anonymous",
            f"timeout -k 5s 60s ssh-audit {shown_target}",
            f"printf 'VRFY root\\n' | nc -w 3 {shown_target} 25",
            f"timeout -k 5s 60s smtp-user-enum -M VRFY -U <names.txt> -t {shown_target}  # se VRFY è attivo",
            f"timeout -k 2s 15s dig @{shown_target} axfr {shown_target}",
            f"timeout -k 5s 60s dnsenum --dnsserver {shown_target} {shown_target} --noreverse",
            f"timeout -k 2s 15s showmount -e {shown_target}",
            f"timeout -k 5s 120s enum4linux-ng -A {shown_target}  # fallback: enum4linux -a",
            f"timeout -k 2s 30s smbmap -H {shown_target} -u '' -p ''",
            f"timeout -k 2s 30s smbclient -L //{shown_target} -N",
            f"timeout -k 2s 20s ldapsearch -x -H ldap://{shown_target} -b '' -s base '(objectclass=*)'",
            f"timeout -k 5s 60s ldapsearch -x -H ldap://{shown_target} -b <baseDN> '(objectclass=person)' cn uid sAMAccountName description",
            f"timeout -k 2s 30s rdp-sec-check {shown_target}",
            f"timeout -k 2s 30s nmap [-Pn] --script rdp-ntlm-info -p 3389 {shown_target}",
            f"timeout -k 2s 8s mysql --connect-timeout=5 -h {shown_target} -u <root|mysql|admin> --password=<vuota|root|mysql|password|toor> -e 'SELECT VERSION();'",
            f"mysql ... -e 'SHOW DATABASES;'                         # dopo login riuscito",
            f"PGPASSWORD=<vuota|postgres|password|admin> timeout -k 2s 8s psql -w -h {shown_target} -U <postgres|admin> -c 'SELECT version();'",
            "psql ... -c '\\l'                                      # dopo login riuscito",
            f"printf 'INFO server\\r\\nQUIT\\r\\n' | nc -w 5 {shown_target} 6379",
            f"printf 'KEYS *\\r\\nQUIT\\r\\n' | nc -w 5 {shown_target} 6379  # se Redis è no-auth",
            f"timeout -k 2s 20s mongosh --host {shown_target} --eval \"db.adminCommand('listDatabases')\" --quiet",
            f"timeout -k 5s 60s onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt {shown_target}",
            f"printf 'public\\nprivate\\ncommunity\\n' | timeout -k 5s 20s onesixtyone -c /dev/stdin {shown_target}  # fallback",
            f"timeout -k 5s 30s snmpwalk -v2c -c <community> {shown_target} 1.3.6.1.2.1.1              # system",
            f"timeout -k 5s 30s snmpwalk -v2c -c <community> {shown_target} 1.3.6.1.2.1.2.2.1.2        # interfacce",
            f"timeout -k 5s 30s snmpwalk -v2c -c <community> {shown_target} 1.3.6.1.2.1.25.4.2.1       # processi",
            f"timeout -k 5s 30s snmpwalk -v2c -c <community> {shown_target} 1.3.6.1.2.1.25.6.3.1.2     # software",
            f"timeout -k 5s 30s snmpwalk -v2c -c <community> {shown_target} 1.3.6.1.4.1.77.1.2.25      # utenti",
            f"timeout -k 5s {kerberos_limit}s kerbrute userenum -d {shown_target} --dc {shown_target} /usr/share/seclists/Usernames/xato-net-10-million-usernames-nt.txt",
            "  ↳ fallback wordlist: /usr/share/seclists/Usernames/Names/names.txt",
        ]
        groups.append(("SERVICE FOLLOW-UP (read-only)", service_commands))

    if selected_phase in {"all", "report", "ports", "web", "services", "wordlists"}:
        report_items = ["Parsing porte TCP/UDP e versioni servizi"]
        if selected_phase == "all" and profile in {"medium", "full"}:
            report_items.append("Attesa del worker wordlist e allegato wordlist_scan.txt")
        report_items.extend([
            "Riepilogo finding, warning, timeout, tool mancanti e copertura incompleta",
            "Timer totale T+hh:mm:ss e suggerimenti successivi",
        ])
        groups.append(("REPORT", report_items))

    print(f"\n  \033[1mRECON {profile.upper()} — contenuto dello scan\033[0m")
    print(f"  Target: \033[96m{shown_target}\033[0m")
    print(f"  Fase:   \033[96m{selected_phase}\033[0m")
    print(f"  Profilo: {summary}")
    print("  Questa modalità è solo informativa: nessun comando viene eseguito.\n")
    for title, commands in groups:
        print(f"  \033[93;1m══ {title} ══\033[0m")
        for command in commands:
            if command.startswith("  "):
                print(f"    \033[2m{command.strip()}\033[0m")
            elif command.startswith(("Parsing", "Attesa", "Riepilogo", "Timer")):
                print(f"    • {command}")
            else:
                print(f"    \033[92m$\033[0m {command}")
        print()


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
            "  \033[93mrecon <target> --no-ping\033[0m    Forza -Pn su nmap\n"
            "  \033[93mrecon medium -i\033[0m            Mostra tutto ciò che include MEDIUM, senza eseguirlo\n"
            "  \033[93mrecon <target> --medium -i\033[0m Mostra i comandi risolti per il target\n"
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
        _print_recon_info(profile, info_target, phase)
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
            for wt in ("wt.exe", "cmd.exe"):
                wt_path = which(wt)
                if wt_path:
                    if wt == "wt.exe":
                        subprocess.Popen(
                            [wt_path, "new-tab", "--title", f"SLRecon: {target}", "wsl.exe", "-e", "sh", "-c", shell_cmd],
                            start_new_session=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                    else:
                        subprocess.Popen(
                            [wt_path, "/c", "wsl.exe", "-e", "sh", "-c", shell_cmd],
                            start_new_session=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                    launched = True
                    break
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
