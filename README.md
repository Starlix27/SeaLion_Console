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
                              =%%#%@@%*@*                   .%%%#*+=--..
                           .#%@%######@+
                        -*#######%@%:
                    =###%%%+.
```

**Personal tool vault per pentester.** Console interattiva per gestire, installare e consultare tool di sicurezza offensiva e cheatsheet per protocolli vulnerabili.

---

## Installazione

```bash
git clone https://github.com/Starlix27/sealion.git
cd sealion
bash setup.sh
```

`setup.sh` crea il comando `slconsole` in `~/.local/bin/` e aggiorna il PATH automaticamente. Nessuna dipendenza esterna richiesta (Python 3.10+).

Per applicare subito senza riaprire il terminale:

```bash
source ~/.bashrc
```

## Utilizzo

```bash
slconsole              # Avvia la console interattiva
slconsole list         # Elenca i tool disponibili
slconsole search <q>   # Cerca tool per nome o descrizione
slconsole vuln smb     # Cheatsheet vulnerabilità SMB
slconsole vuln list    # Elenca tutti i protocolli
slconsole --version    # Versione
```

### Console interattiva

```
slconsole> list                   # Mostra tutti i tool
slconsole> search scanner         # Ricerca full-text (anche multi-parola)
slconsole> use nmap               # Seleziona un tool
slconsole(nmap)> install          # Installa il tool selezionato
slconsole> vuln ftp               # Vulnerabilità, comandi, tool per FTP
slconsole> back                   # Torna alla console principale
slconsole> exit                   # Esci
```

## Tool inclusi

| Tool | Descrizione |
|------|-------------|
| **braa** | Scanner SNMP massivo |
| **cewl** | Generatore di wordlist da siti web |
| **crackmapexec** | Network exploitation suite (NetExec) |
| **dnsenum** | Enumerazione DNS |
| **enum4linux-ng** | Enumerazione SMB/RPC |
| **evil-winrm** | Shell WinRM per pentesting |
| **finalrecon** | Web reconnaissance |
| **gobuster** | Directory/DNS/VHost fuzzer |
| **hashcat** | Password recovery con GPU |
| **hashid** | Identificatore di hash |
| **impacket** | Libreria protocolli di rete Python |
| **john** | John the Ripper — password cracker |
| **nikto** | Web server scanner |
| **nmap** | Network scanner |
| **odat** | Oracle Database Attacking Tool |
| **onesixtyone** | Scanner community string SNMP |
| **rdp-sec-check** | Verifica sicurezza RDP |
| **recon-ng** | Framework di web reconnaissance |
| **scrapy** | Framework di web crawling |
| **shodan** | Motore di ricerca per dispositivi IoT |
| **smbmap** | Mappa permessi share SMB |
| **ssh-audit** | Audit configurazione SSH |
| **theHarvester** | OSINT gathering (email, sottodomini) |
| **wafw00f** | Rilevamento WAF |
| **whois** | Lookup informazioni dominio |

## Protocolli vulnerabili (`vuln`)

Il comando `vuln <protocollo>` mostra per ogni protocollo: descrizione, porte, vulnerabilità comuni, comandi di enumerazione e tool consigliati.

| Protocollo | Porte | Alias |
|------------|-------|-------|
| `ftp` | 21 | ftps, tftp |
| `smb` | 445, 137-139 | samba, cifs, netbios, rpc |
| `nfs` | 2049, 111 | nfsd, portmapper |
| `dns` | 53 | bind, bind9, dig, nslookup |
| `smtp` | 25, 587, 465 | postfix, sendmail |
| `imap-pop3` | 143, 110, 993, 995 | imap, pop3, dovecot |
| `snmp` | 161/UDP | — |
| `mysql` | 3306 | mariadb |
| `mssql` | 1433 | sqlserver |
| `oracle-tns` | 1521 | oracle, tns |
| `ipmi` | 623/UDP | idrac, ilo, bmc |
| `ssh` | 22 | openssh, sshd |
| `rdp` | 3389 | mstsc, xfreerdp |
| `winrm` | 5985, 5986 | — |
| `wmi` | 135 | — |

## Aggiungere un tool

Crea una sottocartella con due file:

```
mio-tool/
├── help.md        # Documentazione in Markdown
└── install.py     # Script di installazione
```

`install.py` deve esporre:

```python
import subprocess

ENTRY_POINT = "{dest}/mio-tool"  # Comando per il launcher

def install(dest):
    subprocess.check_call(["apt", "install", "-y", "mio-tool"])
    return 0
```

Il tool apparirà automaticamente in `slconsole list`.

## Struttura del progetto

```
sealion/
├── sealion.py          # Codice principale
├── setup.sh            # Installer automatico
├── pyproject.toml      # Metadata pacchetto (per pip install -e .)
├── ascii-art.txt       # Logo ASCII
├── nmap/               # Tool: help.md + install.py
├── nikto/
├── ...                 # Altri 23 tool
└── README.md
```

## Requisiti

- Python 3.10+
- Linux (WSL supportato)
- `rich` (opzionale, per rendering Markdown migliorato): `pip install rich`


