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

`setup.sh` crea il comando `slconsole` in `~/.local/bin/` e aggiorna il PATH automaticamente.

Per applicare subito senza riaprire il terminale:

```bash
source ~/.bashrc
```

**Requisiti:** Python 3.10+, Linux (WSL supportato). `rich` opzionale per rendering Markdown migliorato (`pip install rich`).

---

## Utilizzo

```bash
slconsole              # Avvia la console interattiva
slconsole list         # Elenca i tool disponibili
slconsole search <q>   # Cerca tool per nome o descrizione
slconsole vuln smb     # Cheatsheet vulnerabilità SMB
slconsole vuln list    # Elenca tutti i protocolli per categoria
slconsole vuln *       # Uguale a vuln list
slconsole --version    # Versione
```

### Console interattiva

```
slconsole> list                   # Mostra tutti i tool
slconsole> search scanner         # Ricerca full-text (anche multi-parola)
slconsole> use nmap               # Seleziona un tool
slconsole(nmap)> install          # Installa il tool selezionato
slconsole> vuln ftp               # Vulnerabilità, comandi, tool per FTP
slconsole> vuln list              # Elenca protocolli per categoria
slconsole> back                   # Torna alla console principale
slconsole> exit                   # Esci
```

---

## Tool inclusi

### Ricognizione & OSINT

| Tool | Descrizione |
|------|-------------|
| **nmap** | Network scanner — scansione porte, servizi, OS detection, script NSE |
| **shodan** | Motore di ricerca per dispositivi esposti su Internet (server, webcam, IoT) |
| **theHarvester** | OSINT gathering — raccoglie email, sottodomini, IP da fonti pubbliche |
| **recon-ng** | Framework modulare di web reconnaissance (come Metasploit per l'OSINT) |
| **finalrecon** | Web reconnaissance automatizzata (header, whois, DNS, crawler) |
| **whois** | Lookup informazioni di registrazione dominio (proprietario, date, nameserver) |

### DNS & Web Fuzzing

| Tool | Descrizione |
|------|-------------|
| **dnsenum** | Enumerazione DNS automatica: zone transfer, brute force sottodomini, reverse lookup |
| **gobuster** | Directory/DNS/VHost fuzzer — brute force di percorsi web, sottodomini e virtual host |
| **nikto** | Web server scanner — trova vulnerabilità note, file di default, misconfigurazioni |
| **scrapy** | Framework Python di web crawling e scraping |

### Enumerazione Servizi

| Tool | Descrizione |
|------|-------------|
| **enum4linux-ng** | Enumerazione SMB/RPC completa: utenti, gruppi, share, policy password |
| **smbmap** | Mappa permessi READ/WRITE sulle share SMB di un target |
| **crackmapexec** | Network exploitation suite (NetExec) — multi-protocollo (SMB, RDP, WinRM, SSH, MSSQL) |
| **onesixtyone** | Brute force community string SNMP con wordlist |
| **braa** | Scanner SNMP massivo e parallelo — estrae OID molto più veloce di snmpwalk |
| **ssh-audit** | Audit configurazione SSH (cifrari, KEX, chiavi host, vulnerabilità) |
| **rdp-sec-check** | Verifica impostazioni di sicurezza server RDP (NLA, cifrari, auth level) |

### Accesso Remoto & Post-Exploitation

| Tool | Descrizione |
|------|-------------|
| **evil-winrm** | Shell WinRM interattiva per pentesting — supporta Pass-the-Hash |
| **impacket** | Libreria Python per protocolli di rete (wmiexec, mssqlclient, samrdump, secretsdump) |
| **odat** | Oracle Database Attacking Tool — enumerazione, brute force SID, upload file |

### Password Cracking & Wordlist

| Tool | Descrizione |
|------|-------------|
| **john** | John the Ripper — password cracker multi-formato (single, wordlist, incremental mode) |
| **hashcat** | Password recovery con GPU — supporta centinaia di formati hash |
| **hashid** | Identificatore automatico di hash — riconosce il tipo (MD5, SHA, NTLM, ecc.) |
| **cewl** | Generatore di wordlist personalizzate da siti web (crawl + estrazione parole) |
| **seclists** | Raccolta di wordlist per fuzzing, brute force, DNS discovery e password cracking |

### Web Application

| Tool | Descrizione |
|------|-------------|
| **wafw00f** | Rilevamento Web Application Firewall (identifica il WAF che protegge un sito) |

---

## SecLists

SecLists è la raccolta di wordlist più usata nel pentesting. Si installa con:

```
slconsole> use seclists
slconsole(seclists)> install
```

Una volta installata in `/usr/share/seclists/`, le wordlist principali sono:

| Percorso | Uso |
|----------|-----|
| `Discovery/DNS/subdomains-top1million-110000.txt` | Brute force sottodomini con dnsenum/gobuster |
| `Discovery/Web-Content/directory-list-2.3-medium.txt` | Fuzzing directory web con gobuster |
| `Discovery/SNMP/snmp.txt` | Brute force community string con onesixtyone |
| `Passwords/Leaked-Databases/rockyou.txt` | Cracking password con john/hashcat |
| `Usernames/` | Liste username comuni |
| `Fuzzing/` | Payload per fuzzing generico |

### Esempi di utilizzo

```bash
# Brute force directory web
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Brute force sottodomini
dnsenum --dnsserver <IP> --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt <dominio>

# VHost fuzzing (trova virtual host nascosti)
gobuster vhost -u http://<target> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain

# Brute force community string SNMP
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>

# Crack password con John
john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hash.txt
```

Su Kali/Parrot `rockyou.txt` è anche in `/usr/share/wordlists/rockyou.txt`.

---

## Protocolli vulnerabili (`vuln`)

Il comando `vuln <protocollo>` mostra per ogni protocollo: descrizione dettagliata, file di configurazione, vulnerabilità comuni, comandi di enumerazione passo-passo e tool consigliati.

### Trasferimento File

| Protocollo | Porte | Alias | Cosa cercare |
|------------|-------|-------|--------------|
| `ftp` | 21, 20 | ftps, tftp, vsftpd | Login anonimo, upload abilitato, credenziali in chiaro |
| `smb` | 445, 137-139 | samba, cifs, rpc | Null session, share scrivibili, EternalBlue, enum utenti RPC |
| `nfs` | 2049, 111 | nfsd, portmapper | no_root_squash, export aperti, UID mismatch |

### DNS & Ricognizione

| Protocollo | Porte | Alias | Cosa cercare |
|------------|-------|-------|--------------|
| `dns` | 53 | bind, bind9, dig | Zone transfer AXFR, recursion aperta, sottodomini nascosti |

### Email

| Protocollo | Porte | Alias | Cosa cercare |
|------------|-------|-------|--------------|
| `smtp` | 25, 587, 465 | postfix, sendmail | Open relay, VRFY/EXPN abilitati, mancanza SPF/DKIM |
| `imap-pop3` | 143, 110, 993, 995 | imap, pop3, dovecot | Password nei log, auth anonima, chiavi SSH nelle email |

### Monitoraggio Rete

| Protocollo | Porte | Alias | Cosa cercare |
|------------|-------|-------|--------------|
| `snmp` | 161/UDP, 162/UDP | — | Community string di default (public), rwuser noauth, info esposte |

### Database

| Protocollo | Porte | Alias | Cosa cercare |
|------------|-------|-------|--------------|
| `mysql` | 3306 | mariadb | Root senza password, debug attivo, secure_file_priv aperto |
| `mssql` | 1433 | sqlserver | sa con password debole, xp_cmdshell, auth Windows rubata |
| `oracle-tns` | 1521 | oracle, tns | SID brute force, credenziali default (scott/tiger), upload file con utlfile |

### Accesso Remoto

| Protocollo | Porte | Alias | Cosa cercare |
|------------|-------|-------|--------------|
| `ssh` | 22 | openssh, sshd | PermitRootLogin, password vuote, chiavi private esposte, Protocol 1 |
| `rdp` | 3389 | mstsc, xfreerdp | BlueKeep, certificati autofirmati, NLA disabilitato |
| `winrm` | 5985, 5986 | — | Pass-the-Hash, HTTP in chiaro (5985), PowerShell completo |
| `wmi` | 135 | — | RCE con credenziali admin, non monitorato da IDS |

### Hardware & Management

| Protocollo | Porte | Alias | Cosa cercare |
|------------|-------|-------|--------------|
| `ipmi` | 623/UDP | idrac, ilo, bmc | Password default (Dell: root/calvin), hash RAKP estraibili senza auth |

---

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
from pathlib import Path

ENTRY_POINT = "{dest}/mio-tool"  # Template per il launcher

def install(dest):
    subprocess.check_call(["apt", "install", "-y", "mio-tool"])
    return 0

if __name__ == "__main__":
    install(Path.cwd())
```

Il tool apparirà automaticamente in `slconsole list`.

---

## Struttura del progetto

```
sealion/
├── sealion.py          # Codice principale (console + vuln DB)
├── setup.sh            # Installer automatico (crea comando slconsole)
├── pyproject.toml      # Metadata pacchetto
├── ascii-art.txt       # Logo ASCII
├── README.md
│
├── nmap/               # Ogni tool ha la sua cartella:
│   ├── help.md         #   documentazione
│   └── install.py      #   script di installazione
├── seclists/
├── enum4linux-ng/
├── ...                 # 26 tool totali
```

