# WMI — Windows Management Instrumentation
**Porte:** 135 (TCP)  
**Categoria:** Accesso Remoto

Insieme di strumenti per gestire qualsiasi impostazione di Windows da remoto:
RAM, processi, software installati, configurazioni, servizi.
Porta TCP 135. Usa wmiexec.py di Impacket per connettersi da Linux.
Spesso non monitorato dai sistemi di difesa → attività difficile da rilevare.

## Vulnerabilità comuni

- Credenziali admin — controllo totale del sistema Windows
- Esecuzione comandi remoti — RCE immediata con qualsiasi utente privilegiato
- Spesso non monitorato da IDS/SIEM — attività invisibile nei log standard

## Enumerazione & Comandi

### CONNESSIONE CON IMPACKET

```bash
python3 wmiexec.py user:'password'@<IP> 'hostname'    # Esegui comando remoto
python3 wmiexec.py user:'password'@<IP> 'whoami'      # Chi sono sul target?
python3 wmiexec.py user:'password'@<IP> 'ipconfig /all'  # Configurazione rete completa
```

### CON NETEXEC

```bash
nxc smb <IP> -u 'user' -p 'password' -x 'whoami'     # Esecuzione via SMB/WMI
```

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **impacket**
- **crackmapexec**
