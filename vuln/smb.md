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

## Enumerazione & Comandi

### ELENCO SHARE

```bash
smbclient -N -L //<IP>                               # Elenca share (null session, senza password)
smbclient //<IP>/<share>                              # Accedi a una share specifica
  > !cat flag.txt                                    # '!' esegue comandi sul TUO PC senza uscire
smbmap -H <IP>                                       # Mappa permessi READ/WRITE su ogni share
smbmap -H <IP> -u 'user' -p 'pass'                   # Con credenziali specifiche
```

### ENUMERAZIONE RPC (rpcclient)

```bash
rpcclient -U '' <IP>                                  # Sessione RPC anonima
  > srvinfo                                          # Info server (nome, versione OS)
  > enumdomains                                      # Elenca tutti i domini nella rete
  > querydominfo                                     # Info dominio, server e utenti
  > enumdomusers                                     # Lista utenti dominio con RID
  > netshareenumall                                   # Lista tutte le share (anche nascoste)
  > netsharegetinfo <share>                          # Dettagli su una share specifica
  > queryuser <RID>                                  # Info su utente specifico (per RID)
  > querygroup <RID>                                 # Info su gruppo specifico
```

### BRUTE FORCE RID (se enum bloccata)

```bash
for i in $(seq 500 1100);do rpcclient -N -U '' <IP> -c "queryuser 0x$(printf '%x\n' $i)" | grep 'User Name' && echo '';done
samrdump.py <IP>                                      # Alternativa Python (Impacket)
```

### TOOL AUTOMATICI

```bash
nxc smb <IP> --shares -u '' -p ''                    # NetExec: enum share anonime
nxc smb <IP> -u 'admin' -p 'pass' --sam             # Dump hash SAM (con admin)
nxc smb <SUBNET>/24 -u users.txt -p 'Password123!'  # Password spraying su subnet
nxc smb <IP> -u 'admin' -p 'pass' -x 'whoami'       # Esecuzione comandi remoti
enum4linux-ng.py <IP> -A                             # Enumerazione completa (porte, utenti, gruppi, share, policy password)
sudo nmap -sV -sC -p139,445 <IP>                    # Nmap SMB scan
```

### MONITORAGGIO (lato admin)

```bash
smbstatus                                             # Chi è connesso, versione protocollo, file lockati
```

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **nmap**
- **enum4linux-ng**
- **smbmap**
- **netexec**
- **hydra**
- **impacket**
