# RDP — Remote Desktop Protocol
**Porte:** 3389 (TCP)  
**Categoria:** Accesso Remoto

Protocollo Microsoft per il controllo remoto del desktop (GUI completa).
Dati cifrati ma spesso con certificati autofirmati → il PC non può verificare
se si sta connettendo al server giusto o a un impostore (MitM possibile).

## Vulnerabilità comuni

- BlueKeep (CVE-2019-0708) — RCE pre-auth su vecchi Windows (XP, 7, Server 2008)
- Certificati autofirmati — MitM attack (intercettazione desktop remoto)
- NLA disabilitato — attacchi brute force facilitati (nessun pre-auth)
- Credenziali deboli — brute force con hydra/nxc
- Session hijacking — furto sessioni RDP attive

## Enumerazione & Comandi

### SCAN

```bash
nmap -sV -sC -p3389 --script rdp* <IP>               # Scan + script RDP
nmap -sV -sC -p3389 --packet-trace --disable-arp-ping -n <IP>  # Dettagliato
```

### VERIFICA SICUREZZA

```bash
./rdp-sec-check.pl <IP>                               # Check cifrari, NLA, auth level
```

### VERIFICA CREDENZIALI

```bash
nxc rdp <IP> -u 'admin' -p 'password'                 # Singolo tentativo
nxc rdp <SUBNET>/24 -u users.txt -p 'Password123!'   # Password spraying su rete
```

### CONNESSIONE

```bash
xfreerdp /u:user /p:'password' /v:<IP> /cert:ignore /dynamic-resolution +clipboard
# Opzioni utili: /drive:share,/tmp (monta cartella locale) /sec:tls (forza TLS)
```

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **nmap**
- **rdp-sec-check**
- **netexec**
- **hydra**
- **xfreerdp**
