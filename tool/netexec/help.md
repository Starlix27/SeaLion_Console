# NetExec (NXC) — Network Exploitation & Auditing Framework

**NetExec** (noto anche come NXC) è un potente strumento open-source di network exploitation e auditing, progettato per automatizzare la valutazione della sicurezza delle reti, con un'enfasi particolare sugli ambienti Active Directory. È l'evoluzione attiva del popolare strumento CrackMapExec.

> Quel **`(Pwn3d!)`** nell'output indica che l'utente ha i privilegi di amministrazione locale sul server — hai il controllo totale della macchina.

---

## Sintassi base

```bash
nxc <protocollo> <IP_target_o_subnet> -u <utente> -p <password>
```

---

## Come usarlo

### Enumerazione rete SMB

Mappa la rete ed estrae informazioni dettagliate su utenti, gruppi, policy delle password, condivisioni di rete e servizi esposti.

```bash
nxc smb 192.168.1.0/24
```

### Verifica credenziali (Password Spraying)

Testa la validità delle password su larga scala o individua accessi non autorizzati sfruttando vari protocolli (SMB, LDAP, RDP, WinRM).

```bash
nxc smb 192.168.1.0/24 -u utenti.txt -p 'Password123!'
```

### Controllo permessi delle share

```bash
nxc smb 192.168.1.50 -u 'admin' -p 'password' --shares
```

### Esecuzione comandi remoti

```bash
nxc smb 192.168.1.50 -u 'admin' -p 'password' -x 'whoami'
```

### Estrazione hash SAM (Credential Dumping)

```bash
nxc smb 192.168.1.50 -u 'admin' -p 'password' --sam
```

---

## Altri protocolli utili

NetExec supporta molti altri vettori di attacco e verifica.

### RDP — Verifica accesso Desktop Remoto

```bash
nxc rdp 192.168.1.0/24 -u 'admin' -p 'password'
```

### WinRM — Esecuzione comandi via Windows Remote Management

```bash
nxc winrm 192.168.1.50 -u 'admin' -p 'password' -x 'hostname'
```

### SSH — Verifica accessi su macchine Linux

```bash
nxc ssh 192.168.1.0/24 -u 'root' -p 'password'
```

### MSSQL — Audit di database Microsoft SQL

```bash
nxc mssql 192.168.1.20 -u 'sa' -p 'password' --q 'SELECT @@version;'
```

---

## Funzionalità principali

- **Enumerazione rete:** Mappa host, utenti, gruppi, share e servizi
- **Password Spraying:** Testa credenziali su larga scala con più protocolli
- **Post-sfruttamento e movimento laterale:** Esecuzione comandi remoti, credential dumping, sfruttamento configurazioni errate
- **Multi-protocollo:** SMB, RDP, WinRM, SSH, MSSQL, LDAP, FTP, VNC e altri

> Fonte: https://github.com/Pennyw0rth/NetExec
