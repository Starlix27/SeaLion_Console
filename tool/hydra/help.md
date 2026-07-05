# Hydra — Network Login Brute-Forcer

**Hydra** è il tool di riferimento per attacchi brute force e password spraying su protocolli di rete. Supporta oltre 50 protocolli tra cui SSH, RDP, SMB, FTP, HTTP, IMAP, POP3, MSSQL e molti altri.

---

## A cosa serve?

- **Brute force credenziali:** Testa combinazioni utente/password su servizi di rete
- **Password spraying:** Una password contro molti utenti (o viceversa)
- **Multi-protocollo:** SSH, RDP, SMB, FTP, HTTP-Form, IMAP, POP3, MSSQL, VNC, Telnet...

---

## Come usarlo

### Sintassi base

```bash
hydra -L <user_list> -P <password_list> <protocollo>://<IP>
```

### Brute force SSH

```bash
hydra -L user.list -P password.list ssh://10.129.42.197
```

### Brute force RDP

```bash
hydra -L user.list -P password.list rdp://10.129.42.197
```

### Brute force SMB

```bash
hydra -L user.list -P password.list smb://10.129.42.197
```

### Brute force FTP

```bash
hydra -L user.list -P password.list ftp://10.129.42.197
```

### Singolo utente con wordlist password

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.129.42.197
```

### Opzioni utili

```bash
hydra -t 4 ...        # Limita a 4 thread paralleli (evita lockout)
hydra -V ...           # Mostra ogni tentativo (verbose)
hydra -f ...           # Ferma al primo login trovato
hydra -o results.txt   # Salva risultati su file
```

> **Nota:** Le vecchie versioni di Hydra possono dare errori `invalid reply` su SMBv3 (Windows moderni). Aggiorna sempre all'ultima versione o usa NetExec/Metasploit come alternativa.

> Fonte: https://github.com/vanhauser-thc/thc-hydra
