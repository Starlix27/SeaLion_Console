# Medusa — Parallel Network Login Auditor

**Medusa** è un login bruter parallelo per servizi di rete. Supporta molti protocolli e permette combinazioni flessibili di utenti, password e host.

---

## A cosa serve?

- **Bruteforce credenziali** su servizi di rete
- **Audit parallelo** — testa più host, utenti e password contemporaneamente
- **Supporto modulare** — ogni protocollo è un modulo separato

---

## Come usarlo

### Bruteforce SSH

```bash
medusa -h 10.10.11.42 -u admin -P /usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt -M ssh -t 4
```

### Bruteforce FTP

```bash
medusa -h 10.10.11.42 -u admin -P passwords.txt -M ftp -t 4
```

### Bruteforce HTTP form

```bash
medusa -h 10.10.11.42 -u admin -P passwords.txt -M http -m DIR:/login
```

### Bruteforce SMB

```bash
medusa -h 10.10.11.42 -u administrator -P passwords.txt -M smbnt
```

### Multi-host

```bash
medusa -H hosts.txt -U users.txt -P passwords.txt -M ssh -t 4
```

### Multi-utente con un host

```bash
medusa -h 10.10.11.42 -U users.txt -P passwords.txt -M ssh -t 4
```

---

## Moduli disponibili

| Modulo | Servizio |
|--------|----------|
| `ssh` | SSH |
| `ftp` | FTP |
| `telnet` | Telnet |
| `http` | HTTP Basic/Digest |
| `smbnt` | SMB/CIFS |
| `mysql` | MySQL |
| `mssql` | MSSQL |
| `postgres` | PostgreSQL |
| `vnc` | VNC |
| `pop3` | POP3 |
| `imap` | IMAP |
| `smtp-vrfy` | SMTP VRFY |
| `rlogin` | rlogin |
| `rdp` | RDP |
| `svn` | SVN |

Per vedere tutti: `medusa -d`

---

## Opzioni utili

| Flag | Descrizione |
|------|-------------|
| `-h host` | Host target |
| `-H hosts.txt` | File con lista host |
| `-u user` | Username singolo |
| `-U users.txt` | File con lista utenti |
| `-p pass` | Password singola |
| `-P passwords.txt` | Wordlist password |
| `-M modulo` | Modulo da usare (ssh, ftp, ecc.) |
| `-m PARAM:val` | Parametro per il modulo |
| `-t 4` | Thread per host |
| `-T 8` | Thread totali |
| `-f` | Fermati al primo successo per host |
| `-F` | Fermati al primo successo globale |
| `-O output.txt` | File di output |
| `-e ns` | Prova password vuota (n) e user=pass (s) |
| `-v 4` | Verbosity (0-6) |

---

## Differenze con Hydra

| | medusa | hydra |
|---|---|---|
| Architettura | Modulare (moduli .so) | Monolitica |
| Multi-host | Nativo (`-H`) | Sì ma meno flessibile |
| Protocolli | ~20 | ~50 |
| Velocità | Veloce | Veloce |
| Combo file | No | Sì (`-C user:pass`) |

> Fonte: https://github.com/jmk-foofus/medusa
