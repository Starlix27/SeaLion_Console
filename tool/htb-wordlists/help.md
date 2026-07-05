# HTB Wordlists — Wordlist personalizzate per HackTheBox

Raccolta di wordlist ottimizzate per i laboratori e le macchine di **HackTheBox**, incluse liste di utenti e password comuni negli scenari HTB.

---

## A cosa serve?

- **Brute force:** Liste utenti e password mirate per ambienti HTB
- **Password spraying:** Combinazioni utente/password frequenti nei lab
- **Complemento a SecLists:** Wordlist più specifiche per CTF e lab HTB

---

## Come usarlo

### Con Hydra (SSH)

```bash
hydra -L user.list -P password.list ssh://10.129.42.197
```

### Con Hydra (RDP)

```bash
hydra -L user.list -P password.list rdp://10.129.42.197
```

### Con NetExec (WinRM)

```bash
nxc winrm 10.129.42.197 -u user.list -p password.list
```

### Con NetExec (SMB)

```bash
nxc smb 10.129.42.197 -u user.list -p password.list
```

### Con John the Ripper

```bash
john --wordlist=password.list hash.txt
```

---

## Percorso dopo installazione

```
~/.sealionconsole/tools/htb-wordlists/
```

> Fonte: https://file.ax/d/admkbkg6
