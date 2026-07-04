# SecLists

## Cos'e SecLists

SecLists e una raccolta di wordlist per security testing (fuzzing, brute force, credential testing, DNS discovery, ecc.).
E mantenuto da Daniel Miessler su GitHub: https://github.com/danielmiessler/SecLists

## Percorso di installazione

I file vengono installati in:

```
/usr/share/seclists/
```

## Categorie principali

| Categoria | Descrizione |
|---|---|
| `Discovery/DNS/` | Wordlist per subdomain brute force (es. `subdomains-top1million-110000.txt`) |
| `Discovery/Web-Content/` | Directory e file comuni per fuzzing web |
| `Passwords/` | Wordlist di password (include `rockyou.txt`) |
| `Usernames/` | Liste di username comuni |
| `Discovery/SNMP/` | Community string per SNMP brute force |
| `Fuzzing/` | Payload per fuzzing generico |
| `Miscellaneous/` | Varie (user-agents, wordlist IDOR, ecc.) |

## Esempi di utilizzo con tool di slconsole

### Fuzzing di directory web con gobuster

```bash
gobuster dir -u http://target -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

### Enumerazione DNS con dnsenum

```bash
dnsenum --dnsserver <IP> --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt <dominio>
```

### Brute force SNMP con onesixtyone

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>
```

### Cracking password con john

```bash
john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hash.txt
```

### Enumerazione virtual host con gobuster

```bash
gobuster vhost -u http://target -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

## rockyou.txt su Kali

Su Kali Linux, `rockyou.txt` e disponibile anche in:

```
/usr/share/wordlists/rockyou.txt
```

Potrebbe essere compresso (`.gz`). Per decomprimerlo:

```bash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```
