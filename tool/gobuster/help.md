# Gobuster — Directory/VHost/DNS Fuzzer

**Gobuster** è un tool veloce per il fuzzing di directory, sottodomini DNS e Virtual Host. Scritto in Go, è molto performante.

---

## A cosa serve?

- **Directory Fuzzing:** Trova cartelle e file nascosti su web server
- **VHost Fuzzing:** Scopre Virtual Host nascosti
- **DNS Fuzzing:** Enumera sottodomini

---

## Come usarlo

### Directory fuzzing

```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
```

### VHost fuzzing

```bash
gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

### DNS subdomain fuzzing

```bash
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Opzioni utili

- `-t 50` — Numero di thread (più veloce)
- `-k` — Ignora errori certificati SSL
- `-o risultati.txt` — Salva output in file
- `-x php,html,txt` — Cerca file con queste estensioni

> Fonte: https://github.com/OJ/gobuster
