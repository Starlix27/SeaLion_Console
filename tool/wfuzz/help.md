# Wfuzz — Web Application Fuzzer

**Wfuzz** è un web fuzzer scritto in Python. Estremamente flessibile, permette di fuzzare qualsiasi parte di una richiesta HTTP (URL, header, body, cookie, metodo).

---

## A cosa serve?

- **Directory / file discovery**
- **Parameter fuzzing** (GET/POST)
- **Subdomain / VHost discovery**
- **Bruteforce login**
- **Fuzzing avanzato** — qualsiasi punto della richiesta

---

## Come usarlo

### Directory fuzzing

```bash
wfuzz -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404
```

### Con estensioni

```bash
wfuzz -u http://target.com/FUZZ.FUZ2Z -w /usr/share/seclists/Discovery/Web-Content/common.txt -z list,php-txt-bak --hc 404
```

### Subdomain fuzzing

```bash
wfuzz -u http://FUZZ.target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hc 404 -t 50
```

### VHost fuzzing

```bash
wfuzz -u http://target.com -H "Host: FUZZ.target.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hc 404
```

### Parameter fuzzing (GET)

```bash
wfuzz -u "http://target.com/page?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --hc 404
```

### Parameter fuzzing (POST)

```bash
wfuzz -u http://target.com/login -d "user=admin&pass=FUZZ" -w /usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt --hc 401,403
```

### Bruteforce login

```bash
wfuzz -u http://target.com/login -d "user=FUZZ&pass=FUZ2Z" \
  -w users.txt -w passwords.txt --hc 401,403 -t 20
```

---

## Filtri (hide / show)

| Flag | Tipo | Descrizione |
|------|------|-------------|
| `--hc 404` | Hide | Nascondi status code |
| `--hl 10` | Hide | Nascondi risposte con N righe |
| `--hw 50` | Hide | Nascondi risposte con N parole |
| `--hh 1234` | Hide | Nascondi risposte con N byte |
| `--sc 200` | Show | Mostra solo status code |
| `--sl 10` | Show | Mostra solo risposte con N righe |
| `--sw 50` | Show | Mostra solo risposte con N parole |
| `--sh 1234` | Show | Mostra solo risposte con N byte |
| `--ss "pattern"` | Show | Mostra risposte che contengono la stringa |
| `--hs "pattern"` | Hide | Nascondi risposte che contengono la stringa |

---

## Opzioni utili

| Flag | Descrizione |
|------|-------------|
| `-u URL` | URL target (con FUZZ come placeholder) |
| `-w wordlist` | Wordlist (ripetibile per multi-keyword) |
| `-d "data"` | POST data |
| `-H "Header: value"` | Header custom |
| `-b "cookie=value"` | Cookie |
| `-t 50` | Thread |
| `-s 0.5` | Delay tra richieste (secondi) |
| `-p 127.0.0.1:8080` | Proxy |
| `-R 2` | Ricorsione (profondità) |
| `-o output.json` | Output file |
| `-f json` | Formato output |
| `-z file,wordlist` | Payload source alternativa |
| `-z range,1-100` | Range numerico come payload |

---

## Multi-keyword (FUZZ, FUZ2Z, FUZ3Z, ...)

```bash
# User e password contemporaneamente
wfuzz -u http://target.com/login -d "user=FUZZ&pass=FUZ2Z" \
  -w users.txt -w passwords.txt --hc 403

# Directory + estensione
wfuzz -u http://target.com/FUZZ.FUZ2Z \
  -w dirs.txt -z list,php-txt-html --hc 404
```

---

## Differenze con ffuf

| | wfuzz | ffuf |
|---|---|---|
| Linguaggio | Python | Go |
| Multi-keyword | FUZZ, FUZ2Z, FUZ3Z | FUZZ, FUZZ2 (o custom) |
| Payload types | file, list, range, hex, ecc. | Solo file |
| Velocità | Buona | Molto veloce |
| Ricorsione | Sì | Sì |
| Filtri regex | Sì | Sì |

> Fonte: https://github.com/xmendez/wfuzz
