# ffuf — Fast Web Fuzzer

**ffuf** (Fuzz Faster U Fool) è un web fuzzer veloce scritto in Go. Rispetto a gobuster è più flessibile: supporta fuzzing su qualsiasi parte della richiesta (URL, header, body, cookie), filtri avanzati e output strutturato.

---

## A cosa serve?

- **Directory / file fuzzing** — trova path nascosti
- **Virtual Host discovery** — scopri vhost con header Host
- **Parameter fuzzing** — enumera parametri GET/POST
- **Subdomain fuzzing** — scopri sottodomini
- **API fuzzing** — scopri endpoint REST/GraphQL

---

## Come usarlo

### Directory fuzzing

```bash
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -c
```

### Con estensioni

```bash
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .php,.txt,.bak -c
```

### Subdomain fuzzing

```bash
ffuf -u http://FUZZ.target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -c
```

### Virtual Host fuzzing

```bash
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -c -fs 0
```

### Parameter fuzzing (GET)

```bash
ffuf -u "http://target.com/page?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -c -fs 0
```

### Parameter fuzzing (POST)

```bash
ffuf -u http://target.com/login -X POST -d "user=admin&FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -c -fs 0
```

### Password bruteforce

```bash
ffuf -u http://target.com/login -X POST -d "user=admin&pass=FUZZ" -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt -fc 401,403 -c
```

### API endpoint fuzzing

```bash
ffuf -u http://target.com/api/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt -c -mc all -fc 404
```

---

## Filtri e match

| Flag | Descrizione |
|------|-------------|
| `-mc 200,301` | Mostra solo questi status code (match) |
| `-fc 404,403` | Nascondi questi status code (filter) |
| `-fs 0` | Nascondi risposte di questa dimensione |
| `-fw 12` | Nascondi risposte con N parole |
| `-fl 5` | Nascondi risposte con N righe |
| `-mc all -fc 404` | Mostra tutto tranne 404 |
| `-fr "Not Found"` | Filtra per regex nel body |

---

## Opzioni utili

| Flag | Descrizione |
|------|-------------|
| `-c` | Output colorato |
| `-t 50` | Numero di thread (default 40) |
| `-p 0.1` | Delay tra richieste (secondi) |
| `-r` | Segui redirect |
| `-recursion -recursion-depth 2` | Fuzzing ricorsivo |
| `-o output.json -of json` | Salva output in formato JSON |
| `-H "Cookie: session=abc"` | Header custom |
| `-X POST` | Metodo HTTP |
| `-d "key=value"` | POST data |
| `-x http://127.0.0.1:8080` | Proxy (es. Burp Suite) |
| `-k` | Ignora errori certificati SSL |
| `-ic` | Ignora commenti nella wordlist |

---

## Multi-keyword (due wordlist contemporaneamente)

```bash
ffuf -u http://target.com/FUZZ1/FUZZ2 \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ1 \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ2 \
  -c -mc 200
```

---

## Differenze con gobuster

| | ffuf | gobuster |
|---|---|---|
| Fuzzing posizione | Ovunque (URL, header, body, cookie) | Principalmente URL |
| Filtri | Match + filter su size/words/lines/regex | Solo status code |
| Multi-keyword | Sì (FUZZ1, FUZZ2, ...) | No |
| Ricorsione | Sì | No |
| Output | JSON, CSV, HTML, eJSON | Testo |
| Velocità | Comparabile | Comparabile |

> Fonte: https://github.com/ffuf/ffuf
