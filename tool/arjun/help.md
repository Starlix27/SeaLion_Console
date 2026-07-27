# Arjun — HTTP Parameter Discovery

**Arjun** scopre parametri HTTP nascosti (GET, POST, JSON, XML) tramite fuzzing intelligente. Usa tecniche di analisi delle risposte per minimizzare i falsi positivi.

---

## A cosa serve?

- **Scoprire parametri GET/POST nascosti** che non sono visibili nell'interfaccia
- **Trovare parametri per IDOR, SSRF, SQLi** — spesso i parametri nascosti sono più vulnerabili
- **Enumerare API** — scopri parametri di endpoint non documentati

---

## Come usarlo

### Discovery parametri GET

```bash
arjun -u http://target.com/page
```

### Discovery parametri POST

```bash
arjun -u http://target.com/api -m POST
```

### Discovery parametri JSON

```bash
arjun -u http://target.com/api -m JSON
```

### Con wordlist custom

```bash
arjun -u http://target.com/page -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

### Multi-URL da file

```bash
arjun -i urls.txt -oT output.txt
```

---

## Opzioni utili

| Flag | Descrizione |
|------|-------------|
| `-u URL` | URL target |
| `-m GET/POST/JSON/XML` | Metodo (default: GET) |
| `-w wordlist.txt` | Wordlist custom |
| `-i urls.txt` | File con lista URL |
| `-o output.json` | Output JSON |
| `-oT output.txt` | Output testo |
| `-t 10` | Thread |
| `-d 2` | Delay tra richieste (secondi) |
| `--headers "Cookie: x=y"` | Header custom |
| `-c 250` | Chunk size (parametri per richiesta) |
| `--stable` | Modalità stabile (meno aggressivo) |
| `--include 200` | Includi solo risposte con questo status |

---

## Come funziona

1. Invia una richiesta base e misura la risposta (dimensione, parole, righe)
2. Invia richieste con ~250 parametri alla volta
3. Se la risposta cambia, fa binary search per trovare il parametro esatto
4. Molto più efficiente di testare un parametro alla volta

---

## Esempio pratico

```bash
# Trova parametri nascosti
arjun -u http://10.10.11.42/dashboard -m GET

# Output:
# [*] Probing the target for stability
# [*] Analysing HTTP response for anomalies
# [+] Found: id, user, debug, admin
```

> Fonte: https://github.com/s0md3v/Arjun
