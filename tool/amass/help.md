# Amass — Subdomain Enumeration & OSINT

**Amass** (OWASP) è il tool più completo per subdomain enumeration. Combina brute-force, scraping, API di terze parti e analisi dei certificati per scoprire sottodomini.

---

## A cosa serve?

- **Subdomain discovery** — passivo (OSINT) e attivo (bruteforce DNS)
- **Asset discovery** — mappa la superficie d'attacco
- **Certificato analysis** — enumera sottodomini da certificati TLS

---

## Come usarlo

### Enumerazione passiva (solo OSINT, no DNS queries)

```bash
amass enum -passive -d target.com
```

### Enumerazione attiva con brute-force

```bash
amass enum -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Enumerazione completa

```bash
amass enum -active -d target.com -brute -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o results.txt
```

### Intelligence (info su un dominio)

```bash
amass intel -d target.com -whois
```

### Visualizzazione risultati

```bash
amass viz -d target.com -o graph.html
```

---

## Opzioni utili

| Flag | Descrizione |
|------|-------------|
| `-d target.com` | Dominio target |
| `-passive` | Solo OSINT (nessuna query DNS) |
| `-active` | Enumerazione attiva |
| `-brute` | Abilita brute-force DNS |
| `-w wordlist.txt` | Wordlist per brute-force |
| `-o output.txt` | Salva risultati |
| `-rf resolvers.txt` | File con DNS resolver custom |
| `-max-dns-queries 200` | Limita query DNS al secondo |
| `-timeout 30` | Timeout in minuti |
| `-config config.yaml` | File di configurazione (API keys, ecc.) |

---

## Configurazione API

Amass supporta decine di API per OSINT. Crea `~/.config/amass/config.yaml`:

```yaml
datasources:
  - name: Shodan
    creds:
      - account:
          apikey: YOUR_KEY
  - name: VirusTotal
    creds:
      - account:
          apikey: YOUR_KEY
```

Più API configuri, più sottodomini trova in modalità passiva.

---

## enum vs intel

| Comando | Uso |
|---------|-----|
| `amass enum` | Trova sottodomini di un dominio noto |
| `amass intel` | Scopri domini collegati a un'organizzazione |

> Fonte: https://github.com/owasp-amass/amass
