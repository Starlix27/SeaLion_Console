# Nuclei — Fast Vulnerability Scanner

**Nuclei** è uno scanner di vulnerabilità veloce e personalizzabile basato su template YAML. Sviluppato da ProjectDiscovery, permette di scansionare target per CVE note, misconfiguration, exposed panel, default login e molto altro.

---

## A cosa serve?

- **Vulnerability Scanning:** Rileva CVE note, misconfiguration e falle di sicurezza su web app e servizi
- **Template-based:** Migliaia di template community-driven (aggiornati costantemente)
- **Veloce e scalabile:** Scritto in Go, gestisce migliaia di target in parallelo
- **Personalizzabile:** Puoi scrivere i tuoi template YAML per check custom

---

## Installazione

```bash
# Via Go (consigliato)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Aggiornare i template
nuclei -update-templates
```

---

## Come usarlo

### Scansione base su un target

```bash
nuclei -u https://target.com
```

### Scansione su lista di target

```bash
nuclei -l targets.txt
```

### Filtrare per severità

```bash
nuclei -u https://target.com -s critical,high
nuclei -u https://target.com -s medium,low
```

### Filtrare per tipo di template

```bash
nuclei -u https://target.com -t cves/
nuclei -u https://target.com -t exposed-panels/
nuclei -u https://target.com -t default-logins/
nuclei -u https://target.com -t misconfigurations/
```

### Filtrare per tag

```bash
nuclei -u https://target.com -tags rce
nuclei -u https://target.com -tags sqli,xss
nuclei -u https://target.com -tags cve2023
```

### Usare template specifici

```bash
nuclei -u https://target.com -t cves/2021/CVE-2021-44228.yaml
```

### Escludere template

```bash
nuclei -u https://target.com -exclude-tags dos
```

### Output e report

```bash
nuclei -u https://target.com -o risultati.txt
nuclei -u https://target.com -json -o risultati.json
nuclei -u https://target.com -me output_dir/     # Markdown export
```

---

## Comandi utili

| Comando | Descrizione |
|---------|-------------|
| `nuclei -u <URL>` | Scansione singolo target |
| `nuclei -l <file>` | Scansione lista target |
| `nuclei -s critical,high` | Solo vulnerabilità critiche e alte |
| `nuclei -t <path>` | Usa template specifici |
| `nuclei -tags <tag>` | Filtra per tag |
| `nuclei -exclude-tags dos` | Escludi template DoS |
| `nuclei -rl 50` | Rate limit (50 req/s) |
| `nuclei -c 25` | Concorrenza (25 template paralleli) |
| `nuclei -stats` | Mostra statistiche durante la scansione |
| `nuclei -update-templates` | Aggiorna i template alla versione più recente |
| `nuclei -tl` | Lista tutti i template disponibili |

---

## Workflow tipico

```bash
# 1. Aggiorna i template
nuclei -update-templates

# 2. Scansione completa
nuclei -u https://target.com -stats

# 3. Solo vulnerability critiche
nuclei -u https://target.com -s critical,high -o critical_findings.txt

# 4. Combinare con altri tool (subfinder + httpx + nuclei)
subfinder -d target.com | httpx | nuclei -s critical,high
```

---

## Template personalizzati

I template sono file YAML nella cartella `~/nuclei-templates/`. Struttura base:

```yaml
id: my-custom-check
info:
  name: Custom Check
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status:
          - 200
```

> Fonte: https://github.com/projectdiscovery/nuclei
