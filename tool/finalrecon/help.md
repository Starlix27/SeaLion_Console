# FinalRecon — Web Reconnaissance Tool

**FinalRecon** è un tool modulare in Python per la ricognizione web. Raccoglie header, certificati SSL, WHOIS, DNS, sottodomini e fa crawling.

---

## A cosa serve?

- **Headers:** Analizza intestazioni HTTP per trovare configurazioni errate
- **WHOIS:** Informazioni di registrazione del dominio
- **SSL:** Esamina certificati SSL/TLS
- **DNS:** Enumera oltre 40 tipi di record
- **Sottodomini:** Cerca in crt.sh, Shodan, VirusTotal e altre fonti
- **Crawling:** Estrae link, JavaScript, commenti dal codice

---

## Come usarlo

### Scansione completa

```bash
./finalrecon.py --full --url http://target.com
```

### Solo header e WHOIS

```bash
./finalrecon.py --headers --whois --url http://target.com
```

### Solo sottodomini

```bash
./finalrecon.py --sub --url http://target.com
```

### Solo crawling

```bash
./finalrecon.py --crawl --url http://target.com
```

> Fonte: https://github.com/thewhiteh4t/FinalRecon
