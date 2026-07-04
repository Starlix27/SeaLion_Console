# Recon-ng — Web Reconnaissance Framework

**Recon-ng** è un framework di ricognizione modulare con un'interfaccia simile a Metasploit. Supporta moduli per DNS, OSINT, geolocalizzazione, e molto altro.

---

## A cosa serve?

- **Framework modulare:** Centinaia di moduli per ricognizione
- **Database integrato:** Salva tutti i risultati per analisi successive
- **API Keys:** Si integra con Shodan, VirusTotal, HaveIBeenPwned
- **Reporting:** Genera report in HTML, JSON, CSV

---

## Come usarlo

### Avviare il framework

```bash
recon-ng
```

### Comandi principali

```
marketplace search             # Cerca moduli disponibili
marketplace install all        # Installa tutti i moduli
modules load recon/domains-hosts/hackertarget
options set SOURCE target.com
run
show hosts                     # Mostra risultati
```

> Fonte: https://github.com/lanmaster53/recon-ng
