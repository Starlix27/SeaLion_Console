# theHarvester — OSINT Information Gathering

**theHarvester** raccoglie email, nomi, sottodomini, IP e URL da fonti pubbliche come Google, Bing, LinkedIn, Shodan, e molte altre.

---

## A cosa serve?

- **Email Harvesting:** Trova indirizzi email dei dipendenti
- **Sottodomini:** Scopre sottodomini da fonti OSINT
- **Host Discovery:** Trova IP associati al dominio
- **Fonti multiple:** Google, Bing, Shodan, DNSDumpster, crt.sh

---

## Come usarlo

### Ricerca completa

```bash
theHarvester -d target.com -b all
```

### Solo Google e Bing

```bash
theHarvester -d target.com -b google,bing
```

### Salvare output

```bash
theHarvester -d target.com -b all -f results.html
```

> Fonte: https://github.com/laramies/theHarvester
