# WHOIS — Domain Information Lookup

**WHOIS** interroga i database di registrazione domini per ottenere informazioni sul proprietario, i name server, le date di registrazione e scadenza.

---

## A cosa serve?

- **Info registrante:** Nome, email, organizzazione del proprietario
- **Name Servers:** Quali DNS gestiscono il dominio
- **Date:** Creazione, scadenza, ultimo aggiornamento
- **Lock Status:** Se il dominio è protetto da trasferimenti

---

## Come usarlo

### Query base

```bash
whois target.com
```

### Solo informazioni essenziali

```bash
whois target.com | grep -E "Registrant|Name Server|Creation|Expiry"
```

> Installato di default su molte distro Linux.
> Per installare: `sudo apt install whois`
