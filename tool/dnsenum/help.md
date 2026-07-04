# dnsenum — DNS Enumeration Tool

**dnsenum** automatizza l'enumerazione DNS: recupera name server, tenta zone transfer (AXFR), e fa brute force di sottodomini con wordlist.

---

## A cosa serve?

- **Zone Transfer:** Tenta di scaricare l'intera zona DNS
- **Brute Force:** Testa sottodomini da wordlist
- **Name Servers:** Identifica i server DNS autoritativi

---

## Come usarlo

### Enumerazione completa

```bash
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt target.com
```

### Enumerazione base

```bash
dnsenum target.com
```

> Fonte: https://github.com/fwaeytens/dnsenum
