# onesixtyone — SNMP Community String Scanner

**onesixtyone** è un brute forcer veloce per trovare le community string SNMP. Invia richieste UDP in parallelo per testare migliaia di stringhe rapidamente.

---

## A cosa serve?

- **Brute Force:** Testa community string da wordlist
- **Velocità:** Invia richieste in parallelo su UDP 161
- **Scoperta:** Identifica dispositivi con community string deboli

---

## Come usarlo

### Brute force community string

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.129.14.128
```

### Scansione su più host

```bash
onesixtyone -c community.txt -i hosts.txt
```

> Fonte: https://github.com/trailofbits/onesixtyone
