# braa — Mass SNMP Scanner

**braa** fa richieste SNMP in parallelo su migliaia di OID contemporaneamente, molto più veloce di snmpwalk per estrarre grandi quantità di dati.

---

## A cosa serve?

- **Scansione massiva:** Interroga OID in parallelo
- **Velocità:** Molto più rapido di snmpwalk
- **Enumerazione:** Estrae info sistema, software, configurazioni

---

## Come usarlo

### Scansione base

```bash
braa public@10.129.14.128:.1.3.6.*
```

### Con community string personalizzata

```bash
braa community_string@10.129.14.128:.1.3.6.*
```

> Fonte: https://github.com/mteg/braa
