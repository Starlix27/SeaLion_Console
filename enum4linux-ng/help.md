# enum4linux-ng — Enumerazione SMB/RPC All-in-One

**enum4linux-ng** è la versione moderna del classico enum4linux. Combina automaticamente scansione porte, enumerazione utenti, gruppi, condivisioni e policy password via SMB/RPC.

---

## A cosa serve?

- **Enumerazione completa:** Utenti, gruppi, condivisioni, policy password
- **Dialetti SMB:** Rileva le versioni del protocollo supportate
- **Password Policy:** Scopre lunghezza minima password, lockout policy

---

## Come usarlo

### Enumerazione completa

```bash
./enum4linux-ng.py 10.129.14.128 -A
```

### Solo utenti e gruppi

```bash
./enum4linux-ng.py 10.129.14.128 -U -G
```

### Output in JSON

```bash
./enum4linux-ng.py 10.129.14.128 -A -oJ output.json
```

> Fonte: https://github.com/cddmp/enum4linux-ng
