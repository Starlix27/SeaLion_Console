# SMBMap — Enumerazione Permessi SMB

**SMBMap** permette di visualizzare rapidamente i permessi (lettura/scrittura) sulle condivisioni SMB di un target.

---

## A cosa serve?

- **Mappa permessi:** Mostra READ/WRITE su ogni share
- **Navigazione:** Esplora il contenuto delle condivisioni
- **Download/Upload:** Trasferisce file da/verso le share

---

## Come usarlo

### Enumerazione base (sessione anonima)

```bash
smbmap -H 10.129.14.128
```

### Con credenziali

```bash
smbmap -H 10.129.14.128 -u 'utente' -p 'password'
```

### Elencare file in una share

```bash
smbmap -H 10.129.14.128 -r 'share_name'
```

### Scaricare un file

```bash
smbmap -H 10.129.14.128 --download 'share_name\file.txt'
```

> Fonte: https://github.com/ShawnDEvans/smbmap
