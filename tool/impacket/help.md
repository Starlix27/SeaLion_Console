# Impacket — Python Network Protocol Library

**Impacket** è una raccolta di classi Python per lavorare con protocolli di rete. Include tool fondamentali per il pentesting Windows: mssqlclient, wmiexec, smbclient, secretsdump, e molti altri.

---

## A cosa serve?

- **mssqlclient.py:** Connessione a database MSSQL
- **wmiexec.py:** Esecuzione comandi remoti via WMI
- **smbclient.py:** Client SMB avanzato
- **secretsdump.py:** Dump di hash e credenziali
- **psexec.py:** Shell remota via SMB
- **samrdump.py:** Enumerazione utenti via SAM/RPC

---

## Come usarlo

### Connessione MSSQL

```bash
python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
```

### Esecuzione comandi via WMI

```bash
python3 wmiexec.py user:"password"@10.129.201.248 "hostname"
```

### Dump credenziali

```bash
python3 secretsdump.py user:password@10.129.201.248
```

### Enumerazione utenti RPC

```bash
python3 samrdump.py 10.129.14.128
```

> Fonte: https://github.com/fortra/impacket
