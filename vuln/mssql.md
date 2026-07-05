# MSSQL — Microsoft SQL Server
**Porte:** 1433 (TCP)  
**Categoria:** Database

Database relazionale Microsoft, integrato con .NET e Active Directory.
Client principale: SSMS (SQL Server Management Studio) — GUI per admin.
Da Linux: mssqlclient.py (Impacket) o mssql-cli.

Database di sistema: master (config), model (template), msdb (job/backup), tempdb (dati temporanei).
ATTENZIONE: SSMS a volte salva le password in chiaro sul PC dell'admin!

## Vulnerabilità comuni

- Utente sa (System Administrator) con password debole o di default
- Autenticazione Windows — account rubato = accesso automatico al DB
- xp_cmdshell abilitato — esecuzione comandi di sistema dal database → RCE
- Certificati non validati — intercettazione connessione (MitM)
- SSMS salva password in chiaro sul PC dell'admin
- Nessuna cifratura tra client e server per default

## Enumerazione & Comandi

### SCAN COMPLETO CON NMAP

```bash
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,\
ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,\
ms-sql-dac,ms-sql-dump-hashes \
--script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,\
mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>
```

### CONNESSIONE CON IMPACKET

```bash
python3 mssqlclient.py Administrator@<IP> -windows-auth  # Auth Windows
python3 mssqlclient.py sa@<IP>                            # Auth SQL diretta
```

### NETEXEC

```bash
nxc mssql <IP> -u 'sa' -p 'password' --query 'SELECT @@version;'
```

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **nmap**
- **impacket**
- **netexec**
