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

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **nmap**
