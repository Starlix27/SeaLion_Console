---
title: "SQL Injection"
aliases:
  - "sqli"
  - "sql injection"
  - "iniezione sql"
category: "Web"
cwe: "89"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "critical"
mitre:
  - "T1190"
refs:
  - "https://owasp.org/www-community/attacks/SQL_Injection"
  - "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
---

## Descrizione

I dati forniti dall'utente vengono concatenati direttamente nelle query SQL senza parametrizzazione: un attaccante può alterare la logica delle interrogazioni al database iniettando frammenti di SQL tramite parametri di input (GET/POST, header, cookie). Sono state verificate tecniche di estrazione dati (UNION-based, error-based) e/o inferenziali (blind, time-based).

## Impatto

Accesso non autorizzato in lettura e scrittura al database: esfiltrazione di dati sensibili (credenziali, dati personali), bypass dell'autenticazione, modifica o cancellazione di informazioni e, in alcune configurazioni (es. xp_cmdshell, INTO OUTFILE), esecuzione di comandi sul sistema operativo.

## Remediation

Utilizzare esclusivamente prepared statement / query parametrizzate o ORM con binding dei parametri, applicare il principio del minimo privilegio all'account del database, validare gli input con whitelist, disabilitare funzionalità pericolose del DBMS e implementare la gestione centralizzata degli errori senza dettagli SQL.
