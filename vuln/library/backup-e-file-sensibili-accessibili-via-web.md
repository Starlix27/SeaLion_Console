---
title: "Backup e file sensibili accessibili via web"
aliases:
  - "backup files"
  - "file backup"
  - ".bak"
  - "file sensibili esposti"
category: "Web"
cwe: "530"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
severity: "high"
mitre:
  - "T1592"
refs:
  - "https://owasp.org/www-community/vulnerabilities/"
---

## Descrizione

File di backup, copie di configurazione, dump di database o archivi (es. .bak, .old, .sql, .zip, ~) sono raggiungibili via web: contenuti non destinati alla pubblicazione risultano scaricabili da chiunque.

## Impatto

I file esposti contengono frequentemente credenziali, codice sorgente, dump di database e dati personali: il loro recupero può compromettere direttamente applicazione, database e infrastruttura.

## Remediation

Rimuovere i file di backup e non necessari dalla webroot, negare l'accesso alle estensioni sensibili a livello di web server, proteggere i backup con storage dedicato non esposto e verificare le procedure di deploy.
