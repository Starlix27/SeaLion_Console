---
title: "Repository Git esposto"
aliases:
  - "git exposed"
  - ".git"
  - "repository esposto"
category: "Web"
cwe: "527"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
severity: "high"
mitre:
  - "T1592"
refs:
  - "https://owasp.org/www-community/attacks/"
---

## Descrizione

La directory .git del repository di sviluppo è accessibile via web: è possibile scaricare l'intero repository (con strumenti come git-dumper) e ricostruire codice sorgente e cronologia completa dell'applicazione.

## Impatto

Il codice sorgente e la history Git possono contenere credenziali, chiavi API, segreti committati e logica di business, esponendo l'organizzazione a compromissioni multiple ben oltre la singola applicazione.

## Remediation

Bloccare l'accesso alle directory .git a livello di web server, verificare le procedure di deploy (escludere i metadati di versionamento), ruotare eventuali segreti presenti nella history e bonificare il repository.
