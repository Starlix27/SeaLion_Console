---
title: "Directory Listing abilitato"
aliases:
  - "directory listing"
  - "directory indexing"
  - "indice directory"
category: "Web"
cwe: "548"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
severity: "medium"
mitre:
  - "T1083"
refs:
  - "https://owasp.org/www-community/Improper_Error_Handling"
---

## Descrizione

Il server web mostra l'elenco dei file delle directory prive di documento indice, esponendo la struttura interna dell'applicazione e file potenzialmente sensibili (backup, configurazioni, documenti).

## Impatto

Un attaccante può enumerare e scaricare file non referenziati dalle pagine: documenti riservati, dump, script e file di configurazione, facilitando attacchi successivi.

## Remediation

Disabilitare il directory listing (Options -Indexes / autoindex off), pubblicare solo i file strettamente necessari e proteggere con autenticazione le aree di file-sharing interne.
