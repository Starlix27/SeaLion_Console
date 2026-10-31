---
title: "Information Disclosure"
aliases:
  - "information disclosure"
  - "information leak"
  - "esposizione informazioni"
  - "stack trace"
  - "verbose error"
category: "Web"
cwe: "200"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
severity: "medium"
mitre:
  - "T1592"
refs:
  - "https://owasp.org/www-community/Improper_Error_Handling"
---

## Descrizione

L'applicazione rivela informazioni tecniche non destinate al pubblico: stack trace completi, versioni di server e framework, percorsi interni, commenti nel codice, directory listing o file di backup accessibili.

## Impatto

Le informazioni esposte (versioni, percorsi, tecnologie, dati interni) facilitano la pianificazione di attacchi mirati e l'identificazione di exploit noti per le versioni in uso.

## Remediation

Disabilitare messaggi di errore dettagliati in produzione (gestione centralizzata con pagine generiche), rimuovere banner e header che rivelano versioni, eliminare file di backup e commenti sensibili dal codice distribuito e disabilitare il directory listing.
