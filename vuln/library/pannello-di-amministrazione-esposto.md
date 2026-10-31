---
title: "Pannello di amministrazione esposto"
aliases:
  - "admin panel"
  - "pannello admin"
  - "interfaccia amministrativa esposta"
category: "Web"
cwe: "284"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "critical"
mitre:
  - "T1190"
refs:
  - "https://owasp.org/www-community/attacks/"
---

## Descrizione

Interfacce di amministrazione (console gestionali, dashboard, pannelli di debug) sono raggiungibili dalla rete senza restrizioni, talvolta con autenticazione assente o debole: chiunque raggiunga il servizio può accedere a funzioni privilegiate.

## Impatto

Le interfacce amministrative offrono funzionalità ad alto privilegio (gestione utenti, esecuzione script, configurazioni): la loro esposizione permette la compromissione diretta dell'applicazione e spesso del server sottostante.

## Remediation

Limitare l'accesso ai pannelli amministrativi ai soli indirizzi autorizzati (ACL di rete, VPN, segmentazione), richiedere autenticazione robusta possibilmente con MFA, disabilitare le interfacce di debug/gestione in produzione e monitorarne gli accessi.
