---
title: "DNS zone transfer (AXFR) consentito"
aliases:
  - "zone transfer"
  - "axfr"
  - "dns zone transfer"
category: "Rete"
cwe: "200"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
severity: "medium"
mitre:
  - "T1590.002"
refs:
  - "https://attack.mitre.org/techniques/T1590/002/"
---

## Descrizione

Il server DNS consente il trasferimento di zona (AXFR) a richiedenti non autorizzati: l'intero contenuto della zona (nomi host, indirizzi IP, record di servizio) è scaricabile da chiunque.

## Impatto

La mappa completa dei sistemi del dominio semplifica la ricognizione: nomi e IP di server, servizi e dispositivi diventano noti all'attaccante, accelerando l'individuazione di target di valore.

## Remediation

Limitare i trasferimenti di zona ai soli DNS secondari autorizzati (ACL per indirizzo IP e TSIG), disabilitando AXFR verso qualsiasi altro richiedente.
