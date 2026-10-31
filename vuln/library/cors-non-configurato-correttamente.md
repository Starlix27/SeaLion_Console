---
title: "CORS non configurato correttamente"
aliases:
  - "cors"
  - "cross origin"
  - "cors misconfiguration"
category: "Web"
cwe: "942"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
severity: "medium"
refs:
  - "https://portswigger.net/web-security/cors"
  - "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
---

## Descrizione

La policy Cross-Origin Resource Sharing è eccessivamente permissiva: l'header Access-Control-Allow-Origin riflette qualsiasi origine (o usa wildcard) in combinazione con Access-Control-Allow-Credentials: true, permettendo a siti terzi di leggere le risposte autenticate dell'applicazione.

## Impatto

Un sito malevolo visitato dalla vittima può leggere dati sensibili dalle API dell'applicazione usando le credenziali di sessione della vittima, con esfiltrazione di informazioni riservate.

## Remediation

Definire una whitelist esplicita delle origini affidabili senza wildcard, non riflettere l'origine arbitraria, evitare Allow-Credentials dove non indispensabile e limitare metodi ed header consentiti.
