---
title: "JWT con firma debole o non verificata"
aliases:
  - "jwt"
  - "json web token"
  - "alg none"
  - "weak jwt secret"
category: "Web"
cwe: "347"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
severity: "critical"
mitre:
  - "T1528"
refs:
  - "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens"
---

## Descrizione

I token JWT usati per l'autenticazione presentano debolezze crittografiche: firma con segreto debole/indovinabile, accettazione dell'algoritmo 'none', mancata verifica della scadenza o confusione algoritmo RS256/HS256.

## Impatto

Un attaccante può forgiare token validi con identità e privilegi arbitrari (inclusi amministratori), ottenendo accesso completo all'applicazione senza credenziali legittime.

## Remediation

Verificare sempre firma, scadenza, issuer e audience lato server, usare segreti robusti e casuali (o coppie di chiavi asimmetriche con kid controllato), rifiutare 'none' e algoritmi non attesi, e ruotare i segreti se esposti.
