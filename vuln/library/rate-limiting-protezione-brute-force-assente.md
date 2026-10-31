---
title: "Rate limiting / protezione brute force assente"
aliases:
  - "brute force"
  - "rate limiting"
  - "password spraying"
  - "lockout"
category: "Web"
cwe: "307"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
severity: "high"
mitre:
  - "T1110"
refs:
  - "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"
---

## Descrizione

I meccanismi di autenticazione non limitano il numero di tentativi: è possibile effettuare attacchi di forza bruta, password spraying ed enumerazione degli utenti senza blocchi né rallentamenti.

## Impatto

Senza rate limiting un attaccante può testare migliaia di credenziali in tempi brevi: account con password deboli vengono compromessi sistematicamente, spesso senza generare allarmi.

## Remediation

Implementare lockout progressivo o throttling adattivo per account e per IP sorgente, proteggere i form di login con CAPTCHA dopo tentativi falliti, uniformare i messaggi di errore per prevenire l'enumerazione e monitorare i picchi di autenticazioni fallite.
