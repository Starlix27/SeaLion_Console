---
title: "Open Redirect"
aliases:
  - "open redirect"
  - "unvalidated redirect"
category: "Web"
cwe: "601"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N"
severity: "medium"
mitre:
  - "T1204.001"
refs:
  - "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
---

## Descrizione

L'applicazione redirige l'utente verso un URL derivato da un parametro controllabile senza validazione: un attaccante può costruire link apparentemente legittimi (dominio del Cliente) che portano a siti malevoli.

## Impatto

Il redirect aperto viene sfruttato per campagne di phishing credibili e per il furto di token OAuth/sessioni tramite redirect verso domini dell'attaccante, sfruttando la fiducia nel dominio legittimo.

## Remediation

Evitare redirect basati su input utente; dove indispensabili, usare una whitelist di destinazioni consentite o una mappa di identificativi opachi, e mostrare una pagina di avviso per le destinazioni esterne.
