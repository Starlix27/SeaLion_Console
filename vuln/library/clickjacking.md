---
title: "Clickjacking"
aliases:
  - "clickjacking"
  - "ui redressing"
  - "x-frame-options"
category: "Web"
cwe: "1021"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
severity: "medium"
mitre:
  - "T1204"
refs:
  - "https://owasp.org/www-community/attacks/Clickjacking"
---

## Descrizione

L'applicazione non impedisce di essere inclusa in iframe di siti terzi (mancano X-Frame-Options e la direttiva frame-ancestors della CSP): un attaccante può sovrapporre la pagina legittima a elementi malevoli e indurre l'utente a cliccare su controlli invisibili.

## Impatto

Un attaccante può far compiere alla vittima azioni non volute sull'applicazione (modifica impostazioni, autorizzazioni, transazioni) sfruttandone la sessione autenticata, con tecniche di UI redressing.

## Remediation

Impostare la direttiva frame-ancestors 'none' (o domini fidati) nella Content-Security-Policy e l'header X-Frame-Options: DENY/SAMEORIGIN per i browser legacy; per le operazioni critiche richiedere conferme aggiuntive.
