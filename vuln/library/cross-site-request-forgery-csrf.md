---
title: "Cross-Site Request Forgery (CSRF)"
aliases:
  - "csrf"
  - "xsrf"
  - "cross site request forgery"
category: "Web"
cwe: "352"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"
severity: "medium"
mitre:
  - "T1204"
refs:
  - "https://owasp.org/www-community/attacks/csrf"
  - "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
---

## Descrizione

Le funzionalità sensibili dell'applicazione non verificano l'origine delle richieste: un attaccante può indurre il browser di un utente autenticato a inviare richieste non volute (cambio password/email, bonifici, modifiche di configurazione) tramite una pagina malevola visitata dalla vittima.

## Impatto

Un attaccante può far eseguire alla vittima azioni privilegiate a sua insaputa, sfruttandone la sessione attiva: modifica di credenziali e impostazioni, transazioni non autorizzate e, nel caso di utenti amministratori, compromissione dell'intera applicazione.

## Remediation

Implementare token anti-CSRF imprevedibili validati lato server su ogni richiesta di modifica dello stato, impostare l'attributo SameSite (Strict/Lax) sui cookie di sessione, verificare gli header Origin/Referer e richiedere la ri-autenticazione per le operazioni critiche.
