---
title: "Cross-Site Scripting (XSS) memorizzato"
aliases:
  - "stored xss"
  - "xss persistente"
  - "persistent xss"
category: "Web"
cwe: "79"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
severity: "medium"
mitre:
  - "T1059.007"
  - "T1189"
refs:
  - "https://owasp.org/www-community/attacks/xss/"
  - "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
---

## Descrizione

L'applicazione salva lato server (database, commenti, profili, log) payload controllati dall'attaccante e li restituisce ad altri utenti senza encoding: lo script viene eseguito automaticamente nel browser di chiunque visualizzi il contenuto, senza bisogno di indurre la vittima a cliccare un link.

## Impatto

La persistenza del payload amplifica l'impatto rispetto all'XSS riflesso: ogni utente che visita la pagina compromessa esegue il codice dell'attaccante. Possibili furto di sessioni (anche di amministratori), worm self-propagating, defacement e raccolta massiva di credenziali.

## Remediation

Applicare encoding contestuale su ogni output che includa dati persistiti, validare gli input in scrittura con whitelist, sanitizzare eventuale HTML ammesso con librerie dedicate (es. DOMPurify), adottare Content Security Policy e cookie HttpOnly/Secure.
