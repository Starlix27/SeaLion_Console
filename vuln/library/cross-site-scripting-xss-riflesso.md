---
title: "Cross-Site Scripting (XSS) riflesso"
aliases:
  - "xss"
  - "reflected xss"
  - "cross site scripting"
  - "xss riflesso"
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

L'applicazione include nel markup della risposta dati controllati dall'attaccante senza adeguata validazione o encoding: un parametro della richiesta (query string, form, header) viene riflesso nella pagina e interpretato come codice JavaScript dal browser della vittima. L'attacco richiede che la vittima segua un link predisposto (phishing, social engineering).

## Impatto

Un attaccante può eseguire script arbitrari nel contesto di sicurezza del sito vulnerabile: furto di cookie di sessione e credenziali, redirezioni verso siti malevoli, modifica del contenuto delle pagine e azioni per conto della vittima, con possibile compromissione completa dell'account.

## Remediation

Applicare l'encoding contestuale di tutti i dati in output (HTML, attributo, JavaScript, URL), validare gli input lato server con whitelist, adottare una Content Security Policy restrittiva e impostare gli attributi HttpOnly e Secure sui cookie di sessione.
