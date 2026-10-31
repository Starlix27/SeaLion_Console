---
title: "Session management: cookie senza flag di sicurezza"
aliases:
  - "session"
  - "cookie"
  - "httponly"
  - "secure flag"
  - "session fixation"
category: "Web"
cwe: "614"
cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"
severity: "medium"
mitre:
  - "T1539"
refs:
  - "https://owasp.org/www-community/controls/SecureCookieAttribute"
---

## Descrizione

I cookie di sessione sono privi degli attributi di sicurezza: senza HttpOnly sono accessibili da JavaScript (esfiltrabili via XSS), senza Secure viaggiano su HTTP in chiaro, senza SameSite sono inviati in contesti cross-site (CSRF). Inoltre gli ID di sessione non vengono rigenerati dopo l'autenticazione (session fixation).

## Impatto

Il furto o la fissazione degli identificativi di sessione permette il dirottamento degli account (session hijacking): l'impatto è massimo in combinazione con XSS o con la possibilità di intercettare il traffico.

## Remediation

Impostare sui cookie di sessione gli attributi Secure, HttpOnly e SameSite, rigenerare l'ID di sessione a ogni cambio di stato di autenticazione, applicare timeout di inattività e invalidare le sessioni al logout.
