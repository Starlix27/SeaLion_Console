---
title: "Server-Side Request Forgery (SSRF)"
aliases:
  - "ssrf"
  - "server side request forgery"
category: "Web"
cwe: "918"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
severity: "high"
mitre:
  - "T1190"
refs:
  - "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
  - "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
---

## Descrizione

L'applicazione recupera risorse remote a partire da un URL controllabile dall'utente senza adeguata validazione: un attaccante può far effettuare al server richieste verso destinazioni arbitrarie, inclusi servizi interni non esposti (localhost, metadata cloud, reti private).

## Impatto

Accesso a servizi interni altrimenti irraggiungibili: lettura dei metadata cloud (credenziali temporanee IAM), scansione della rete interna, interazione con API e console di amministrazione locali, con possibile escalation verso la compromissione dell'infrastruttura.

## Remediation

Validare gli URL con whitelist di domini/schemi consentiti, bloccare gli indirizzi delle reti private e loopback dopo la risoluzione DNS (mitigando il DNS rebinding), disabilitare i redirect non necessari, separare la rete del servizio e richiedere autenticazione ai servizi interni.
