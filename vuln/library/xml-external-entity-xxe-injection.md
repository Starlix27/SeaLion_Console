---
title: "XML External Entity (XXE) Injection"
aliases:
  - "xxe"
  - "xml external entity"
category: "Web"
cwe: "611"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
severity: "high"
mitre:
  - "T1190"
refs:
  - "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"
  - "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
---

## Descrizione

Il parser XML dell'applicazione elabora entità esterne definite nel documento inviato dal client: un attaccante può dichiarare entità che leggono file locali del server o che effettuano richieste verso risorse interne (SSRF), sfruttando la configurazione permissiva del parser.

## Impatto

Lettura di file arbitrari dal filesystem del server (configurazioni, chiavi, credenziali), port scanning ed enumerazione della rete interna tramite SSRF e, in alcuni casi, denial of service (Billion Laughs) o esecuzione remota di codice.

## Remediation

Disabilitare la risoluzione delle entità esterne e dei DTD in tutti i parser XML, preferire formati dati meno complessi (JSON) dove possibile, aggiornare le librerie XML e applicare whitelist lato server sugli input; filtrare in uscita le richieste del server verso la rete interna.
