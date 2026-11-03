---
title: "Divulgazione della versione del software (banner / pagine informative)"
aliases:
  - "banner grabbing"
  - "version disclosure"
  - "divulgazione versione"
  - "fingerprinting"
  - "info.php"
  - "server header"
category: "Web"
cwe: "200"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
severity: "info"
mitre:
  - "T1592"
refs:
  - "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
---

## Descrizione

Banner di servizio, header HTTP (Server, X-Powered-By), pagine di diagnostica (info.php, server-status) o il CMS stesso rivelano nome e versione esatti del software in uso: l'ambiente risulta fingerprintabile da chiunque senza autenticazione.

## Impatto

L'impatto immediato è nullo, ma l'esposizione della release facilita la ricognizione: un attaccante può mappare istantaneamente il software alle vulnerabilità note e monitorare l'asset in attesa di futuri 0-day o exploit pubblici.

## Remediation

Ridurre le informazioni esposte: disabilitare/ genericizzare i banner e gli header di versione, rimuovere pagine di diagnostica dalla webroot, e nascondere la versione del CMS/framework dove possibile (security through obscurity come misura complementare, non sostitutiva del patching).

## Verifica

curl -sI http://TARGET/ per gli header, accesso diretto a /info.php o pagine equivalenti, e confronto dei banner con l'output di nmap -sV.
