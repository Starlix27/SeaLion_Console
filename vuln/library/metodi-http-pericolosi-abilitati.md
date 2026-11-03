---
title: "Metodi HTTP pericolosi abilitati (PUT, DELETE, TRACE)"
aliases:
  - "http methods"
  - "put delete"
  - "trace"
  - "options"
  - "webdav"
  - "metodi http"
category: "Web"
cwe: "749"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
severity: "medium"
mitre:
  - "T1190"
refs:
  - "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"
---

## Descrizione

Il server web (o WebDAV) accetta metodi HTTP pericolosi: PUT permette di caricare file arbitrari sulla webroot, DELETE di rimuovere risorse, TRACE/TRACK riflettono le richieste (utile per XST e furto di header httpOnly). La risposta a OPTIONS elenca i metodi consentiti.

## Impatto

Upload di webshell o contenuti arbitrari, cancellazione di risorse e, con TRACE, cross-site tracing per sottrarre credenziali: in combinazione con estensioni eseguibili l'impatto arriva all'esecuzione di codice sul server.

## Remediation

Disabilitare i metodi non necessari a livello di web server/application gateway (consentire solo GET/POST/HEAD secondo necessità), disattivare WebDAV se non utilizzato e verificare i metodi ammessi dopo ogni modifica alla configurazione.

## Verifica

curl -s -X OPTIONS -i http://TARGET/ per elencare i metodi, seguito da un tentativo controllato di PUT/DELETE su un path di test; nmap --script http-methods automatizza l'enumerazione.
