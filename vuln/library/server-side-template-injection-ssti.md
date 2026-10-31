---
title: "Server-Side Template Injection (SSTI)"
aliases:
  - "ssti"
  - "template injection"
  - "jinja2"
  - "twig"
  - "freemarker"
category: "Web"
cwe: "94"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "critical"
mitre:
  - "T1190"
refs:
  - "https://portswigger.net/web-security/server-side-template-injection"
---

## Descrizione

Input dell'utente vengono concatenati nei template server-side invece di essere passati come dati: il motore di template (Jinja2, Twig, Freemarker, Velocity, ...) interpreta il payload iniettato come codice template.

## Impatto

L'iniezione di template consente l'accesso a oggetti interni dell'applicazione e, nella maggior parte dei motori, l'esecuzione di codice arbitrario sul server: compromissione completa dell'host.

## Remediation

Passare i dati utente sempre come variabili e mai come parte del template, sanitizzare gli input, abilitare modalità sandbox dove disponibili e mantenere aggiornati i motori di template.
