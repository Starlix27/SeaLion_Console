---
title: "robots.txt / sitemap.xml rivelano percorsi riservati"
aliases:
  - "robots.txt"
  - "robots"
  - "sitemap"
  - "robots_txt"
category: "Web"
cwe: "200"
cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
severity: "low"
mitre:
  - "T1592"
refs:
  - "https://www.rapid7.com/db/modules/auxiliary/scanner/http/robots_txt/"
---

## Descrizione

Il file robots.txt (o sitemap.xml) elenca percorsi che il proprietario intende nascondere ai crawler: voci Disallow verso pannelli di amministrazione, file di backup, directory di upload o documenti interni costituiscono di fatto una mappa delle risorse riservate, consultabile da chiunque.

## Impatto

Impatto diretto limitato, ma il file fornisce a un attaccante una lista pronta di endpoint sensibili da testare, accelerando la discovery di backup, console di amministrazione e file con credenziali.

## Remediation

Non fare affidamento su robots.txt per proteggere risorse: i percorsi sensibili vanno protetti con autenticazione e autorizzazione reali (robots.txt è solo un'indicazione per i crawler), rimuovendo dalla webroot ciò che non deve essere pubblico.

## Verifica

curl -s http://TARGET/robots.txt e analisi delle voci Disallow; il modulo Metasploit auxiliary/scanner/http/robots_txt automatizza il controllo.
