---
title: "Unrestricted File Upload"
aliases:
  - "file upload"
  - "upload malevolo"
  - "webshell"
  - "unrestricted upload"
category: "Web"
cwe: "434"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "critical"
mitre:
  - "T1190"
  - "T1105"
refs:
  - "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
---

## Descrizione

La funzionalità di upload non verifica adeguatamente tipo, estensione e contenuto dei file caricati: è possibile caricare script eseguibili (webshell, pagine ASP/PHP/JSP) in directory accessibili via web, ottenendo l'esecuzione di codice sul server.

## Impatto

Esecuzione remota di codice con i privilegi del servizio web: controllo completo dell'applicazione e del server sottostante, accesso ai dati, movimento laterale verso altri sistemi della rete.

## Remediation

Consentire solo estensioni strettamente necessarie (whitelist), verificare MIME type e contenuto (magic bytes), rinominare i file con nomi casuali, salvarli fuori dalla webroot o servirli da dominio separato con Content-Disposition: attachment, disabilitare l'esecuzione nelle directory di upload e limitare le dimensioni.
