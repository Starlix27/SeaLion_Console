---
title: "Path Traversal / Local File Inclusion"
aliases:
  - "lfi"
  - "path traversal"
  - "directory traversal"
  - "file inclusion"
  - "rfi"
  - "local file inclusion"
category: "Web"
cwe: "22"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
severity: "high"
mitre:
  - "T1190"
refs:
  - "https://owasp.org/www-community/attacks/Path_Traversal"
---

## Descrizione

L'applicazione costruisce percorsi di file a partire da input dell'utente senza sanificazione: sequenze come ../ permettono di uscire dalla directory prevista e leggere (o includere) file arbitrari del filesystem, inclusi file di configurazione e codice sorgente.

## Impatto

Lettura di file sensibili (/etc/passwd, configurazioni con credenziali, chiavi private, codice sorgente) e, nelle varianti di inclusione con esecuzione (LFI/RFI su PHP), possibile esecuzione di codice arbitrario sul server fino alla compromissione completa.

## Remediation

Non usare mai input utente per costruire percorsi: mappare le risorse su identificativi opachi, normalizzare i path e verificare che restino nella directory consentita (chroot/jail), applicare whitelist sui nomi file e disabilitare l'inclusione remota (allow_url_include=Off).
