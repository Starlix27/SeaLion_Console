---
title: "TLS/SSL: protocolli o cifrari obsoleti"
aliases:
  - "ssl"
  - "tls"
  - "weak tls"
  - "cifrari deboli"
  - "sslv3"
  - "tls 1.0"
  - "tls 1.1"
  - "weak cipher"
category: "Rete"
cwe: "327"
cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
severity: "medium"
mitre:
  - "T1040"
refs:
  - "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
---

## Descrizione

Il servizio supporta versioni obsolete di SSL/TLS (SSLv3, TLS 1.0/1.1) o suite di cifratura deboli (RC4, DES, 3DES, export, null): la protezione del canale cifrato è vulnerabile ad attacchi noti (POODLE, BEAST, downgrade).

## Impatto

Un attaccante in posizione man-in-the-middle può decifrare o manipolare il traffico protetto, esponendo credenziali, cookie di sessione e dati sensibili scambiati con il servizio.

## Remediation

Disabilitare SSLv2/v3 e TLS 1.0/1.1, abilitare esclusivamente TLS 1.2 e 1.3 con suite di cifratura AEAD robuste, ordinare le preferenze lato server e verificare la configurazione con scansioni periodiche (testssl.sh, sslscan).
