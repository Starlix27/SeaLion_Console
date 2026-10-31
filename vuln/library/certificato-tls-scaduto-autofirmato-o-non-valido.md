---
title: "Certificato TLS scaduto, autofirmato o non valido"
aliases:
  - "certificato"
  - "self-signed"
  - "expired certificate"
  - "certificato scaduto"
  - "autofirmato"
category: "Rete"
cwe: "295"
cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"
severity: "medium"
mitre:
  - "T1040"
  - "T1557"
refs:
  - "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
---

## Descrizione

Il servizio presenta un certificato TLS scaduto, autofirmato, con nome non corrispondente o emesso da CA non affidabile: i client non possono verificare l'identità del server e gli utenti sono abituati ad accettare avvisi di sicurezza.

## Impatto

L'impossibilità di validare il certificato espone ad attacchi man-in-the-middle con intercettazione di credenziali e dati; l'abitudine a ignorare gli avvisi abbassa la difesa complessiva degli utenti.

## Remediation

Installare certificati emessi da una CA affidabile (interna o pubblica) con CN/SAN corretti, automatizzare il rinnovo prima della scadenza, correggere gli avvisi sui client e sensibilizzare gli utenti a non accettare certificati non validi.
