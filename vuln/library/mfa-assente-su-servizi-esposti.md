---
title: "MFA assente su servizi esposti"
aliases:
  - "mfa"
  - "2fa"
  - "autenticazione multifattore"
  - "missing mfa"
category: "Identità"
cwe: "308"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
severity: "high"
mitre:
  - "T1078"
  - "T1110"
refs:
  - "https://csrc.nist.gov/publications/detail/sp/800-63b/final"
---

## Descrizione

Servizi critici raggiungibili dalla rete (VPN, webmail, portali, console) richiedono la sola autenticazione a singolo fattore (username e password), senza un secondo fattore di verifica.

## Impatto

La compromissione o l'indovinamento della sola password (phishing, spraying, reuse da breach note) è sufficiente per ottenere accesso completo: l'assenza di MFA elimina la principale barriera contro l'abuso di credenziali valide.

## Remediation

Abilitare l'autenticazione multi-fattore su tutti i servizi esposti e sugli accessi amministrativi, preferendo fattori resistenti al phishing (FIDO2/WebAuthn) dove possibile, e integrare il controllo nella policy di accesso aziendale.
