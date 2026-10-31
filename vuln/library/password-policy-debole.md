---
title: "Password policy debole"
aliases:
  - "weak password policy"
  - "password deboli"
  - "weak password"
category: "Identità"
cwe: "521"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
severity: "high"
mitre:
  - "T1110"
refs:
  - "https://pages.nist.gov/800-63-3/sp800-63b.html"
---

## Descrizione

Le password in uso non rispettano requisiti minimi di robustezza: sono state individuate password brevi, da dizionario, derivate dal nome dell'organizzazione o uguali allo username, indovinabili con attacchi a dizionario in tempi brevi.

## Impatto

Password prevedibili permettono attacchi di password spraying, brute force e credential stuffing con conseguente accesso non autorizzato ad account utente e amministrativi, spesso senza far scattare blocchi o allarmi.

## Remediation

Adottare una password policy basata su passphrase lunghe (minimo 12-14 caratteri) con filtro contro password comuni e compromesse (blocklist), abilitare MFA sui servizi esposti, configurare lockout intelligente e sensibilizzare gli utenti.
