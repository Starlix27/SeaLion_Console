---
title: "Password riutilizzate su più sistemi"
aliases:
  - "password reuse"
  - "riutilizzo password"
  - "credential reuse"
category: "Identità"
cwe: "521"
cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1078"
refs:
  - "https://pages.nist.gov/800-63-3/sp800-63b.html"
---

## Descrizione

La stessa password risulta condivisa tra più account o sistemi: le credenziali recuperate da un sistema compromesso sono risultate valide su altri host/servizi dell'infrastruttura.

## Impatto

La compromissione di un singolo sistema si propaga a cascata: un attaccante riutilizza le credenziali recuperate (in chiaro o come hash) per muoversi lateralmente e acquisire accessi crescenti senza dover sfruttare ulteriori vulnerabilità.

## Remediation

Garantire password univoche per ogni account e sistema (in particolare per account amministrativi e account di servizio), adottare un password manager aziendale, implementare soluzioni LAPS per le password locali e abilitare MFA dove possibile.
