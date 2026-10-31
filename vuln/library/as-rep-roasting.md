---
title: "AS-REP Roasting"
aliases:
  - "as-rep roasting"
  - "asreproast"
  - "pre-authentication"
  - "uf_dont_require_preauth"
category: "Active Directory"
cwe: "327"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "critical"
mitre:
  - "T1558.004"
refs:
  - "https://attack.mitre.org/techniques/T1558/004/"
---

## Descrizione

Alcuni account di dominio hanno disabilitata la pre-autenticazione Kerberos (DONT_REQ_PREAUTH): è possibile richiedere per questi account un AS-REP e crackarne offline una porzione per recuperare la password, senza bisogno di credenziali valide.

## Impatto

Un attaccante senza alcuna credenziale può recuperare offline le password degli account configurati in modo errato: se tali account hanno privilegi, l'attacco fornisce un punto di ingresso diretto nel dominio.

## Remediation

Rimuovere il flag 'Non richiedere preautenticazione Kerberos' da tutti gli account, verificare periodicamente l'assenza di account con DONT_REQ_PREAUTH e applicare password robuste agli account che ne hanno necessità documentata.
