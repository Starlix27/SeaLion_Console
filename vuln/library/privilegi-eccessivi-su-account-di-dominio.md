---
title: "Privilegi eccessivi su account di dominio"
aliases:
  - "excessive privileges"
  - "privilegi eccessivi"
  - "domain admin"
  - "acl ad"
category: "Active Directory"
cwe: "250"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1078.002"
refs:
  - "https://attack.mitre.org/techniques/T1078/002/"
---

## Descrizione

Numerosi account standard dispongono di privilegi amministrativi non giustificati (appartenenza a Domain Admins, ACL pericolose come GenericAll/WriteDacl su oggetti sensibili, diritti DCSync), in violazione del principio del minimo privilegio.

## Impatto

La compromissione di un qualsiasi account con privilegi eccessivi equivale alla compromissione del dominio: l'ampiezza della superficie privilegiata moltiplica le probabilità che un attacco a un singolo utente diventi un incidente critico.

## Remediation

Ridurre l'appartenenza ai gruppi privilegiati al minimo indispensabile, revisionare le ACL sugli oggetti sensibili (BloodHound), adottare un modello a tier con account separati per amministrazione e uso quotidiano e istituire revisioni periodiche dei privilegi.
