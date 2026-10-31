---
title: "Kerberoasting"
aliases:
  - "kerberoasting"
  - "spn"
  - "tgs"
  - "service ticket"
category: "Active Directory"
cwe: "327"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1558.003"
refs:
  - "https://attack.mitre.org/techniques/T1558/003/"
---

## Descrizione

Gli account di servizio con Service Principal Name (SPN) registrato utilizzano password deboli o cifratura RC4: qualsiasi utente di dominio autenticato può richiedere ticket di servizio (TGS) per questi SPN e crackarne offline l'hash per recuperare la password dell'account.

## Impatto

Le password degli account di servizio — spesso con privilegi elevati e mai modificate — vengono recuperate offline senza interazioni con il target e senza allarmi: il cracking di un singolo account di servizio privilegiato può portare alla compromissione del dominio.

## Remediation

Impostare password lunghe e casuali (25+ caratteri) per gli account di servizio, preferendo gMSA (Group Managed Service Accounts), disabilitare la cifratura RC4 a favore di AES, ridurre i privilegi degli SPN e monitorare le richieste TGS anomale (Event ID 4769 con RC4).
