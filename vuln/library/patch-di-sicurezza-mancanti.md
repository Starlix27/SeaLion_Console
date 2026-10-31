---
title: "Patch di sicurezza mancanti"
aliases:
  - "missing patches"
  - "patch mancanti"
  - "hotfix mancanti"
category: "Sistemi"
cwe: "1104"
cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1190"
refs:
  - "https://learn.microsoft.com/it-it/windows/deployment/update/"
---

## Descrizione

Il sistema risulta privo di numerosi aggiornamenti di sicurezza rilasciati dal vendor: dalla versione/build rilevata mancano cumulative e hotfix critici degli ultimi anni.

## Impatto

Le falle note e non corrette sono sfruttabili con exploit pubblici per accesso remoto ed escalation di privilegio: il sistema non resiste ad attaccanti che utilizzino strumenti offensivi comunemente disponibili.

## Remediation

Installare gli aggiornamenti cumulativi mancanti dopo test di compatibilità, automatizzare la distribuzione delle patch (WSUS/MDM), definire SLA di patching in base alla criticità e verificare periodicamente la conformità con vulnerability assessment.
