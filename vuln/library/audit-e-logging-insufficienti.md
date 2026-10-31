---
title: "Audit e logging insufficienti"
aliases:
  - "logging"
  - "audit insufficiente"
  - "log mancanti"
category: "Sistemi"
cwe: "778"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
severity: "info"
mitre:
  - "T1562"
refs:
  - "https://www.cisa.gov/resources-tools/resources/best-practices-for-event-logging-and-threat-detection"
---

## Descrizione

La raccolta e la conservazione dei log sono insufficienti: eventi di autenticazione, esecuzione di processi e modifiche amministrative non vengono registrati o vengono sovrascritti rapidamente, senza raccolta centralizzata né monitoraggio.

## Impatto

In assenza di logging adeguato le attività malevole non vengono rilevate né possono essere ricostruite in fase di incident response: gli attaccanti possono operare a lungo nell'ambiente senza lasciare evidenze utili.

## Remediation

Definire una policy di logging (autenticazioni, privilege use, process creation, PowerShell, modifiche AD), centralizzare i log su un SIEM/syslog protetto con retention adeguata, configurare alerting sugli eventi critici e verificare periodicamente la copertura.
