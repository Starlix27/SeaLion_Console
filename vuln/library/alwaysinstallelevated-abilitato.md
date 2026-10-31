---
title: "AlwaysInstallElevated abilitato"
aliases:
  - "alwaysinstallelevated"
  - "msi elevate"
category: "Windows"
cwe: "732"
cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1548.002"
refs:
  - "https://attack.mitre.org/techniques/T1548/002/"
---

## Descrizione

Le chiavi di registro AlwaysInstallElevated sono impostate a 1 sia in HKLM sia in HKCU: qualsiasi pacchetto MSI lanciato da un utente standard viene installato con privilegi SYSTEM.

## Impatto

Un utente non privilegiato può generare un MSI malevolo e installarlo ottenendo l'esecuzione di codice come SYSTEM: privilege escalation immediata.

## Remediation

Rimuovere o impostare a 0 le chiavi AlwaysInstallElevated in HKLM e HKCU su tutti i sistemi tramite GPO.
