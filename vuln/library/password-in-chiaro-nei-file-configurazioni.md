---
title: "Password in chiaro nei file / configurazioni"
aliases:
  - "cleartext credentials"
  - "password in chiaro"
  - "hardcoded password"
  - "credenziali hardcoded"
category: "Sistemi"
cwe: "256"
cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1552.001"
refs:
  - "https://attack.mitre.org/techniques/T1552/001/"
---

## Descrizione

Sono state individuate password e segreti in chiaro in file accessibili: script, file di configurazione, documenti, cronologie di shell o file unattended di installazione (es. unattend.xml).

## Impatto

Le credenziali esposte permettono l'accesso diretto ai sistemi e servizi associati: un singolo file dimenticato può compromettere account amministrativi e propagare l'attacco ad altri sistemi.

## Remediation

Rimuovere le credenziali dai file, ruotare immediatamente quelle esposte, migrare i segreti verso un vault centralizzato, bonificare la history dei sistemi di versionamento e introdurre controlli automatici (secret scanning) nei processi di sviluppo.
