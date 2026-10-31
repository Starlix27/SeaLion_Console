---
title: "Condivisioni di rete con accesso anonimo / permessi eccessivi"
aliases:
  - "writable share"
  - "condivisioni"
  - "smb share"
  - "anonymous share"
  - "condivisione anonima"
category: "Rete"
cwe: "732"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
severity: "high"
mitre:
  - "T1135"
refs:
  - "https://attack.mitre.org/techniques/T1135/"
---

## Descrizione

Sono state individuate condivisioni di rete accessibili in lettura o scrittura senza autenticazione o con permessi eccessivi (Everyone: lettura/scrittura), contenenti dati aziendali, script o file di configurazione.

## Impatto

Accesso non autorizzato a dati riservati (documenti, backup, configurazioni con credenziali) e, per le condivisioni scrivibili, possibilità di depositare malware o modificare script eseguiti da altri utenti/servizi, con conseguente esecuzione di codice.

## Remediation

Rivedere i permessi delle condivisioni applicando il minimo privilegio (gruppi specifici, lettura/scrittura solo dove necessario), eliminare l'accesso anonimo e a Everyone, auditare periodicamente le share e monitorare gli accessi anomali.
