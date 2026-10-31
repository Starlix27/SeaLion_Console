---
title: "Software obsoleto / End-of-Life"
aliases:
  - "outdated"
  - "obsolete"
  - "eol"
  - "end of life"
  - "versione obsoleta"
  - "software non aggiornato"
category: "Sistemi"
cwe: "1104"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "critical"
mitre:
  - "T1190"
refs:
  - "https://endoflife.date/"
---

## Descrizione

Sono in uso versioni di sistemi operativi o applicativi non più supportate dal vendor (End-of-Life) o prive degli aggiornamenti di sicurezza recenti: le vulnerabilità note per queste versioni non riceveranno patch.

## Impatto

Il sistema è esposto a vulnerabilità note con exploit pubblici e maturi: la mancanza di patch facilita sia l'accesso iniziale sia l'escalation di privilegio, rendendo la compromissione alla portata di attaccanti con bassa competenza.

## Remediation

Pianificare l'aggiornamento a versioni supportate, installare gli aggiornamenti di sicurezza mancanti, introdurre un processo di patch management con verifica periodica della copertura e, per i sistemi non aggiornabili, applicare misure compensative (isolamento di rete, monitoraggio).
