---
title: "Jenkins Script Console accessibile"
aliases:
  - "jenkins"
  - "script console"
  - "jenkins rce"
  - "groovy console"
category: "Applicazioni"
cwe: "94"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "critical"
mitre:
  - "T1190"
  - "T1059"
refs:
  - "https://www.jenkins.io/doc/book/security/access-control/"
  - "https://www.jenkins.io/doc/book/managing/script-console/"
---

## Descrizione

L'istanza Jenkins espone la Script Console (Groovy) o le pagine di amministrazione a utenti anonimi o non autorizzati: la console esegue codice Groovy direttamente sul server Jenkins con i privilegi del suo account di servizio.

## Impatto

Esecuzione remota di codice sul server CI/CD: accesso a credenziali e segreti dei job, modifica delle pipeline, furto di artefatti e pivoting verso tutti i sistemi raggiunti dal server di build — tipicamente un nodo ad alta fiducia dell'infrastruttura.

## Remediation

Abilitare immediatamente l'autenticazione (security realm) e l'autorizzazione basata su ruoli, reimpostare le credenziali potenzialmente compromesse, aggiornare Jenkins a una versione supportata e limitare l'esposizione di rete del servizio ai soli sistemi autorizzati.
