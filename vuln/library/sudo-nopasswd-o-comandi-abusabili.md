---
title: "Privilegi sudo eccessivi (NOPASSWD o comandi abusabili)"
aliases:
  - "sudo"
  - "sudoers"
  - "nopasswd"
  - "sudo -l"
  - "sudo misconfigurato"
category: "Sistemi"
cwe: "266"
cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1548.003"
refs:
  - "https://gtfobins.github.io/"
  - "https://attack.mitre.org/techniques/T1548/003/"
---

## Descrizione

Il file /etc/sudoers concede a utenti non amministrativi l'esecuzione come root (spesso con NOPASSWD) di comandi che possono essere abusati per ottenere una shell o scrivere file privilegiati: binari con -exec (find), editor (vi, nano, less), interpreti (python, perl, awk), tar/zip con checkpoint-action, ecc.

## Impatto

Un attaccante con accesso locale limitato eleva i privilegi a root senza conoscere password, ottenendo il controllo completo del sistema e la possibilità di persistenza e movimento laterale.

## Remediation

Applicare il principio del minimo privilegio in sudoers: rimuovere le regole NOPASSWD non indispensabili, evitare comandi abusabili (verificarli su GTFOBins), preferire regole con argomenti vincolati e NOEXEC, e monitorare sudo -l su tutti gli account.

## Verifica

sudo -l elenca i comandi consentiti; ogni voce va confrontata con GTFOBins per verificare se consente escalation (es. (ALL) NOPASSWD: /usr/bin/find -> sudo find . -exec /bin/sh \; -quit).
