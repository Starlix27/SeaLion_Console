---
title: "Cron job scrivibile / wildcard injection in script privilegiati"
aliases:
  - "cron"
  - "crontab"
  - "cronjob"
  - "wildcard injection"
  - "tar wildcard"
  - "script scrivibile"
category: "Sistemi"
cwe: "732"
cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1053.003"
refs:
  - "https://attack.mitre.org/techniques/T1053/003/"
  - "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html"
---

## Descrizione

Un cron job eseguito con privilegi elevati referenzia uno script o un percorso scrivibile da utenti non privilegiati, oppure usa wildcard (es. tar *) in directory scrivibili: un utente locale può modificare lo script eseguito da root o iniettare opzioni tramite file con nomi che iniziano per -- (es. --checkpoint-action=exec=...).

## Impatto

Esecuzione di codice arbitrario con i privilegi dell'owner del cron job (spesso root) a intervalli regolari: privilege escalation e persistenza garantita sul sistema.

## Remediation

Correggere ownership e permessi di script e directory referenziati dai cron job (root:root, non scrivibili), evitare wildcard nei comandi privilegiati o usarle con -- e path assoluti, e revisionare periodicamente /etc/crontab, /etc/cron.* e le crontab utente.

## Verifica

Ispezionare /etc/crontab e /etc/cron.d, identificare gli script eseguiti come root e verificarne i permessi (ls -l); tool automatici come pspy mostrano i job in esecuzione con i relativi UID.
