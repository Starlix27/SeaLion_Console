---
title: "Permessi deboli su servizi / binary Windows"
aliases:
  - "weak service permissions"
  - "service misconfiguration"
  - "permessi servizi"
category: "Windows"
cwe: "732"
cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1574.010"
  - "T1574.011"
refs:
  - "https://attack.mitre.org/techniques/T1574/010/"
  - "https://attack.mitre.org/techniques/T1574/011/"
---

## Descrizione

Uno o più servizi Windows hanno ACL troppo permissive (modifica della configurazione del servizio o del binario eseguito concesse a utenti standard): un utente non privilegiato può sostituire l'eseguibile o riconfigurare il percorso del binario.

## Impatto

Al riavvio del servizio il codice dell'attaccante viene eseguito con i privilegi del servizio (tipicamente SYSTEM): privilege escalation affidabile e persistente sull'host.

## Remediation

Correggere le ACL dei servizi e dei rispettivi binari limitando la modifica ai soli amministratori, auditare periodicamente i permessi (sc sdshow, accesschk) e applicare hardening baseline sui sistemi.
