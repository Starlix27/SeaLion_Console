---
title: "Unquoted Service Path"
aliases:
  - "unquoted service path"
  - "percorso servizio senza virgolette"
category: "Windows"
cwe: "428"
cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1574.009"
refs:
  - "https://attack.mitre.org/techniques/T1574/009/"
---

## Descrizione

Il percorso dell'eseguibile di uno o più servizi Windows contiene spazi e non è racchiuso tra virgolette: Windows tenta l'esecuzione dei file nei percorsi intermedi (es. C:\Program.exe) prima di quello corretto, e le directory interessate sono scrivibili da utenti non privilegiati.

## Impatto

Un utente non privilegiato può collocare un eseguibile malevolo in uno dei percorsi intermedi: al riavvio del servizio (o del sistema) il codice viene eseguito con i privilegi del servizio, tipicamente SYSTEM, realizzando una privilege escalation.

## Remediation

Correggere le chiavi di registro dei servizi racchiudendo il percorso tra virgolette, verificare che le directory dei percorsi non siano scrivibili da utenti standard e auditare periodicamente i servizi con unquoted path (es. con PowerUp o WinPEAS).
