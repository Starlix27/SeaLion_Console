---
title: "Privilege escalation via SeImpersonatePrivilege (famiglia Potato)"
aliases:
  - "rottenpotato"
  - "rotten potato"
  - "juicypotato"
  - "juicy potato"
  - "potato"
  - "seimpersonateprivilege"
  - "printspoofer"
  - "sweetpotato"
  - "godpotato"
category: "Windows"
cwe: "269"
cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1134.001"
  - "T1068"
refs:
  - "https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/"
  - "https://github.com/ohpe/juicy-potato"
  - "https://attack.mitre.org/techniques/T1134/001/"
---

## Descrizione

L'account di servizio con cui è stato ottenuto l'accesso dispone del privilegio SeImpersonatePrivilege (assegnato di default a IIS, SQL Server, Local Service e altri servizi): su sistemi Windows non aggiornati questo privilegio è sfruttabile con le tecniche della famiglia 'Potato' (RottenPotato, Juicy Potato, PrintSpoofer, SweetPotato, GodPotato) per impersonare token SYSTEM.

## Impatto

Un attaccante con accesso limitato (tipicamente come account di servizio dopo una compromissione web) può elevarsi a NT AUTHORITY\SYSTEM, ottenendo il controllo completo dell'host: è una delle vie di privilege escalation più affidabili su Windows non aggiornato.

## Remediation

Mantenere i sistemi aggiornati (le versioni recenti di Windows hanno mitigato la maggior parte delle varianti), ridurre al minimo gli account con SeImpersonatePrivilege, eseguire i servizi con account a privilegi minimi e monitorare la creazione di named pipe e i log di impersonation.
