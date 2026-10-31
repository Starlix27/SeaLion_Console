---
title: "RDP esposto senza protezioni adeguate"
aliases:
  - "rdp"
  - "remote desktop"
  - "nla"
  - "bluekeep"
category: "Rete"
cwe: "284"
cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1021.001"
refs:
  - "https://learn.microsoft.com/en-us/troubleshoot/windows-client/remote/understanding-remote-desktop-services"
---

## Descrizione

Il servizio Remote Desktop è raggiungibile dalla rete senza controlli adeguati: NLA non richiesto, assenza di limitazioni per indirizzo sorgente e protezioni anti brute-force, su una versione potenzialmente soggetta a vulnerabilità note del protocollo.

## Impatto

L'esposizione di RDP consente attacchi di brute force e password spraying sugli account, sfruttamento di vulnerabilità del protocollo (storicamente critiche, es. BlueKeep) e accesso interattivo diretto ai sistemi.

## Remediation

Limitare l'accesso RDP ai soli indirizzi autorizzati (firewall, VPN, gateway RDP), richiedere NLA e MFA, abilitare lockout e monitoraggio dei tentativi di accesso, mantenere aggiornato il servizio e valutare alternative con accesso brokerato.
