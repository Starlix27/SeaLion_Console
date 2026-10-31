---
title: "LLMNR / NBT-NS / mDNS poisoning"
aliases:
  - "llmnr"
  - "nbt-ns"
  - "netbios"
  - "poisoning"
  - "responder"
category: "Rete"
cwe: "290"
cvss_vector: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
severity: "high"
mitre:
  - "T1557.001"
refs:
  - "https://attack.mitre.org/techniques/T1557/001/"
  - "https://www.cisa.gov/news-events/alerts/2017/04/14/microsoft-releases-security-updates"
---

## Descrizione

I protocolli di risoluzione nomi broadcast LLMNR e NBT-NS sono abilitati sugli host Windows: un attaccante presente nel segmento di rete può rispondere alle richieste con il proprio indirizzo (tool Responder), inducendo le vittime a inviargli hash delle credenziali.

## Impatto

Gli hash NTLM catturati possono essere crackati offline (recuperando la password in chiaro) o rigirati con attacchi di relay verso altri sistemi, portando alla compromissione di account utente e, in scenari favorevoli, di account amministrativi.

## Remediation

Disabilitare LLMNR e NBT-NS su tutti gli host tramite GPO, richiedere la firma SMB, disabilitare NTLMv1, correggere le cause delle risoluzioni fallite (DNS) e segmentare la rete per contenere i broadcast.
