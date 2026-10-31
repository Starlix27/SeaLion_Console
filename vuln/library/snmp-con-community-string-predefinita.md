---
title: "SNMP con community string predefinita"
aliases:
  - "snmp"
  - "public community"
  - "snmp default"
  - "community string"
category: "Rete"
cwe: "798"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
severity: "high"
mitre:
  - "T1040"
  - "T1592"
refs:
  - "https://attack.mitre.org/techniques/T1592/"
---

## Descrizione

I dispositivi di rete rispondono a richieste SNMP con community string predefinite ('public' in lettura, 'private' in scrittura): è possibile enumerare configurazioni, interfacce, VLAN, tabelle ARP e, con accesso in scrittura, modificare la configurazione dei dispositivi.

## Impatto

Esposizione di informazioni dettagliate sulla rete (utile a mappare l'infrastruttura e pianificare attacchi) e, se la community di scrittura è attiva, riconfigurazione non autorizzata dei dispositivi con impatto su disponibilità e riservatezza.

## Remediation

Disabilitare SNMPv1/v2c a favore di SNMPv3 (autenticazione e cifratura), modificare le community string con valori robusti dove v2c è indispensabile, limitare l'accesso SNMP ai soli sistemi di monitoring tramite ACL e disabilitare la scrittura.
