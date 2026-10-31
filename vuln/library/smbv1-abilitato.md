---
title: "SMBv1 abilitato"
aliases:
  - "smbv1"
  - "smb1"
  - "smb v1"
  - "eternalblue"
  - "wannacry"
category: "Rete"
cwe: "327"
cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1021.002"
refs:
  - "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"
---

## Descrizione

Il servizio SMB supporta ancora il dialect SMBv1, protocollo obsoleto privo di protezioni moderne (nessuna crittografia, firma debole, meccanismi vulnerabili storicamente a exploit come EternalBlue/WannaCry).

## Impatto

SMBv1 mantiene esposta una superficie di attacco obsoleta: su sistemi non aggiornati consente esecuzione remota di codice, e in ogni caso facilita attacchi man-in-the-middle e di relay delle autenticazioni nella rete interna.

## Remediation

Disabilitare SMBv1 su server e client (Set-SmbServerConfiguration -EnableSMB1Protocol $false / GPO), verificare preventivamente che nessuna applicazione legacy dipenda dal protocollo e monitorare la rete per tentativi di negoziazione SMBv1.
