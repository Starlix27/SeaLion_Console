---
title: "Firma SMB non richiesta"
aliases:
  - "smb signing"
  - "firma smb"
  - "smb relay"
  - "ntlm relay"
category: "Rete"
cwe: "300"
cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
severity: "high"
mitre:
  - "T1557.001"
refs:
  - "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing"
---

## Descrizione

I server SMB non richiedono la firma dei pacchetti (signing non obbligatorio): un attaccante in posizione man-in-the-middle nella rete interna può rigirare le autenticazioni NTLM catturate verso questi host (SMB/NTLM relay).

## Impatto

Gli attacchi di relay permettono di autenticarsi ai server con le credenziali catturate ad altri utenti: se la vittima ha privilegi amministrativi sul target, l'attaccante ottiene esecuzione di codice remota e compromette l'host senza conoscere alcuna password.

## Remediation

Richiedere la firma SMB su server e workstation tramite GPO (Microsoft network server: Digitally sign communications - Always), disabilitare NTLMv1, abilitare EPA/channel binding su LDAP e segmentare la rete per ridurre le posizioni di ascolto.
