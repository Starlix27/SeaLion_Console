---
title: "Pass-the-Hash / riutilizzo di hash NTLM"
aliases:
  - "pass the hash"
  - "pth"
  - "ntlm hash"
  - "pass-the-hash"
category: "Active Directory"
cwe: "522"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "critical"
mitre:
  - "T1550.002"
refs:
  - "https://attack.mitre.org/techniques/T1550/002/"
  - "https://learn.microsoft.com/en-us/security/compass/privileged-access-access-model"
---

## Descrizione

Gli hash NTLM delle password, recuperati da database, memoria o file di un sistema compromesso, possono essere riutilizzati direttamente per autenticarsi ad altri sistemi (pass-the-hash) senza conoscere la password in chiaro, a causa del supporto dell'autenticazione NTLM.

## Impatto

Un singolo hash amministrativo recuperato su un host compromesso consente l'accesso a tutti i sistemi dove quell'account ha privilegi: il movimento laterale diventa immediato e difficile da rilevare.

## Remediation

Ridurre l'esposizione degli hash: disabilitare NTLMv1 e limitare NTLM dove possibile a favore di Kerberos, implementare LAPS per le password amministrative locali, proteggere gli account privilegiati con tiering (no logon interattivo su sistemi meno fidati), abilitare Credential Guard e monitorare gli accessi anomali.
