---
title: "Capabilities Linux pericolose assegnate a binari"
aliases:
  - "capabilities"
  - "cap_setuid"
  - "getcap"
  - "linux capabilities"
category: "Sistemi"
cwe: "250"
cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1548.001"
refs:
  - "https://gtfobins.github.io/"
  - "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html"
---

## Descrizione

A binari ordinari sono state assegnate capabilities granulari ma abusabili (cap_setuid, cap_setgid, cap_sys_admin, cap_dac_read_search, cap_dac_override): un interprete con cap_setuid può impostare UID 0, un binario con cap_dac_read_search legge qualunque file ignorando i permessi.

## Impatto

Privilege escalation a root o lettura/scrittura di file arbitrari da parte di utenti senza privilegi, aggirando il modello permessi tradizionale e i controlli basati solo su SUID.

## Remediation

Rimuovere le capabilities non necessarie (setcap -r), mantenere un inventario delle capabilities assegnate, e includere getcap -r / nei controlli di hardening periodici.

## Verifica

getcap -r / 2>/dev/null elenca binari e capabilities; ogni combinazione va confrontata con GTFOBins (es. python con cap_setuid -> python3 -c 'import os; os.setuid(0); os.system("/bin/sh")').
