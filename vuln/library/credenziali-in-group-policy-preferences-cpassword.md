---
title: "Credenziali in Group Policy Preferences (cpassword)"
aliases:
  - "gpp"
  - "cpassword"
  - "group policy preferences"
category: "Active Directory"
cwe: "256"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1552.006"
refs:
  - "https://attack.mitre.org/techniques/T1552/006/"
  - "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2014-1812"
---

## Descrizione

Nei file XML delle Group Policy Preferences su SYSVOL sono presenti campi cpassword: la chiave AES usata per cifrare queste password è pubblica (documentata da Microsoft), quindi qualsiasi utente di dominio può decifrarle.

## Impatto

Le password decifrate sono tipicamente credenziali di amministratori locali distribuite via GPP: il loro recupero fornisce accesso amministrativo immediato a tutti i sistemi che ricevono la policy.

## Remediation

Rimuovere i file XML con cpassword da SYSVOL, cambiare tutte le password distribuite storicamente via GPP, usare LAPS per la gestione delle password amministrative locali e applicare la patch MS14-025 sui sistemi legacy.
