---
title: "Database KeePass con master password debole"
aliases:
  - "keepass"
  - "kdbx"
  - "keepass weak password"
  - "password manager"
category: "Identità"
cwe: "521"
cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1555.005"
refs:
  - "https://keepass.info/help/base/security.html"
---

## Descrizione

È stato individuato un database KeePass (file .kdbx) la cui master password è presente in wordlist pubbliche: il crack offline dell'hash della master password ha richiesto pochi secondi, esponendo l'intero contenuto del gestore di password.

## Impatto

Il contenuto integrale del password manager è stato compromesso: credenziali amministrative, password di servizi interni ed esterni e note riservate, con possibile elevazione dei privilegi e compromissione di ulteriori sistemi.

## Remediation

Sostituire la master password con una passphrase lunga e non presente in dizionari noti, valutare l'uso di un key file aggiuntivo, cambiare tutte le credenziali contenute nel database compromesso, non archiviare database di password su workstation condivise e preferire cassaforti centralizzate con controllo degli accessi.
