---
title: "FTP con accesso anonimo / credenziali in chiaro"
aliases:
  - "ftp anonimo"
  - "anonymous ftp"
  - "ftp"
  - "protocollo in chiaro"
category: "Rete"
cwe: "319"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
severity: "high"
mitre:
  - "T1078"
  - "T1040"
refs:
  - "https://attack.mitre.org/techniques/T1040/"
---

## Descrizione

Il server FTP consente l'accesso anonimo (o con credenziali deboli) e trasmette credenziali e dati in chiaro sulla rete: le informazioni scambiate sono intercettabili da chiunque abbia visibilità sul segmento.

## Impatto

Accesso non autorizzato ai file pubblicati e intercettazione di credenziali e dati tramite sniffing del traffico, con possibile compromissione dei sistemi che riutilizzano le stesse credenziali.

## Remediation

Disabilitare l'accesso anonimo, sostituire FTP con SFTP/FTPS (canale cifrato), limitare l'accesso ai soli host autorizzati e verificare i log per accessi pregressi non autorizzati.
