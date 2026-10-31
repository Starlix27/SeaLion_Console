---
title: "Esportazioni NFS accessibili"
aliases:
  - "nfs"
  - "nfs export"
  - "showmount"
category: "Rete"
cwe: "732"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
severity: "high"
mitre:
  - "T1135"
refs:
  - "https://attack.mitre.org/techniques/T1135/"
---

## Descrizione

Le esportazioni NFS sono montabili da host non autorizzati o con opzioni insicure (no_root_squash): è possibile accedere ai file system condivisi e, con no_root_squash, operare con privilegi di root sul contenuto.

## Impatto

Lettura di dati sensibili e, in presenza di no_root_squash, caricamento di file con bit SUID o modifica di file di sistema sul server NFS, con conseguente compromissione completa del server.

## Remediation

Limitare le esportazioni ai soli client autorizzati, abilitare root_squash (default) ed eventualmente all_squash, esportare in sola lettura dove possibile e proteggere il servizio con firewall.
