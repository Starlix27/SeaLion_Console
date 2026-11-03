---
title: "Privilege Escalation via binario SUID/SGID misconfigurato"
aliases:
  - "suid"
  - "sgid"
  - "suid binary"
  - "gtfobins"
  - "suid misconfigurato"
  - "find suid"
category: "Sistemi"
cwe: "250"
cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1548.001"
refs:
  - "https://gtfobins.github.io/"
  - "https://attack.mitre.org/techniques/T1548/001/"
---

## Descrizione

Un binario di sistema ha il bit SUID (o SGID) attivo ed è di proprietà di root: il kernel lo esegue con i privilegi del proprietario indipendentemente dall'utente che lo lancia. Se il binario espone funzionalità abusabili (es. find con -exec, editor, linguaggi interpretati, cp/tar), un utente con accesso locale limitato può eseguire comandi come root.

## Impatto

Escalation verticale dei privilegi fino a root: esecuzione di codice arbitrario con i massimi privilegi, lettura di qualunque file del sistema (incluse /etc/shadow e flag/file riservati) e compromissione completa della macchina.

## Remediation

Rimuovere il bit SUID/SGID dai binari che non lo richiedono (chmod u-s), mantenere una whitelist minima di binari SUID, monitorare periodicamente il filesystem con find / -perm -4000 e applicare mount option nosuid dove possibile.

## Verifica

find / -perm -4000 -type f 2>/dev/null elenca i binari SUID; confrontarli con GTFOBins e verificare lo sfruttamento, es. sudo find . -exec /bin/sh \; -quit per un find con SUID o permesso sudo NOPASSWD.
