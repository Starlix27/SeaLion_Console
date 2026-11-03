---
title: "Appartenenza a gruppi privilegiati (docker, lxd, disk, adm)"
aliases:
  - "docker group"
  - "lxd"
  - "docker privesc"
  - "gruppo docker"
  - "disk group"
category: "Sistemi"
cwe: "250"
cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1078"
refs:
  - "https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-privilege-escalation.html"
---

## Descrizione

Account di servizio o utenti standard appartengono a gruppi che equivalgono di fatto a root: docker permette di montare il filesystem host in un container privilegiato, lxd/lxc di creare container con privilegi completi, disk di leggere i device a blocchi (incluso /etc/shadow), adm di leggere tutti i log di sistema.

## Impatto

Privilege escalation immediata a root senza exploit: chi controlla un utente nel gruppo docker o lxd ottiene una shell root sull'host in pochi secondi, vanificando la segregazione dei privilegi.

## Remediation

Limitare l'appartenenza ai gruppi privilegiati ai soli account strettamente necessari, usare Docker rootless o socket con accesso ristretto, e auditare regolarmente le appartenenze (getent group docker lxd disk adm).

## Verifica

id o getent group docker mostrano le appartenenze; la via classica di verifica è docker run -v /:/mnt --rm -it alpine chroot /mnt sh.
