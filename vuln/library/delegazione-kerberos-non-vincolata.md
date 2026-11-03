---
title: "Delegazione Kerberos non vincolata su account macchina/servizio"
aliases:
  - "unconstrained delegation"
  - "delegazione non vincolata"
  - "kerberos delegation"
  - "printer bug"
category: "Active Directory"
cwe: "522"
cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1558.003"
refs:
  - "https://attack.mitre.org/techniques/T1558/003/"
  - "https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/kerberos-authentication.html"
---

## Descrizione

Un account macchina o di servizio è configurato con delegazione non vincolata (TrustedForDelegation): il sistema memorizza i TGT degli utenti che si autenticano e può impersonarli verso qualunque servizio. Chi compromette l'host può estrarre i ticket, eventualmente forzando l'autenticazione di account privilegiati (printer bug, PetitPotam).

## Impatto

Cattura e riuso dei ticket TGT di qualunque utente si autentichi al sistema, incluse eventuali credenziali di Domain Admin: escalation fino alla compromissione completa del dominio Active Directory.

## Remediation

Rimuovere la delegazione non vincolata dove non strettamente necessaria, preferire delegazione vincolata o basata su risorse (RBCD), proteggere gli account privilegiati con 'Account is sensitive and cannot be delegated' e Protected Users, e monitorare le modifiche agli attributi di delegazione.

## Verifica

PowerView: Get-DomainComputer -Unconstrained e Get-DomainUser -TrustedToAuth; BloodHound evidenzia i nodi con delegazione non vincolata nei percorsi di attacco verso Domain Admin.
