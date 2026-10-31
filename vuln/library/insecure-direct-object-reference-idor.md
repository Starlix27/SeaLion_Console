---
title: "Insecure Direct Object Reference (IDOR)"
aliases:
  - "idor"
  - "broken object level authorization"
  - "bola"
  - "access control"
category: "Web"
cwe: "639"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
severity: "high"
mitre:
  - "T1190"
refs:
  - "https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference"
  - "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
---

## Descrizione

L'applicazione espone riferimenti diretti a oggetti interni (ID numerici, nomi file, chiavi) e non verifica che l'utente autenticato sia autorizzato ad accedere alla risorsa richiesta: modificando l'identificativo è possibile accedere a dati di altri utenti.

## Impatto

Accesso orizzontale o verticale a dati e funzioni non autorizzate: lettura/modifica di documenti, ordini e profili di altri utenti, con violazione massiva della riservatezza e possibile acquisizione di account.

## Remediation

Verificare lato server, per ogni richiesta, che l'utente sia autorizzato sull'oggetto specifico (controllo a livello di oggetto), usare identificativi indiretti non predicibili (UUID) e implementare test di autorizzazione automatici nelle regressioni.
