---
title: "Enumerazione degli utenti"
aliases:
  - "user enumeration"
  - "enumerazione utenti"
  - "username enumeration"
category: "Web"
cwe: "204"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
severity: "medium"
mitre:
  - "T1087"
refs:
  - "https://owasp.org/www-community/attacks/"
---

## Descrizione

L'applicazione permette di distinguere utenti esistenti da utenti inesistenti: messaggi di errore diversi nel login/reset password, risposte con tempi diversi o endpoint che espongono elenchi di account.

## Impatto

L'enumerazione fornisce all'attaccante una lista di username validi, prerequisito per attacchi mirati di password spraying e phishing: dimezza lo sforzo di indovinare le credenziali.

## Remediation

Uniformare messaggi e tempi di risposta delle funzioni di login/recupero/registrazione, non esporre elenchi di utenti e monitorare i pattern di enumerazione.
