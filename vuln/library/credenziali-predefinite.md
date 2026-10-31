---
title: "Credenziali predefinite"
aliases:
  - "default credentials"
  - "default password"
  - "credenziali di default"
category: "Web"
cwe: "798"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "critical"
mitre:
  - "T1078.001"
refs:
  - "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"
---

## Descrizione

Il servizio è accessibile con le credenziali predefinite del produttore (es. admin/admin, admin/password), mai modificate dopo l'installazione: l'accesso amministrativo è di pubblico dominio.

## Impatto

Accesso amministrativo immediato e completo al servizio o al dispositivo, con possibilità di modifica delle configurazioni, accesso ai dati e — frequente su applicazioni di gestione — esecuzione di codice sul sistema.

## Remediation

Modificare immediatamente tutte le credenziali predefinite con password robuste e univoche, disabilitare gli account non necessari, verificare nei log eventuali accessi pregressi non autorizzati e includere il cambio password nelle procedure di hardening iniziale.
