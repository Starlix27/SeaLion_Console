---
title: "Documentazione API esposta (Swagger/OpenAPI, GraphQL introspection)"
aliases:
  - "swagger"
  - "openapi"
  - "graphql"
  - "introspection"
  - "api docs"
  - "api-docs"
category: "Web"
cwe: "200"
cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
severity: "low"
mitre:
  - "T1592"
refs:
  - "https://owasp.org/www-project-api-security/"
---

## Descrizione

Interfacce di documentazione API (Swagger UI, /openapi.json, /api-docs) o la GraphQL introspection sono raggiungibili in produzione senza autenticazione: espongono l'elenco completo di endpoint, parametri e schemi dati, incluse operazioni amministrative o deprecate non linkate dal frontend.

## Impatto

Un attaccante ottiene la mappa completa della superficie API senza enumeration: può mirare direttamente endpoint nascosti, parametri sensibili e operazioni privilegiate, aumentando l'efficacia di attacchi BOLA/IDOR e injection.

## Remediation

Disabilitare Swagger UI e GraphQL introspection in produzione (o proteggerli con autenticazione forte), pubblicare la documentazione solo su ambienti interni e mantenere l'inventario degli endpoint allineato a quanto effettivamente esposto.

## Verifica

Accesso diretto a /swagger, /swagger-ui, /openapi.json, /graphql (query introspection { __schema { types { name } } }) e confronto degli endpoint scoperti con quelli documentati.
