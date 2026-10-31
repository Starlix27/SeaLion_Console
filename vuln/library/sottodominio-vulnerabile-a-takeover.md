---
title: "Sottodominio vulnerabile a takeover"
aliases:
  - "subdomain takeover"
  - "dangling dns"
  - "cname dangling"
category: "Web"
cwe: "1104"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
severity: "high"
mitre:
  - "T1584.001"
refs:
  - "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"
---

## Descrizione

Un record DNS (tipicamente CNAME) punta a un servizio esterno dismesso o non più registrato (cloud, hosting, SaaS): chiunque può registrare la risorsa puntata e servire contenuti dal sottodominio dell'organizzazione.

## Impatto

Il controllo di un sottodominio legittimo permette phishing credibile, furto di cookie a scope ampio e bypass di policy basate su dominio, sfruttando la fiducia degli utenti nel dominio del Cliente.

## Remediation

Rimuovere i record DNS che puntano a risorse dismesse, verificare periodicamente che i CNAME puntino a risorse attive e controllate e includere il controllo DNS nelle procedure di deprovisioning.
