---
title: "Header di sicurezza HTTP mancanti"
aliases:
  - "security headers"
  - "header mancanti"
  - "hsts"
  - "content security policy"
category: "Web"
cwe: "693"
cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"
severity: "medium"
refs:
  - "https://owasp.org/www-project-secure-headers/"
  - "https://securityheaders.com/"
---

## Descrizione

Le risposte HTTP dell'applicazione non includono uno o più header di sicurezza raccomandati: Strict-Transport-Security (HSTS), Content-Security-Policy, X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy e Permissions-Policy.

## Impatto

L'assenza degli header espone gli utenti ad attacchi lato client: downgrade a HTTP e intercettazione (senza HSTS), esecuzione di script non autorizzati (senza CSP), clickjacking (senza frame-ancestors) e MIME sniffing, che amplificano l'impatto di altre vulnerabilità.

## Remediation

Configurare sul server web / reverse proxy gli header di sicurezza: HSTS con max-age elevato (ed eventualmente preload), CSP restrittiva e progressivamente raffinata, X-Content-Type-Options: nosniff, frame-ancestors per prevenire il clickjacking, Referrer-Policy e Permissions-Policy minimi.
