---
title: "Segmentazione di rete insufficiente"
aliases:
  - "flat network"
  - "segmentazione"
  - "network segmentation"
category: "Rete"
cwe: "923"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
severity: "info"
mitre:
  - "T1021"
refs:
  - "https://www.cisa.gov/resources-tools/resources/layering-network-security-through-segmentation"
---

## Descrizione

La rete interna è piatta: workstation, server e servizi di gestione sono reciprocamente raggiungibili senza filtri, permettendo a un singolo host compromesso di raggiungere qualsiasi altro sistema dell'infrastruttura.

## Impatto

L'assenza di segmentazione rende il movimento laterale banale: la compromissione di una singola postazione può propagarsi rapidamente a server, dominio e sistemi critici, amplificando l'impatto di ogni incidente.

## Remediation

Segmentare la rete in zone con filtri tra i segmenti (VLAN, firewall interni), separare utenti/server/management/IoT, applicare il principio del minimo accesso tra zone e monitorare i flussi inter-segmento.
