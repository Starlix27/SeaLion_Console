---
title: "Deserializzazione insicura"
aliases:
  - "insecure deserialization"
  - "deserializzazione"
  - "ysoserial"
  - "pickle"
  - "viewstate"
category: "Web"
cwe: "502"
cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1190"
refs:
  - "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"
  - "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
---

## Descrizione

L'applicazione deserializza dati controllati dall'attaccante con formati/librerie che istanziano oggetti arbitrari (es. Java serialization, .NET ViewState, PHP unserialize, Python pickle): catene di gadget presenti nelle librerie in uso permettono di ottenere effetti critici alla deserializzazione.

## Impatto

La deserializzazione di dati ostili porta tipicamente all'esecuzione remota di codice sul server applicativo, con compromissione completa dell'host e dei dati trattati.

## Remediation

Non deserializzare mai dati da fonti non fidate: preferire formati dati puri (JSON), firmare/verificare gli oggetti serializzati che devono attraversare il client (es. ViewState con MAC abilitato), applicare filtri sulle classi deserializzabili e mantenere aggiornate le librerie per ridurre le gadget chain disponibili.
