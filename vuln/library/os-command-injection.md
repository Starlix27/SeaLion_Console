---
title: "OS Command Injection"
aliases:
  - "command injection"
  - "rce"
  - "remote code execution"
  - "esecuzione comandi"
category: "Web"
cwe: "78"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
severity: "critical"
mitre:
  - "T1059"
refs:
  - "https://owasp.org/www-community/attacks/Command_Injection"
---

## Descrizione

Input controllati dall'attaccante vengono passati a funzioni che invocano la shell del sistema operativo (system, exec, popen, Process con concatenazione): caratteri speciali come ; | && permettono di eseguire comandi arbitrari nel contesto del servizio.

## Impatto

Esecuzione di comandi arbitrari sul server con i privilegi dell'applicazione: lettura e modifica di dati, installazione di webshell e backdoor, pivoting verso la rete interna e compromissione completa dell'host.

## Remediation

Evitare l'invocazione della shell: usare API native con array di argomenti (senza interprete dei comandi), validare gli input con whitelist rigorose (es. solo alfanumerici), eseguire il servizio con privilegi minimi e in ambienti isolati (container, sandbox).
