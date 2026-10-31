# Libreria Finding (SLReport)

Schede di finding **generici e riusabili** (XSS, Potato, SMBv1, Kerberoasting…):
non richiedono una CVE precisa. Usate da:

- `report lib [ricerca]` — cerca/elenca dalla console
- `report add <report>` — il wizard propone la ricerca in libreria per primo
- SLWeb → wizard → Finding → "Cerca in libreria"

## Formato (un file `.md` per finding)

```markdown
---
title: "Titolo del finding"
aliases: ["xss", "cross site scripting"]   # parole chiave di ricerca
category: "Web"                            # Web|Rete|Windows|Active Directory|Identità|Sistemi|Applicazioni
cwe: "79"
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
severity: "medium"                          # derivata dal vettore (verificata dai test)
mitre: ["T1059.007"]
refs: ["https://..."]
---

## Descrizione
...
## Impatto
...
## Remediation
...
```

Regole: severità coerente col vettore CVSS (verificata da `pytest tests/`),
sezioni Descrizione/Impatto/Remediation obbligatorie, testo in italiano
generico da adattare al caso specifico dopo il prefill.
