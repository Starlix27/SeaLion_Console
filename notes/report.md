# Report di Penetration Test

Il comando `report` crea e gestisce **report di pentest professionali** dal template
SLCtrl (Markdown → PDF, struttura ispirata ai sample report HackTheBox, in italiano).

## Workflow rapido

```bash
slconsole> report new "Acme Corp"        # 1. Crea il report (cover pre-compilata)
slconsole> report edit acme-corp         # 2. Lo apre in VS Code (o derivati) per compilarlo
slconsole> report build acme-corp        # 3. Genera il PDF finale
slconsole> report list                   # Elenca i report esistenti
slconsole> report path acme-corp         # Mostra il percorso del file .md
```

`report edit` cerca nel PATH: `code`, `codium`, `vscodium`, `code-insiders`, `cursor`.
Funziona anche da WSL (usa il `code` di Windows via interop).

## Struttura

```
reports/acme-corp/
├── acme-corp-report.md     # il report (Markdown)
├── acme-corp-report.pdf    # il PDF compilato
└── evidence/               # screenshot e prove
```

Il template si trova in `report/template.md`; tema e cover in `report/template/`
(`slctrl.css`, `slctrl.html`) e `report/assets/`.

## Sezioni del template

Dichiarazione di Riservatezza · Contatti · Executive Summary (Approccio / Perimetro /
Panoramica) · Riepilogo dell'Assessment · Compromissione della Rete · Piano di
Remediation (breve/medio/lungo termine) · Dettagli Tecnici dei Finding ·
Appendici A–E · Considerazioni Finali (con firma).

## Sintassi utile

- **Severità**: `<span class="sev sev-high">Alta</span>`
  classi: `sev-critical`, `sev-high`, `sev-medium`, `sev-low`, `sev-info`
- **Card finding** (tabella a 2 colonne in un fenced div):
  ```markdown
  ::: {.finding}
  |                 | |
  |-----------------|---------------------------------------------|
  | **CWE**         | CWE-522 |
  | **Remediation** | ...     |
  :::
  ```
  NB: la riga dei trattini definisce le proporzioni delle colonne (~28% / ~72%).
- **Evidenze**: salva i file in `reports/<cliente>/evidence/` e referenziali con
  path relativi alla root del progetto:
  `![Figura 1: Attack path](reports/acme-corp/evidence/bloodhound.png)`
- **Caption tabelle**: riga `: Tabella N: titolo` subito dopo la tabella.

## Da SLWeb

Con SLWeb attivo (`serve on`), la pagina `/report` permette di:

- creare un nuovo report dal form (cliente + tipo di test)
- vedere l'**anteprima** renderizzata di template e report
- generare il **PDF** dal browser e scaricare `.md` / `.pdf`

## Dipendenze per il PDF

`pandoc` + `weasyprint`:

```bash
sudo apt install pandoc weasyprint
# oppure
pip install weasyprint
```
