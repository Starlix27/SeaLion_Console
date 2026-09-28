# Report di Penetration Test

Il comando `report` crea e gestisce **report di pentest professionali** dal template
SLCtrl (Markdown → PDF, struttura ispirata ai sample report HackTheBox, in italiano).

## Workflow rapido

```bash
slconsole> report new                    # 1. Wizard: cliente, box, dominio, date
slconsole> report add acme-corp          # 2. Wizard: aggiungi finding (severity auto)
slconsole> report edit acme-corp         # 3. Lo apre in VS Code per il testo libero
slconsole> report build acme-corp        # 4. Genera il PDF finale
slconsole> report list                   # Elenca i report esistenti
slconsole> report sync acme-corp         # Rigenera i blocchi automatici
slconsole> report path acme-corp         # Mostra il percorso del file .md
```

`report edit` cerca nel PATH: `code`, `codium`, `vscodium`, `code-insiders`, `cursor`.
Funziona anche da WSL (usa il `code` di Windows via interop).

## Wizard di creazione

`report new` chiede in sequenza:

1. **Nome del cliente** → inserito automaticamente in cover e in tutto il documento
2. **Tipo di test** (default: Penetration Test Interno)
3. **Approccio**: black / grey / white box — il testo della sezione Approccio si adatta da solo
4. **Dominio target** (derivato automaticamente, es. `ACME.LOCAL`)
5. **Date** di inizio/fine test

## Finding da Metasploit (offline)

`report add` (e il wizard SLWeb) possono cercare CVE e moduli nel **database
locale di Metasploit** — nessuna chiamata a Internet: viene letta la cache
`~/.msf4/store/modules_metadata.json` (generata al primo avvio di `msfconsole`),
con fallback su `msfconsole -q -x "search ..."`.

```
slconsole> report add acme-corp
  Cerca in Metasploit (CVE o nome modulo, offline — invio per saltare): CVE-2017-0143
    [1] exploit/windows/smb/ms17_010_eternalblue (average) [CVE-2017-0143, ...]
  Usa il modulo n. (invio per nessuno): 1
```

Scegliendo un modulo, **titolo, descrizione, severità (dal rank), CVE e
riferimenti** vengono precompilati e finiscono nei *Dettagli Tecnici dei Finding*.

## Immagini con didascalia

Ogni finding può avere **più immagini evidenza**, ciascuna con la propria
didascalia sotto (contesto). Da console: `report add` chiede path + didascalia
e copia il file in `evidence/`. Da SLWeb: upload diretto nel form del finding.

## Sezioni vuote nascoste

Le sezioni lasciate **vuote** nel wizard (walkthrough, remediation breve/medio/
lungo, appendici B–E, considerazioni finali, finding, firma) **non compaiono
nel PDF né nell'anteprima**: vengono rimossi sia il titolo sia il contenuto,
senza lasciare spazi vuoti.

## Stile del report

Dal wizard SLWeb, sezione **Stile**:

- **Colore**: blu navy (default), rosso, nero, verde, giallo/ambra oppure
  personalizzato (hex), con eventuale **secondo colore** d'accento
- **Logo** del report (mostrato in cover)
- **Autore** e **azienda** che eseguono il test (cover, footer e testi dinamici)
- **Firma** (immagine): blocco firma generato automaticamente a fine report;
  se autore e azienda sono vuoti il blocco non compare

Lo stile vive in `meta.json` (`style`) e viene applicato a ogni build del PDF.

## Dati dinamici nel .md

I blocchi racchiusi tra `@@AUTO:nome@@` ... `@@/AUTO:nome@@` sono **generati
automaticamente** (cliente, approccio, perimetro, conteggi severity, elenco e
schede finding) dai dati in `reports/<cliente>/meta.json`: non modificarli a
mano, vengono sovrascritti a ogni sync. I blocchi `@@SEZ:nome@@` ... `@@/SEZ:nome@@`
contengono **testo libero** editabile in VS Code o dal wizard SLWeb.

Ogni volta che aggiungi/modifichi un finding, conteggi e tabelle del riepilogo
si aggiornano da soli: classificando un finding come "critico" il testo dirà
automaticamente "*1* a rischio critico" e così via.

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

Con SLWeb attivo (`serve on`), la pagina `/report` permette di creare il report
**normalmente, un pezzo alla volta**, con il wizard guidato:

1. **Cliente & Test** — nome cliente, tipo di test, dominio
2. **Approccio** — tipo di box (black/grey/white) e date: il testo si genera da solo
3. **Perimetro** — tabella degli asset in scope
4. **Finding (CVE/MSF)** — ricerca offline nel db di Metasploit, severity e
   conteggi live, immagini con didascalia
5. **Walkthrough** — compromissione e percorso di attacco (Markdown libero)
6. **Remediation** — breve / medio / lungo termine
7. **Appendici** — host compromessi, utenti compromessi, bonifica, analisi password
8. **Stile** — colori, logo, autore/azienda, firma
9. **Considerazioni finali & PDF** — sommario severity, anteprima e generazione PDF

Ogni passo ha "Salva" e "Salva e continua". Dalla pagina `/report` anche
anteprima completa, download `.md` / `.pdf` ed eliminazione.

## Dipendenze per il PDF

`pandoc` + `weasyprint`:

```bash
sudo apt install pandoc weasyprint
# oppure
pip install weasyprint
```
