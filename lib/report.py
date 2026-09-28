"""Gestione dei report di penetration test (template SLCtrl).

Comandi console:
    report                          Stato / aiuto
    report new ["Cliente"] [tipo]   Wizard: cliente, black/white/grey box, date
    report list                     Elenca i report esistenti
    report add <nome|num>           Wizard: aggiungi un finding (severity auto)
    report sync <nome|num>          Rigenera i blocchi automatici nel .md
    report edit <nome|num>          Apre il report in VS Code (o derivati)
    report build <nome|num>         Genera il PDF (pandoc + weasyprint)
    report path <nome|num>          Mostra il percorso del file .md
    report help                     Aiuto dettagliato

I dati strutturati (cliente, tipo box, perimetro, finding) vivono in
reports/<slug>/meta.json; i blocchi @@AUTO@@ del .md vengono rigenerati
automaticamente a ogni modifica (sync).
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_ROOT = PROJECT_ROOT / "report"
REPORTS_DIR = PROJECT_ROOT / "reports"
TEMPLATE_MD = REPORT_ROOT / "template.md"
TEMPLATE_HTML = REPORT_ROOT / "template" / "slctrl.html"
TEMPLATE_CSS = REPORT_ROOT / "template" / "slctrl.css"

_VSCODE_CANDIDATES = ("code", "codium", "vscodium", "code-insiders", "cursor")

SEV_ORDER = ("critical", "high", "medium", "low", "info")
SEV_LABEL = {"critical": "Critica", "high": "Alta", "medium": "Media",
             "low": "Bassa", "info": "Info"}
SEV_RISK = {"critical": "critico", "high": "alto", "medium": "medio",
            "low": "basso", "info": "informativo"}

BOX_TYPES = ("black", "grey", "white")
BOX_LABEL = {"black": "Black box", "grey": "Grey box", "white": "White box"}

# ---------------------------------------------------------------------------
# Testi dinamici
# ---------------------------------------------------------------------------

_BOX_APPROACH = {
    "black": (
        'SLCtrl ha eseguito il test con approccio "black box" dal {start} al '
        "{end}, senza credenziali né conoscenza preliminare dell'ambiente "
        "interno del Cliente, con l'obiettivo di identificare debolezze "
        "sconosciute. Il test è stato condotto in modalità non evasiva, con "
        "l'obiettivo di scoprire il maggior numero possibile di "
        "misconfigurazioni e vulnerabilità."
    ),
    "grey": (
        'SLCtrl ha eseguito il test con approccio "grey box" dal {start} al '
        "{end}, con conoscenza parziale dell'ambiente: il Cliente ha fornito "
        "credenziali di un utente standard e informazioni di base "
        "sull'infrastruttura, simulando un attaccante con accesso interno "
        "limitato. Il test è stato condotto in modalità non evasiva, con "
        "l'obiettivo di scoprire il maggior numero possibile di "
        "misconfigurazioni e vulnerabilità."
    ),
    "white": (
        'SLCtrl ha eseguito il test con approccio "white box" dal {start} al '
        "{end}, con piena visibilità sull'ambiente: il Cliente ha fornito "
        "credenziali amministrative, documentazione e configurazioni dei "
        "sistemi, consentendo un'analisi approfondita e mirata. Il test è "
        "stato condotto in modalità non evasiva, con l'obiettivo di scoprire "
        "il maggior numero possibile di misconfigurazioni e vulnerabilità."
    ),
}


# ---------------------------------------------------------------------------
# Path / slug helpers
# ---------------------------------------------------------------------------

def slugify(client: str) -> str:
    s = unicodedata.normalize("NFKD", client).encode("ascii", "ignore").decode()
    s = re.sub(r"[^a-zA-Z0-9]+", "-", s).strip("-").lower()
    return s or "report"


def derive_domain(client: str) -> str:
    """'Acme Corp' -> 'ACME.LOCAL'"""
    first = re.sub(r"[^a-zA-Z0-9]", "", client.split()[0] if client.split() else "cliente")
    return (first.upper() or "CLIENTE") + ".LOCAL"


def report_md_path(slug: str) -> Path:
    return REPORTS_DIR / slug / f"{slug}-report.md"


def _meta_path(slug: str) -> Path:
    return REPORTS_DIR / slug / "meta.json"


def _read_client(md_file: Path) -> str:
    try:
        head = md_file.read_text(encoding="utf-8", errors="replace")[:2000]
    except OSError:
        return ""
    m = re.search(r'^client:\s*"(.*?)"', head, re.M)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# Meta (dati strutturati del report)
# ---------------------------------------------------------------------------

def default_meta(client: str, rtype: str, box: str, domain: str,
                 date_start: str = "", date_end: str = "") -> dict:
    return {
        "client": client,
        "rtype": rtype,
        "box": box,
        "domain": domain,
        "date_start": date_start,
        "date_end": date_end,
        "scope": [{"host": "192.168.100.0/24", "desc": "Rete interna del Cliente"}],
        "findings": [],
    }


def load_meta(slug: str) -> dict | None:
    mp = _meta_path(slug)
    if not mp.is_file():
        return None
    try:
        meta = json.loads(mp.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    meta.setdefault("findings", [])
    meta.setdefault("scope", [])
    meta.setdefault("box", "black")
    meta.setdefault("domain", derive_domain(meta.get("client", "")))
    return meta


def save_meta(slug: str, meta: dict) -> None:
    _meta_path(slug).write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Listing / ricerca
# ---------------------------------------------------------------------------

def list_reports() -> list[dict]:
    out: list[dict] = []
    if not REPORTS_DIR.is_dir():
        return out
    for d in sorted(REPORTS_DIR.iterdir(), key=lambda p: p.name.lower()):
        if not d.is_dir() or d.name.startswith("."):
            continue
        md = d / f"{d.name}-report.md"
        if not md.is_file():
            cands = sorted(d.glob("*.md"))
            md = cands[0] if cands else md
        if not md.is_file():
            continue
        pdf = md.with_suffix(".pdf")
        ev_dir = d / "evidence"
        n_ev = len([f for f in ev_dir.iterdir() if f.is_file()]) if ev_dir.is_dir() else 0
        meta = load_meta(d.name)
        out.append({
            "slug": d.name,
            "client": (meta or {}).get("client") or _read_client(md),
            "box": (meta or {}).get("box", ""),
            "n_findings": len((meta or {}).get("findings", [])),
            "md": str(md),
            "pdf": str(pdf) if pdf.is_file() else None,
            "evidence": n_ev,
            "mtime": md.stat().st_mtime,
        })
    return out


def find_report(name: str | None) -> dict | None:
    reports = list_reports()
    if not reports:
        return None
    if not name:
        return reports[0] if len(reports) == 1 else None
    name = name.strip().lower()
    if name.isdigit():
        idx = int(name) - 1
        return reports[idx] if 0 <= idx < len(reports) else None
    slug = slugify(name)
    for r in reports:
        if r["slug"] == slug or r["client"].lower() == name:
            return r
    for r in reports:
        if slug in r["slug"] or name in r["client"].lower():
            return r
    return None


# ---------------------------------------------------------------------------
# Rendering dei blocchi @@AUTO@@ dal meta
# ---------------------------------------------------------------------------

def _fmt_date(d: str, fallback: str) -> str:
    return d.strip() if d and d.strip() else fallback


def render_approccio(meta: dict) -> str:
    box = meta.get("box", "black")
    tpl = _BOX_APPROACH.get(box, _BOX_APPROACH["black"])
    return tpl.format(start=_fmt_date(meta.get("date_start", ""), "*DATA INIZIO*"),
                      end=_fmt_date(meta.get("date_end", ""), "*DATA FINE*"))


def render_perimetro(meta: dict) -> str:
    domain = meta.get("domain", "CLIENTE.LOCAL")
    scope = meta.get("scope") or []
    intro = ("Il perimetro di questo assessment comprende i sistemi e la rete "
             f"interna del Cliente, incluso il dominio {domain}.")
    if not scope:
        table = ("\n\n| **Host/URL/Indirizzo IP** | **Descrizione** |\n"
                 "|---------------------------|-----------------|\n"
                 "| *da definire*             | *da definire*   |\n\n"
                 ": Tabella 3: Dettagli del Perimetro")
        return intro + table
    rows = "\n".join(f"| `{r['host']}` | {r['desc']} |" for r in scope)
    table = ("\n\n| **Host/URL/Indirizzo IP** | **Descrizione** |\n"
             "|---------------------------|-----------------|\n"
             f"{rows}\n\n: Tabella 3: Dettagli del Perimetro")
    return intro + table


def _sev_counts(findings: list[dict]) -> dict[str, int]:
    c = {k: 0 for k in SEV_ORDER}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in c:
            c[sev] += 1
    return c


def _counts_sentence(counts: dict[str, int]) -> str:
    parts = [f"*{counts[k]}* a rischio {SEV_RISK[k]}" for k in SEV_ORDER if counts[k] > 0]
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    return ", ".join(parts[:-1]) + " e " + parts[-1]


def render_panoramica(meta: dict) -> str:
    n = len(meta.get("findings", []))
    counts = _sev_counts(meta.get("findings", []))
    if n == 0:
        return ("Durante il penetration test non è stato ancora inserito alcun "
                "finding. Usa `report add` da console o il wizard SLWeb per "
                "aggiungere i finding: questo testo e le tabelle di riepilogo "
                "si aggiorneranno automaticamente.")
    breakdown = _counts_sentence(counts)
    return (f"Durante il penetration test, SLCtrl ha identificato *{n}* finding "
            "che minacciano la riservatezza, l'integrità e la disponibilità dei "
            "sistemi informativi del Cliente. I finding sono stati classificati "
            f"per livello di severità: {breakdown}.")


def render_riepilogo(meta: dict) -> str:
    findings = meta.get("findings", [])
    counts = _sev_counts(findings)
    n = len(findings)
    if n == 0:
        return ("Nessun finding ancora inserito. Aggiungi i finding con "
                "`report add` da console o dal wizard SLWeb: questa sezione "
                "(conteggi per severità ed elenco) si aggiornerà "
                "automaticamente.")
    intro = (f"Nel corso del test, SLCtrl ha rilevato un totale di *{n}* finding "
             "che rappresentano un rischio concreto per i sistemi informativi "
             "del Cliente. La tabella seguente riassume i finding per livello "
             "di severità.")
    sev_table = (
        "\n\n| **Critica** | **Alta** | **Media** | **Bassa** | **Info** | **Totale** |\n"
        "|-------------|----------|-----------|-----------|----------|------------|\n"
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} "
        f"| {counts['low']} | {counts['info']} | {n} |\n\n"
        ": Tabella 4: Riepilogo per Severità")
    list_rows = []
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info")
        badge = f'<span class="sev sev-{sev}">{SEV_LABEL.get(sev, sev)}</span>'
        list_rows.append(f"| {i}. | {badge} | {f.get('title', 'Senza titolo')} |")
    list_table = (
        "\n\nDi seguito una panoramica di alto livello di ciascun finding "
        "identificato. I finding sono trattati in dettaglio nella sezione "
        "*Dettagli Tecnici dei Finding* di questo report.\n\n"
        "| **#** | **Severità** | **Nome del Finding** |\n"
        "|-------|--------------|----------------------|\n"
        + "\n".join(list_rows) + "\n\n: Tabella 5: Elenco dei Finding")
    return intro + sev_table + list_table


def _fmt_cwe(cwe: str) -> str:
    cwe = (cwe or "").strip()
    if not cwe:
        return "*—*"
    m = re.search(r"(\d+)", cwe)
    if m:
        num = m.group(1)
        return f"[CWE-{num}](https://cwe.mitre.org/data/definitions/{num}.html)"
    return cwe


def render_finding(idx: int, f: dict) -> str:
    sev = f.get("severity", "info")
    label = SEV_LABEL.get(sev, sev)
    head = f"## SLC-{idx:02d} – {f.get('title', 'Senza titolo')} – <span class=\"sev sev-{sev}\">{label}</span>"
    rows = [
        ("CWE", _fmt_cwe(f.get("cwe", ""))),
        ("Punteggio CVSS 3.1", (f.get("cvss") or "*—*")),
        ("Descrizione (incl. causa)", f.get("description", "")),
        ("Impatto", f.get("impact", "")),
        ("Asset Interessati", f.get("assets", "")),
        ("Remediation", f.get("remediation", "")),
        ("Riferimenti", f.get("refs", "") or "*—*"),
    ]
    body = "\n".join(f"| **{k}** | {v} |" for k, v in rows)
    card = ("\n\n::: {.finding}\n"
            "|                     | |\n"
            "|---------------------|-------------------------------------------------------|\n"
            f"{body}\n:::\n")
    evidence = (f.get("evidence") or "").strip()
    ev_block = ("\n\n**Evidenze:**\n\n" + evidence) if evidence else ""
    return head + card + ev_block


def render_findings(meta: dict) -> str:
    findings = meta.get("findings", [])
    if not findings:
        return ("*Nessun finding ancora inserito. Usa `report add` da console o "
                "il wizard SLWeb: le schede tecniche verranno generate qui "
                "automaticamente.*")
    return "\n\n---\n\n".join(render_finding(i, f) for i, f in enumerate(findings, 1))


_RENDERERS = {
    "approccio": render_approccio,
    "perimetro": render_perimetro,
    "panoramica": render_panoramica,
    "riepilogo": render_riepilogo,
    "findings": render_findings,
}

# ---------------------------------------------------------------------------
# Blocchi marcati nel .md
# ---------------------------------------------------------------------------

_AUTO_RE = r"<!--\s*@@AUTO:{name}@@\s*-->(.*?)<!--\s*@@/AUTO:{name}@@\s*-->"
_SEZ_RE = r"<!--\s*@@SEZ:{name}@@\s*-->(.*?)<!--\s*@@/SEZ:{name}@@\s*-->"


def _replace_block(text: str, name: str, content: str, kind: str = "AUTO") -> str:
    pat = (_AUTO_RE if kind == "AUTO" else _SEZ_RE).format(name=re.escape(name))
    m = re.search(pat, text, re.S)
    if not m:
        return text
    return text[:m.start(1)] + "\n" + content.strip() + "\n" + text[m.end(1):]


def get_sections(md_text: str) -> dict[str, str]:
    """Legge i blocchi @@SEZ@@ (testo libero) dal markdown."""
    out = {}
    for m in re.finditer(
            r"<!--\s*@@SEZ:([a-z_]+)@@\s*-->(.*?)<!--\s*@@/SEZ:\1@@\s*-->",
            md_text, re.S):
        out[m.group(1)] = m.group(2).strip()
    return out


def update_section(slug: str, section: str, content: str) -> bool:
    md = report_md_path(slug)
    if not md.is_file():
        return False
    text = md.read_text(encoding="utf-8")
    new = _replace_block(text, section, content, kind="SEZ")
    if new == text:
        return False
    md.write_text(new, encoding="utf-8")
    return True


def _update_yaml(md_text: str, meta: dict) -> str:
    def _sub(key: str, value: str, t: str) -> str:
        return re.sub(rf'^{key}: ".*"', f'{key}: "{value}"', t, count=1, flags=re.M)
    if meta.get("client"):
        md_text = _sub("client", meta["client"], md_text)
    if meta.get("rtype"):
        md_text = _sub("report-title", meta["rtype"], md_text)
    return md_text


def sync_report(slug: str) -> tuple[bool, str]:
    """Rigenera i blocchi @@AUTO@@ del .md dai dati in meta.json."""
    meta = load_meta(slug)
    if meta is None:
        return False, f"meta.json non trovato per '{slug}'"
    md = report_md_path(slug)
    if not md.is_file():
        return False, f"File report non trovato: {md}"
    text = md.read_text(encoding="utf-8")
    if "@@AUTO:" not in text:
        return False, ("Questo report non ha blocchi dinamici (vecchio formato). "
                       "Ricrealo con 'report new'.")
    text = _update_yaml(text, meta)
    for name, fn in _RENDERERS.items():
        text = _replace_block(text, name, fn(meta), kind="AUTO")
    # sostituzioni globali del testo libero
    text = text.replace("{{DOMAIN}}", meta.get("domain", "CLIENTE.LOCAL"))
    text = text.replace("{{SLUG}}", slug)
    md.write_text(text, encoding="utf-8")
    return True, "Blocchi dinamici aggiornati"


# ---------------------------------------------------------------------------
# Creazione
# ---------------------------------------------------------------------------

def create_report(client: str, rtype: str = "Penetration Test Interno",
                  box: str = "black", domain: str | None = None,
                  date_start: str = "", date_end: str = "") -> Path:
    """Crea un nuovo report dal template. Ritorna il path del .md."""
    client = client.strip()
    if not client:
        raise ValueError("Nome cliente vuoto")
    if not TEMPLATE_MD.is_file():
        raise FileNotFoundError(f"Template non trovato: {TEMPLATE_MD}")
    if box not in BOX_TYPES:
        box = "black"
    domain = (domain or "").strip() or derive_domain(client)
    slug = slugify(client)
    out_dir = REPORTS_DIR / slug
    out = out_dir / f"{slug}-report.md"
    if out.exists():
        raise FileExistsError(f"Report già esistente: {out}")
    (out_dir / "evidence").mkdir(parents=True, exist_ok=True)

    months = ("gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno",
              "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre")
    now = datetime.datetime.now()
    today = f"{now.day} {months[now.month - 1]} {now.year}"

    meta = default_meta(client, rtype, box, domain, date_start, date_end)
    save_meta(slug, meta)

    text = TEMPLATE_MD.read_text(encoding="utf-8")
    text = text.replace("{{CLIENT}}", client)
    text = text.replace("{{RTYPE}}", rtype)
    text = text.replace("{{DATE}}", today)
    text = text.replace("{{DOMAIN}}", domain)
    text = text.replace("{{SLUG}}", slug)
    text = text.replace("{{APPROCCIO}}", render_approccio(meta))
    text = text.replace("{{PERIMETRO}}", render_perimetro(meta))
    text = text.replace("{{PANORAMICA}}", render_panoramica(meta))
    text = text.replace("{{RIEPILOGO}}", render_riepilogo(meta))
    text = text.replace("{{FINDINGS}}", render_findings(meta))
    out.write_text(text, encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def add_finding(slug: str, finding: dict, index: int | None = None) -> tuple[bool, str]:
    meta = load_meta(slug)
    if meta is None:
        return False, f"Report '{slug}' non trovato (o meta.json mancante)."
    sev = (finding.get("severity") or "info").lower()
    if sev not in SEV_ORDER:
        sev = "info"
    finding["severity"] = sev
    if index is not None and 0 <= index < len(meta["findings"]):
        meta["findings"][index] = finding
        msg = f"Finding SLC-{index + 1:02d} aggiornato"
    else:
        meta["findings"].append(finding)
        msg = f"Finding SLC-{len(meta['findings']):02d} aggiunto"
    save_meta(slug, meta)
    ok, smsg = sync_report(slug)
    counts = _sev_counts(meta["findings"])
    breakdown = ", ".join(f"{SEV_LABEL[k]}: {counts[k]}" for k in SEV_ORDER if counts[k])
    return ok, f"{msg}. Totale: {len(meta['findings'])} ({breakdown})"


def delete_finding(slug: str, index: int) -> tuple[bool, str]:
    meta = load_meta(slug)
    if meta is None or not (0 <= index < len(meta["findings"])):
        return False, "Finding non trovato."
    removed = meta["findings"].pop(index)
    save_meta(slug, meta)
    sync_report(slug)
    return True, f"Finding '{removed.get('title', '')}' eliminato."


# ---------------------------------------------------------------------------
# Editor esterno / build PDF
# ---------------------------------------------------------------------------

def _find_editor() -> str | None:
    for cand in _VSCODE_CANDIDATES:
        exe = shutil.which(cand)
        if exe:
            return exe
    return None


def edit_report(name: str | None) -> tuple[bool, str]:
    rep = find_report(name)
    if rep is None:
        return False, "Report non trovato. Usa 'report list' per vedere quelli esistenti."
    folder = str(Path(rep["md"]).parent)
    editor = _find_editor() or shutil.which("code.cmd")
    if editor:
        try:
            subprocess.Popen(
                [editor, folder],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return True, f"Aperto in {Path(editor).name}: {folder}"
        except OSError as e:
            return False, f"Impossibile avviare {editor}: {e}"
    return False, ("VS Code non trovato nel PATH (cercati: " +
                   ", ".join(_VSCODE_CANDIDATES) + ").\n"
                   f"Apri manualmente: {folder}")


def build_report(name: str | None) -> tuple[bool, str]:
    rep = find_report(name)
    if rep is None:
        return False, "Report non trovato. Usa 'report list' per vedere quelli esistenti."
    md = Path(rep["md"])
    out_pdf = md.with_suffix(".pdf")

    pandoc = shutil.which("pandoc")
    if not pandoc:
        local = Path.home() / ".local" / "bin" / "pandoc"
        pandoc = str(local) if local.is_file() else None
    if not pandoc:
        return False, "pandoc non trovato. Installalo: sudo apt install pandoc"
    weasy = shutil.which("weasyprint")
    use_module = False
    if not weasy:
        try:
            import weasyprint  # noqa: F401
            use_module = True
        except ImportError:
            return False, ("weasyprint non trovato. Installalo: sudo apt install weasyprint "
                           "oppure pip install weasyprint")

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", dir=PROJECT_ROOT, delete=False, encoding="utf-8")
    tmp.close()
    tmp_path = Path(tmp.name)
    try:
        r = subprocess.run(
            [pandoc, str(md), "--standalone",
             "--template", str(TEMPLATE_HTML),
             "--css", str(TEMPLATE_CSS),
             "--toc", "--toc-depth=2",
             "--no-highlight",
             "-o", str(tmp_path)],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            return False, f"pandoc fallito:\n{r.stderr.strip()}"
        if use_module:
            from weasyprint import HTML as _WH
            _WH(filename=str(tmp_path), base_url=str(PROJECT_ROOT)).write_pdf(str(out_pdf))
        else:
            r = subprocess.run([weasy, str(tmp_path), str(out_pdf)],
                               cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=180)
            if r.returncode != 0:
                return False, f"weasyprint fallito:\n{r.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return False, "Timeout durante la compilazione del PDF."
    except Exception as e:  # noqa: BLE001
        return False, f"Errore durante il build: {e}"
    finally:
        tmp_path.unlink(missing_ok=True)
    return True, str(out_pdf)


# ---------------------------------------------------------------------------
# Wizard interattivi CLI
# ---------------------------------------------------------------------------

def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        raw = input(f"  {prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise KeyboardInterrupt
    return raw or default


def _ask_box() -> str:
    print("  Tipo di test:")
    print("    1) Black box  — nessuna conoscenza preliminare dell'ambiente")
    print("    2) Grey box   — conoscenza/credenziali parziali (utente standard)")
    print("    3) White box  — piena visibilità (credenziali admin, documentazione)")
    raw = _ask("Scelta", "1")
    return {"1": "black", "2": "grey", "3": "white",
            "black": "black", "grey": "grey", "white": "white"}.get(raw.lower(), "black")


def interactive_new(client: str | None, rtype: str | None) -> int:
    print("\n\033[1mNuovo report di penetration test\033[0m\n")
    try:
        if not client:
            client = _ask("Nome del cliente")
        if not client:
            print("\033[91m[!]\033[0m Nome cliente obbligatorio.", file=sys.stderr)
            return 1
        if not rtype:
            rtype = _ask("Tipo di test", "Penetration Test Interno")
        box = _ask_box()
        domain = _ask("Dominio target", derive_domain(client))
        date_start = _ask("Data inizio test (es. 12 gennaio 2026, invio = segnaposto)")
        date_end = _ask("Data fine test (invio = segnaposto)")
    except KeyboardInterrupt:
        print("Annullato.")
        return 1
    try:
        out = create_report(client, rtype, box, domain, date_start, date_end)
    except (ValueError, FileExistsError, FileNotFoundError) as e:
        print(f"\033[91m[!]\033[0m {e}", file=sys.stderr)
        return 1
    slug = out.parent.name
    print(f"\n\033[92m[+]\033[0m Report creato: \033[96m{out}\033[0m")
    print(f"\033[92m[+]\033[0m Cliente, approccio ({BOX_LABEL[box]}) e dominio ({domain}) inseriti automaticamente.")
    print("\nProssimi passi:")
    print(f"  report add {slug}      # aggiungi i finding (severity e tabelle si aggiornano da sole)")
    print(f"  report edit {slug}     # apri in VS Code per il testo libero")
    print(f"  report build {slug}    # genera il PDF\n")
    return 0


def interactive_add_finding(slug: str) -> int:
    rep = find_report(slug)
    if rep is None:
        print("\033[91m[!]\033[0m Report non trovato. Usa 'report list'.", file=sys.stderr)
        return 1
    slug = rep["slug"]
    print(f"\n\033[1mNuovo finding — {rep['client']}\033[0m\n")
    while True:
        try:
            title = _ask("Titolo del finding")
            if not title:
                print("Annullato (titolo vuoto).")
                return 1
            print("  Severità: 1) Critica  2) Alta  3) Media  4) Bassa  5) Info")
            sev_n = _ask("Scelta", "2")
            severity = {"1": "critical", "2": "high", "3": "medium", "4": "low",
                        "5": "info"}.get(sev_n, "high")
            cwe = _ask("CWE (solo numero, es. 522 — invio per omettere)")
            cvss = _ask("Punteggio CVSS 3.1 (es. 9.5 — invio per omettere)")
            desc = _ask("Descrizione (incl. causa)")
            impact = _ask("Impatto")
            assets = _ask("Asset interessati", load_meta(slug).get("domain", ""))
            remediation = _ask("Remediation")
            refs = _ask("Riferimenti (URL, invio per omettere)")
            evidence = _ask("Evidenze (comandi/output o path screenshot, invio per omettere)")
        except KeyboardInterrupt:
            print("Annullato.")
            return 1
        finding = {"title": title, "severity": severity, "cwe": cwe, "cvss": cvss,
                   "description": desc, "impact": impact, "assets": assets,
                   "remediation": remediation, "refs": refs, "evidence": evidence}
        ok, msg = add_finding(slug, finding)
        print(("\n\033[92m[+]\033[0m " if ok else "\n\033[91m[!]\033[0m ") + msg)
        if not ok:
            return 1
        try:
            again = _ask("Aggiungere un altro finding?", "N")
        except KeyboardInterrupt:
            print()
            return 0
        if again.strip().lower() not in ("s", "si", "sì", "y", "yes"):
            break
        print()
    print("\nTabelle di riepilogo e conteggi severity aggiornati automaticamente nel .md.")
    print(f"Genera il PDF con: report build {slug}\n")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_report_help() -> None:
    print()
    print("\033[1mreport — Report di Penetration Test (template SLCtrl)\033[0m")
    print()
    print("  \033[92;1mUso:\033[0m")
    print('  report new ["Cliente"] [tipo]   Wizard: cliente, black/white/grey box, date')
    print("  report list                     Elenca i report esistenti")
    print("  report add <nome|num>           Wizard: aggiungi un finding (severity auto)")
    print("  report sync <nome|num>          Rigenera i blocchi automatici nel .md")
    print("  report edit <nome|num>          Apre il report in VS Code (o derivati)")
    print("  report build <nome|num>         Genera il PDF (pandoc + weasyprint)")
    print("  report path <nome|num>          Mostra il percorso del file .md")
    print()
    print("  \033[92;1mDati dinamici:\033[0m")
    print("  Cliente, approccio (box), perimetro, conteggi severity e schede finding")
    print("  sono generati automaticamente nei blocchi \033[96m@@AUTO@@\033[0m del .md —")
    print("  non modificarli a mano: vengono sovrascritti dal sync.")
    print("  I blocchi \033[96m@@SEZ@@\033[0m sono testo libero, editabile in VS Code o da SLWeb.")
    print()
    print("  \033[92;1mEsempi:\033[0m")
    print("  report new                       # wizard completo")
    print('  report new "Acme Corp"           # cliente già compilato ovunque')
    print("  report add acme-corp             # aggiungi finding guidato")
    print("  report build 1")
    print()
    print("  \033[92;1mNote:\033[0m")
    print("  - Report in \033[96mreports/<cliente>/\033[0m (+ meta.json con i dati strutturati)")
    print("  - Evidenze in \033[96mreports/<cliente>/evidence/\033[0m")
    print("  - 'report edit' cerca nel PATH: " + ", ".join(_VSCODE_CANDIDATES))
    print("  - Su SLWeb: wizard guidato sezione per sezione in \033[96m/report\033[0m")
    print()


def cmd_report(args: argparse.Namespace, state=None) -> int:
    action = (getattr(args, "action", None) or "").strip().lower()
    target = getattr(args, "target", None)
    extra = " ".join(getattr(args, "extra", []) or []).strip() or None

    if action in ("", "help", "-h", "--help"):
        if not action:
            reports = list_reports()
            print(f"\nReport esistenti: \033[1m{len(reports)}\033[0m  (cartella reports/)")
            print("Digita '\033[96mreport help\033[0m' per i comandi, '\033[96mreport new\033[0m' per il wizard.\n")
            return 0
        _print_report_help()
        return 0

    if action == "new":
        return interactive_new(target, extra)

    if action == "add":
        if not target:
            print("Uso: report add <nome|num>", file=sys.stderr)
            return 1
        return interactive_add_finding(target)

    if action == "sync":
        if not target:
            print("Uso: report sync <nome|num>", file=sys.stderr)
            return 1
        rep = find_report(target)
        if rep is None:
            print("\033[91m[!]\033[0m Report non trovato.", file=sys.stderr)
            return 1
        ok, msg = sync_report(rep["slug"])
        print(("\033[92m[+]\033[0m " if ok else "\033[91m[!]\033[0m ") + msg)
        return 0 if ok else 1

    if action == "list":
        reports = list_reports()
        if not reports:
            print("\nNessun report. Creane uno con: \033[96mreport new\033[0m\n")
            return 0
        print(f"\nReport esistenti ({len(reports)}):\n")
        for i, r in enumerate(reports, 1):
            pdf_tag = "  \033[92m[PDF]\033[0m" if r["pdf"] else ""
            box_tag = f"  \033[94m[{BOX_LABEL.get(r['box'], '')}]\033[0m" if r["box"] else ""
            f_tag = f"  \033[90m{r['n_findings']} finding\033[0m" if r["n_findings"] else ""
            ev_tag = f"  \033[90m({r['evidence']} evidenze)\033[0m" if r["evidence"] else ""
            print(f"  [{i}] \033[1m{r['slug']}\033[0m — {r['client']}{box_tag}{f_tag}{pdf_tag}{ev_tag}")
        print()
        return 0

    if action == "edit":
        ok, msg = edit_report(target)
        print(("\033[92m[+]\033[0m " if ok else "\033[91m[!]\033[0m ") + msg)
        return 0 if ok else 1

    if action == "build":
        if not target:
            print("Uso: report build <nome|num>", file=sys.stderr)
            return 1
        rep = find_report(target)
        if rep is not None and load_meta(rep["slug"]):
            sync_report(rep["slug"])
        print("Compilazione PDF in corso…")
        ok, msg = build_report(target)
        if ok:
            print(f"\033[92m[+]\033[0m PDF generato: \033[96m{msg}\033[0m")
        else:
            print(f"\033[91m[!]\033[0m {msg}", file=sys.stderr)
        return 0 if ok else 1

    if action == "path":
        rep = find_report(target)
        if rep is None:
            print("\033[91m[!]\033[0m Report non trovato.", file=sys.stderr)
            return 1
        print(rep["md"])
        return 0

    print(f"Azione sconosciuta: {action}. Digita 'report help'.", file=sys.stderr)
    return 1
