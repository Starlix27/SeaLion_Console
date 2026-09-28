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
import colorsys
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
# Stile del report (presets colore)
# ---------------------------------------------------------------------------

STYLE_PRESETS = {
    "navy":   {"label": "Blu navy (default)", "color": "#0F4068"},
    "red":    {"label": "Rosso",              "color": "#8B1A1A"},
    "black":  {"label": "Nero",               "color": "#1F2429"},
    "green":  {"label": "Verde",              "color": "#1E5B38"},
    "yellow": {"label": "Giallo / ambra",     "color": "#8A6200"},
}
DEFAULT_AUTHOR = "Santarella Martina"
DEFAULT_COMPANY = "SLCtrl"
DEFAULT_ROLE = "Penetration Tester"
DEFAULT_SIGNATURE_IMG = "report/assets/firma.png"


def default_style() -> dict:
    return {
        "preset": "navy",
        "color": "",          # hex custom (vuoto = usa preset)
        "color2": "",         # hex accento secondario (vuoto = derivato)
        "author": "",
        "company": "",
        "role": "",
        "logo": "",           # path relativo (es. reports/<slug>/evidence/logo.png)
        "signature": "",      # path relativo immagine firma
    }


def style_colors(style: dict) -> tuple[str, str]:
    """Ritorna (colore primario, colore accento) effettivi."""
    style = style or {}
    preset = STYLE_PRESETS.get(style.get("preset", "navy"), STYLE_PRESETS["navy"])
    c1 = _norm_hex(style.get("color")) or preset["color"]
    c2 = _norm_hex(style.get("color2")) or _shift_lightness(c1, +0.12)
    return c1, c2


def _norm_hex(c: str | None) -> str:
    c = (c or "").strip().lstrip("#")
    if re.fullmatch(r"[0-9a-fA-F]{6}", c):
        return "#" + c.upper()
    if re.fullmatch(r"[0-9a-fA-F]{3}", c):
        return "#" + "".join(ch * 2 for ch in c).upper()
    return ""


def _shift_lightness(hex_color: str, delta: float) -> str:
    """Schiarisce (delta>0) o scurisce (delta<0) un colore #RRGGBB."""
    h = _norm_hex(hex_color) or "#0F4068"
    r, g, b = (int(h[i:i + 2], 16) / 255.0 for i in (1, 3, 5))
    hh, ll, ss = colorsys.rgb_to_hls(r, g, b)
    ll = min(1.0, max(0.0, ll + delta))
    r, g, b = colorsys.hls_to_rgb(hh, ll, ss)
    return "#{:02X}{:02X}{:02X}".format(int(r * 255), int(g * 255), int(b * 255))


def style_overrides_css(meta: dict) -> str:
    """CSS aggiuntivo per applicare lo stile scelto (colori + logo)."""
    style = (meta or {}).get("style") or {}
    preset = style.get("preset", "navy")
    has_custom = bool(_norm_hex(style.get("color")) or _norm_hex(style.get("color2")))
    logo = (style.get("logo") or "").strip()
    if preset == "navy" and not has_custom and not logo:
        return ""
    c1, c2 = style_colors(style)
    dark = _shift_lightness(c1, -0.12)
    border = _shift_lightness(c1, +0.66)
    mid = _shift_lightness(c1, +0.42)
    thead = _shift_lightness(c1, +0.82)
    zebra = _shift_lightness(c1, +0.88)
    codebg = _shift_lightness(c1, +0.84)
    css = f"""
/* ---- stile personalizzato (generato da meta.style) ---- */
h1, h2, .toc-heading {{ color: {c1}; }}
h3 {{ color: {c2}; }}
a {{ color: {c2}; }}
strong {{ color: {dark}; }}
hr {{ border-top-color: {mid}; }}
th {{ background: {c1}; }}
td {{ border-bottom-color: {border}; }}
tbody tr:nth-child(even) td {{ background: {zebra}; }}
pre {{ border-left-color: {c1}; }}
code {{ background: {codebg}; color: {c1}; }}
.finding table td:first-child {{ background: {c1}; }}
.finding table tbody tr:nth-child(even) td {{ background: {zebra}; }}
.finding table tbody tr:nth-child(even) td:first-child {{ background: {c1}; }}
.cover-client {{ color: {c1}; background: {thead}; }}
.cover-title {{ color: {c1}; }}
.cover-meta .client {{ color: {c1}; }}
.cover-footer strong {{ color: {c1}; }}
.signature .sig-name {{ color: {c1}; }}
"""
    if logo:
        css += (".cover-center .cover-logo { max-width: 62mm; max-height: 28mm; "
                "margin-bottom: 10mm; }\n")
    return css


# ---------------------------------------------------------------------------
# Ricerca CVE / moduli in Metasploit (SOLO OFFLINE: db locale di msfconsole)
# ---------------------------------------------------------------------------

# rank numerico Metasploit -> severity del report
_MSF_RANK_SEV = ((600, "critical"), (500, "high"), (400, "medium"),
                 (300, "low"), (0, "info"))
_MSF_RANK_NAME = {600: "excellent", 500: "great", 400: "good",
                  300: "normal", 200: "average", 100: "low", 0: "manual"}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _msf_rank_to_sev(rank) -> str:
    try:
        r = int(rank)
    except (TypeError, ValueError):
        r = _MSF_RANK_NAME_INV.get(str(rank).strip().lower(), 0)
    for threshold, sev in _MSF_RANK_SEV:
        if r >= threshold:
            return sev
    return "info"


_MSF_RANK_NAME_INV = {v: k for k, v in _MSF_RANK_NAME.items()}


def _msf_metadata_cache() -> Path | None:
    """Cache JSON dei moduli generata da msfconsole (~/.msf4/store/)."""
    home = Path.home()
    for cand in (home / ".msf4" / "store" / "modules_metadata.json",
                 home / ".msf4" / "store" / "modules_metadata_base.json"):
        if cand.is_file():
            return cand
    return None


def _msf_extract_cves(text: str, refs: list | None = None) -> list[str]:
    found: list[str] = []
    for src in ([text or ""] + [str(r) for r in (refs or [])]):
        for m in _CVE_RE.finditer(src):
            cve = m.group(0).upper()
            if cve not in found:
                found.append(cve)
    return found


def _msf_entry(name: str, fullname: str, mtype: str, rank, description: str,
               refs: list | None = None, date: str = "") -> dict:
    rank_name = str(rank).lower() if isinstance(rank, str) else \
        _MSF_RANK_NAME.get(int(rank), str(rank))
    try:
        rank_int = int(rank)
    except (TypeError, ValueError):
        rank_int = _MSF_RANK_NAME_INV.get(str(rank).strip().lower(), 0)
    cves = _msf_extract_cves(f"{name} {description}", refs)
    return {
        "name": name,
        "fullname": fullname,
        "type": mtype,
        "rank": rank_name,
        "severity": _msf_rank_to_sev(rank_int),
        "cves": cves,
        "description": (description or "").strip(),
        "date": date or "",
    }


def _msf_search_cache(cache: Path, query: str, limit: int) -> list[dict]:
    """Cerca nella cache modules_metadata.json (nessun processo, nessuna rete)."""
    try:
        data = json.loads(cache.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, dict):
        entries = []
        for key, val in data.items():
            if isinstance(val, dict):
                val = dict(val)
                val.setdefault("path", key)
                entries.append(val)
    elif isinstance(data, list):
        entries = [e for e in data if isinstance(e, dict)]
    else:
        return []
    terms = [t.lower() for t in query.split() if t.strip()]
    out: list[dict] = []
    for e in entries:
        path = str(e.get("path") or e.get("fullname") or e.get("ref_name") or "")
        name = str(e.get("name") or path.rsplit("/", 1)[-1])
        desc = str(e.get("description") or "")
        refs = e.get("references") or e.get("refs") or []
        if isinstance(refs, str):
            refs = [refs]
        haystack = " ".join([path, name, desc, " ".join(map(str, refs))]).lower()
        if terms and not all(t in haystack for t in terms):
            continue
        mtype = str(e.get("type") or (path.split("/", 1)[0] if "/" in path else ""))
        fullname = path if "/" in path else str(e.get("ref_name") or name)
        date = str(e.get("disclosure_date") or e.get("date") or "")
        out.append(_msf_entry(name, fullname, mtype, e.get("rank", 0), desc,
                              refs, date))
        if len(out) >= limit:
            break
    # exploit prima, poi rank decrescente
    out.sort(key=lambda r: (r["type"] != "exploit", -_MSF_RANK_NAME_INV.get(r["rank"], 0)))
    return out[:limit]


_MSF_SEARCH_ROW_RE = re.compile(
    r"^\s*\d+\s+(\S+)\s+(?:(\d{4}-\d{2}-\d{2})\s+)?(\w+)\s+(Yes|No)\s+(.*)$",
    re.I)


def _msf_search_console(query: str, limit: int) -> list[dict]:
    """Fallback: interroga `msfconsole -q -x 'search ...'` (comunque offline)."""
    exe = shutil.which("msfconsole")
    if not exe:
        return []
    safe_q = query.replace('"', "").replace(";", " ").strip() or "cve"
    try:
        r = subprocess.run(
            [exe, "-q", "-x", f"search {safe_q}; exit"],
            capture_output=True, text=True, timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    out: list[dict] = []
    for line in (r.stdout or "").splitlines():
        m = _MSF_SEARCH_ROW_RE.match(line)
        if not m:
            continue
        fullname, date, rank, _check, desc = m.groups()
        mtype = fullname.split("/", 1)[0] if "/" in fullname else ""
        name = fullname.rsplit("/", 1)[-1]
        out.append(_msf_entry(name, fullname, mtype, rank, desc, [], date))
        if len(out) >= limit:
            break
    return out


def msf_search(query: str, limit: int = 30) -> dict:
    """Cerca CVE/moduli nel database LOCALE di Metasploit (mai online).

    Ritorna {"ok": bool, "source": "cache"|"msfconsole"|None,
             "results": [...], "error": str|None}.
    """
    cache = _msf_metadata_cache()
    if cache is not None:
        try:
            return {"ok": True, "source": "cache",
                    "results": _msf_search_cache(cache, query, limit),
                    "error": None}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "source": "cache", "results": [],
                    "error": f"cache MSF illeggibile: {e}"}
    if shutil.which("msfconsole"):
        return {"ok": True, "source": "msfconsole",
                "results": _msf_search_console(query, limit), "error": None}
    return {"ok": False, "source": None, "results": [],
            "error": ("Metasploit non trovato: né la cache "
                      "~/.msf4/store/modules_metadata.json né il comando "
                      "msfconsole. Avvia msfconsole almeno una volta per "
                      "generare la cache dei moduli.")}

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
        "time_start": "",
        "time_end": "",
        "scope": [{"host": "192.168.100.0/24", "desc": "Rete interna del Cliente"}],
        "findings": [],
        "style": default_style(),
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
    style = default_style()
    style.update(meta.get("style") or {})
    meta["style"] = style
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


def _company(meta: dict) -> str:
    return ((meta.get("style") or {}).get("company") or "").strip() or DEFAULT_COMPANY


def _fmt_datetime(meta: dict, date_key: str, time_key: str, fallback: str) -> str:
    """'1 settembre 2026' + '09:00' -> '1 settembre 2026, ore 09:00'."""
    d = (meta.get(date_key) or "").strip()
    t = (meta.get(time_key) or "").strip()
    if not d:
        return fallback
    return f"{d}, ore {t}" if t else d


def render_approccio(meta: dict) -> str:
    box = meta.get("box", "black")
    tpl = _BOX_APPROACH.get(box, _BOX_APPROACH["black"])
    text = tpl.format(
        start=_fmt_datetime(meta, "date_start", "time_start", "*DATA INIZIO*"),
        end=_fmt_datetime(meta, "date_end", "time_end", "*DATA FINE*"))
    return text.replace(DEFAULT_COMPANY, _company(meta))


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
        return ""  # sezione nascosta dal PDF/anteprima finché non ci sono finding
    breakdown = _counts_sentence(counts)
    return (f"Durante il penetration test, {_company(meta)} ha identificato *{n}* finding "
            "che minacciano la riservatezza, l'integrità e la disponibilità dei "
            "sistemi informativi del Cliente. I finding sono stati classificati "
            f"per livello di severità: {breakdown}.")


def render_riepilogo(meta: dict) -> str:
    findings = meta.get("findings", [])
    counts = _sev_counts(findings)
    n = len(findings)
    if n == 0:
        return ""  # niente titolo/contenuto nel PDF finché non ci sono finding
    intro = (f"Nel corso del test, {_company(meta)} ha rilevato un totale di *{n}* finding "
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


def _render_images(images: list[dict]) -> str:
    """Blocchi immagine con didascalia (pandoc implicit_figures -> figure+figcaption)."""
    blocks = []
    for im in images or []:
        path = (im.get("path") or "").strip()
        caption = (im.get("caption") or "").strip()
        if not path:
            continue
        alt = caption or Path(path).stem
        blocks.append(f"![{alt}]({path})")
        if caption:
            blocks.append(f"*Figura: {caption}*")
    return "\n\n".join(blocks)


def render_finding(idx: int, f: dict) -> str:
    sev = f.get("severity", "info")
    label = SEV_LABEL.get(sev, sev)
    head = f"## SLC-{idx:02d} – {f.get('title', 'Senza titolo')} – <span class=\"sev sev-{sev}\">{label}</span>"
    cves = [c for c in (f.get("cves") or []) if str(c).strip()]
    rows = [
        ("CWE", _fmt_cwe(f.get("cwe", ""))),
        ("Punteggio CVSS 3.1", (f.get("cvss") or "*—*")),
    ]
    if cves:
        rows.append(("CVE", ", ".join(str(c).upper() for c in cves)))
    rows += [
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
    imgs = _render_images(f.get("images"))
    imgs_block = ("\n\n" + imgs) if imgs else ""
    return head + card + ev_block + imgs_block


def render_findings(meta: dict) -> str:
    findings = meta.get("findings", [])
    if not findings:
        return ""  # sezione nascosta finché non ci sono finding
    return "\n\n---\n\n".join(render_finding(i, f) for i, f in enumerate(findings, 1))


def render_firma(meta: dict) -> str:
    """Blocco firma finale: autore, azienda e immagine firma (sezione Stile)."""
    style = meta.get("style") or {}
    author = (style.get("author") or "").strip()
    company = (style.get("company") or "").strip()
    role = (style.get("role") or "").strip() or DEFAULT_ROLE
    sig_img = (style.get("signature") or "").strip()
    if not author and not company:
        return ""  # niente blocco firma finché la sezione Stile è vuota
    if not sig_img:
        sig_img = DEFAULT_SIGNATURE_IMG
    name = author or DEFAULT_AUTHOR
    role_line = role if not company else f"{role} — {company}"
    return ('<div class="signature">\n'
            f'<img src="{sig_img}" alt="Firma"><br>\n'
            f'<span class="sig-name">{name}</span><br>\n'
            f'<span class="sig-role">{role_line}</span>\n'
            '</div>')


_RENDERERS = {
    "approccio": render_approccio,
    "perimetro": render_perimetro,
    "panoramica": render_panoramica,
    "riepilogo": render_riepilogo,
    "findings": render_findings,
    "firma": render_firma,
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
    author = ((meta.get("style") or {}).get("author") or "").strip()
    if author:
        md_text = _sub("author", author, md_text)
    return md_text


# ---------------------------------------------------------------------------
# Rimozione sezioni vuote (build PDF / anteprima)
# ---------------------------------------------------------------------------

_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_BLOCK_MARK_RE = re.compile(
    r"(<!--\s*@@(SEZ|AUTO):([a-z_]+)@@\s*-->)(.*?)(<!--\s*@@/\2:\3@@\s*-->)", re.S)


def _block_empty(content: str) -> bool:
    """True se il blocco contiene solo commenti HTML, placeholder o spazi."""
    t = _COMMENT_RE.sub("", content)
    t = t.replace("*—*", "").strip()
    return not t


def filter_empty_sections(md_text: str) -> str:
    """Rimuove dal markdown le sezioni rimaste vuote (wizard non compilato):

    1. svuota i blocchi @@SEZ@@/@@AUTO@@ che contengono solo commenti;
    2. elimina i titoli (##, #) il cui corpo è vuoto — niente titoli né
       spazi vuoti nel PDF per le sezioni lasciate vuote.
    Il blocco firma (@@AUTO:firma@@) viene spostato in fondo al documento,
    così non tiene in vita il titolo "Considerazioni Finali" quando vuoto.
    """
    firma_m = re.search(
        r"<!--\s*@@AUTO:firma@@\s*-->(.*?)<!--\s*@@/AUTO:firma@@\s*-->",
        md_text, re.S)
    firma = ""
    if firma_m and not _block_empty(firma_m.group(1)):
        firma = "\n\n" + firma_m.group(0) + "\n"
        md_text = md_text[:firma_m.start()] + md_text[firma_m.end():]

    def _blank(m: re.Match) -> str:
        if _block_empty(m.group(4)):
            return m.group(1) + m.group(5)
        return m.group(0)

    text = _BLOCK_MARK_RE.sub(_blank, md_text)

    for _ in range(20):  # heading pass, ripetuto finché stabile
        lines = text.split("\n")
        heads: list[tuple[int, int]] = []
        in_code = False
        for i, ln in enumerate(lines):
            if re.match(r"^\s*(```|~~~)", ln):
                in_code = not in_code
                continue
            if in_code:
                continue
            m = re.match(r"^(#{1,6})\s", ln)
            if m:
                heads.append((i, len(m.group(1))))
        removed = False
        for hi in range(len(heads) - 1, -1, -1):
            idx, lvl = heads[hi]
            end = len(lines)
            for j, lvl2 in heads[hi + 1:]:
                if lvl2 <= lvl:
                    end = j
                    break
            body = "\n".join(lines[idx + 1:end])
            if _block_empty(body):
                del lines[idx:end]
                text = "\n".join(lines)
                removed = True
                break
        if not removed:
            break
    # compatta le righe vuote multiple lasciate dalle rimozioni
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text + firma


def import_evidence(slug: str, src: str) -> str:
    """Copia un file immagine in reports/<slug>/evidence/ e ritorna il path
    relativo al progetto (da usare nel markdown)."""
    src_path = Path(src).expanduser()
    if not src_path.is_file():
        raise FileNotFoundError(f"File non trovato: {src}")
    ev_dir = REPORTS_DIR / slug / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", src_path.name)
    dst = ev_dir / name
    n = 1
    while dst.exists() and dst.read_bytes() != src_path.read_bytes():
        dst = ev_dir / f"{src_path.stem}_{n}{src_path.suffix}"
        n += 1
    if not dst.exists():
        shutil.copy2(src_path, dst)
    return str(dst.relative_to(PROJECT_ROOT))


def apply_meta(text: str, meta: dict, slug: str) -> str:
    """Applica i dati del meta al testo markdown (blocchi @@AUTO@@ + YAML)."""
    text = _update_yaml(text, meta)
    for name, fn in _RENDERERS.items():
        text = _replace_block(text, name, fn(meta), kind="AUTO")
    # sostituzioni globali del testo libero
    text = text.replace("{{DOMAIN}}", meta.get("domain", "CLIENTE.LOCAL"))
    text = text.replace("{{SLUG}}", slug)
    return text


def preview_md(slug: str, meta: dict | None = None,
               sections: dict | None = None) -> str | None:
    """Markdown finale (filtrato) per l'anteprima live, SENZA toccare i file.

    meta/sections sono bozze provenienti dal wizard: vengono applicate
    in memoria sopra il contenuto salvato.
    """
    md = report_md_path(slug)
    if not md.is_file():
        return None
    text = md.read_text(encoding="utf-8", errors="replace")
    stored = load_meta(slug) or {}
    if meta:
        for key in ("client", "rtype", "box", "domain", "date_start",
                    "date_end", "scope", "findings", "style"):
            if key in meta:
                stored[key] = meta[key]
    if sections:
        for name, content in sections.items():
            if re.fullmatch(r"[a-z_]+", name):
                text = _replace_block(text, name, str(content), kind="SEZ")
    text = apply_meta(text, stored, slug)
    return filter_empty_sections(text)


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
    text = apply_meta(text, meta, slug)
    md.write_text(text, encoding="utf-8")
    return True, "Blocchi dinamici aggiornati"


# ---------------------------------------------------------------------------
# Creazione
# ---------------------------------------------------------------------------

def create_report(client: str, rtype: str = "Penetration Test Interno",
                  box: str = "black", domain: str | None = None,
                  date_start: str = "", date_end: str = "",
                  time_start: str = "", time_end: str = "") -> Path:
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
    meta["time_start"] = time_start
    meta["time_end"] = time_end
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
    text = text.replace("{{FIRMA}}", render_firma(meta))
    out.write_text(text, encoding="utf-8")
    sync_report(slug)  # riempie tutti i blocchi @@AUTO@@ (firma inclusa)
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
    finding["cves"] = [str(c).strip().upper() for c in (finding.get("cves") or [])
                       if str(c).strip()]
    finding["images"] = [{"path": str(im.get("path", "")).strip(),
                          "caption": str(im.get("caption", "")).strip()}
                         for im in (finding.get("images") or [])
                         if isinstance(im, dict) and str(im.get("path", "")).strip()]
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
    meta = load_meta(rep["slug"]) or {}
    if meta:
        sync_report(rep["slug"])

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

    # ---- markdown filtrato: niente titoli/sezioni vuote nel PDF ----
    md_text = md.read_text(encoding="utf-8", errors="replace")
    md_text = filter_empty_sections(md_text)
    tmp_md = tempfile.NamedTemporaryFile(
        mode="w", suffix=".md", dir=PROJECT_ROOT, delete=False, encoding="utf-8",
        prefix=f".{md.stem}-build-")
    tmp_md.write(md_text)
    tmp_md.close()
    tmp_md_path = Path(tmp_md.name)

    # ---- stile: CSS override + eventuale logo/azienda nella cover ----
    style = meta.get("style") or {}
    extra_css = style_overrides_css(meta)
    company = (style.get("company") or "").strip()
    logo = (style.get("logo") or "").strip()
    css_path = TEMPLATE_CSS
    html_path = TEMPLATE_HTML
    tmp_css_path = tmp_html_path = None
    if extra_css:
        tmp_css = tempfile.NamedTemporaryFile(
            mode="w", suffix=".css", dir=PROJECT_ROOT, delete=False, encoding="utf-8",
            prefix=".report-style-")
        tmp_css.write(TEMPLATE_CSS.read_text(encoding="utf-8") + "\n" + extra_css)
        tmp_css.close()
        tmp_css_path = Path(tmp_css.name)
        css_path = tmp_css_path
    if company or logo:
        html_text = TEMPLATE_HTML.read_text(encoding="utf-8")
        if logo:
            html_text = html_text.replace(
                '<div class="cover-client">',
                f'<img class="cover-logo" src="{html_escape_attr(logo)}" alt="Logo"><br>\n'
                '    <div class="cover-client">', 1)
        if company and company != DEFAULT_COMPANY:
            html_text = html_text.replace(DEFAULT_COMPANY, company)
        tmp_html = tempfile.NamedTemporaryFile(
            mode="w", suffix=".html", dir=PROJECT_ROOT, delete=False, encoding="utf-8",
            prefix=".report-tpl-")
        tmp_html.write(html_text)
        tmp_html.close()
        tmp_html_path = Path(tmp_html.name)
        html_path = tmp_html_path

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", dir=PROJECT_ROOT, delete=False, encoding="utf-8")
    tmp.close()
    tmp_path = Path(tmp.name)
    try:
        r = subprocess.run(
            [pandoc, str(tmp_md_path), "--standalone",
             "--template", str(html_path),
             "--css", str(css_path),
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
        tmp_md_path.unlink(missing_ok=True)
        if tmp_css_path:
            tmp_css_path.unlink(missing_ok=True)
        if tmp_html_path:
            tmp_html_path.unlink(missing_ok=True)
    return True, str(out_pdf)


def html_escape_attr(s: str) -> str:
    return (s.replace("&", "&amp;").replace('"', "&quot;")
             .replace("<", "&lt;").replace(">", "&gt;"))


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
        time_start = _ask("Ora inizio (es. 09:00, invio per omettere)")
        date_end = _ask("Data fine test (invio = segnaposto)")
        time_end = _ask("Ora fine (es. 18:00, invio per omettere)")
    except KeyboardInterrupt:
        print("Annullato.")
        return 1
    try:
        out = create_report(client, rtype, box, domain, date_start, date_end,
                            time_start, time_end)
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


def _ask_msf_prefill() -> dict:
    """Cerca una CVE/un modulo nel db locale di Metasploit e prepara i campi."""
    try:
        q = _ask("Cerca in Metasploit (CVE o nome modulo, offline — invio per saltare)")
    except KeyboardInterrupt:
        raise
    if not q:
        return {}
    res = msf_search(q)
    if not res["ok"]:
        print(f"  \033[93m[~]\033[0m {res['error']}")
        return {}
    results = res["results"]
    if not results:
        print("  \033[93m[~]\033[0m Nessun modulo trovato nel db locale di Metasploit.")
        return {}
    print(f"  \033[92m[+]\033[0m {len(results)} moduli trovati (fonte: {res['source']}):\n")
    for i, r in enumerate(results, 1):
        cves = f" [{', '.join(r['cves'])}]" if r["cves"] else ""
        print(f"    [{i}] \033[1m{r['fullname']}\033[0m "
              f"({r['rank']}, sev: {SEV_LABEL.get(r['severity'], r['severity'])}){cves}")
        if r["description"]:
            print(f"        {r['description'][:110]}")
    try:
        pick = _ask("Usa il modulo n. (invio per nessuno)")
    except KeyboardInterrupt:
        raise
    if not pick.isdigit() or not (1 <= int(pick) <= len(results)):
        return {}
    r = results[int(pick) - 1]
    refs = " ".join(f"https://nvd.nist.gov/vuln/detail/{c}" for c in r["cves"])
    if not refs:
        refs = f"https://www.rapid7.com/db/modules/{r['fullname']}"
    return {
        "title": r["name"].replace("_", " ").strip().title() or r["fullname"],
        "severity": r["severity"],
        "cves": r["cves"],
        "description": r["description"] or f"Modulo Metasploit: {r['fullname']}",
        "refs": refs,
        "msf_module": r["fullname"],
    }


def interactive_add_finding(slug: str) -> int:
    rep = find_report(slug)
    if rep is None:
        print("\033[91m[!]\033[0m Report non trovato. Usa 'report list'.", file=sys.stderr)
        return 1
    slug = rep["slug"]
    print(f"\n\033[1mNuovo finding — {rep['client']}\033[0m\n")
    while True:
        try:
            pre = _ask_msf_prefill()
            if pre:
                print("  \033[92m[+]\033[0m Campi precompilati da Metasploit (modifica ciò che serve).")
            title = _ask("Titolo del finding", pre.get("title", ""))
            if not title:
                print("Annullato (titolo vuoto).")
                return 1
            print("  Severità: 1) Critica  2) Alta  3) Media  4) Bassa  5) Info")
            sev_default = {v: str(i) for i, v in enumerate(
                ("critical", "high", "medium", "low", "info"), 1)}.get(pre.get("severity", "high"), "2")
            sev_n = _ask("Scelta", sev_default)
            severity = {"1": "critical", "2": "high", "3": "medium", "4": "low",
                        "5": "info"}.get(sev_n, pre.get("severity", "high"))
            cves = pre.get("cves") or []
            cve_raw = _ask("CVE (separate da virgola, invio per omettere)",
                           ", ".join(cves))
            cves = [c.strip().upper() for c in cve_raw.split(",") if c.strip()]
            cwe = _ask("CWE (solo numero, es. 522 — invio per omettere)")
            cvss = _ask("Punteggio CVSS 3.1 (es. 9.5 — invio per omettere)")
            desc = _ask("Descrizione (incl. causa)", pre.get("description", ""))
            impact = _ask("Impatto")
            assets = _ask("Asset interessati", load_meta(slug).get("domain", ""))
            remediation = _ask("Remediation")
            refs = _ask("Riferimenti (URL, invio per omettere)", pre.get("refs", ""))
            evidence = _ask("Evidenze (comandi/output, invio per omettere)")
            images: list[dict] = []
            print("  Immagini evidenza (con didascalia) — path file, invio per finire:")
            while True:
                img_path = _ask("  Immagine (path)")
                if not img_path:
                    break
                caption = _ask("  Didascalia (descrizione sotto l'immagine)")
                try:
                    rel = import_evidence(slug, img_path)
                except FileNotFoundError as e:
                    print(f"  \033[91m[!]\033[0m {e}")
                    continue
                images.append({"path": rel, "caption": caption})
                print(f"  \033[92m[+]\033[0m Copiata in {rel}")
        except KeyboardInterrupt:
            print("Annullato.")
            return 1
        finding = {"title": title, "severity": severity, "cwe": cwe, "cvss": cvss,
                   "cves": cves, "description": desc, "impact": impact,
                   "assets": assets, "remediation": remediation, "refs": refs,
                   "evidence": evidence, "images": images}
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
    print("  - 'report add' cerca CVE/moduli nel db LOCALE di Metasploit (offline)")
    print("  - Le sezioni lasciate vuote non compaiono nel PDF (né titoli né spazi)")
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
