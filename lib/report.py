"""Gestione dei report di penetration test (template SLCtrl).

Comandi console:
    report                          Stato / aiuto
    report new ["Cliente"] [tipo]   Wizard: cliente, black/white/grey box, date
    report list                     Elenca i report esistenti
    report add <nome|num>           Wizard: aggiungi un finding (libreria + MSF + NVD)
    report lib [ricerca]            Libreria finding generici offline (xss, potato...)
    report sync <nome|num>          Rigenera i blocchi automatici nel .md
    report edit <nome|num> [modo]   Modifica il report: vsc/vscode/md = VS Code,
                                    pdf = editor PDF; il PDF si riaggiorna da solo
    report watch/unwatch <nome|num> Attiva/disattiva l'auto-rebuild del PDF
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
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_ROOT = PROJECT_ROOT / "report"
REPORTS_DIR = PROJECT_ROOT / "reports"
TEMPLATE_MD = REPORT_ROOT / "template.md"
TEMPLATE_HTML = REPORT_ROOT / "template" / "slctrl.html"
TEMPLATE_CSS = REPORT_ROOT / "template" / "slctrl.css"

_VSCODE_CANDIDATES = ("code", "codium", "vscodium", "code-insiders", "cursor")

# Editor PDF esterni, in ordine di preferenza (Linux); su WSL si ripiega
# sull'app Windows associata ai .pdf (Acrobat, Word, Edge...).
_PDF_EDITOR_CANDIDATES = (
    ("libreoffice", ["--draw"]),
    ("soffice", ["--draw"]),
    ("xournalpp", []),
    ("okular", []),
    ("evince", []),
)

# Pacchetto apt installato automaticamente se nessun editor PDF è presente
_PDF_EDITOR_AUTO_PACKAGE = "libreoffice-draw"

# Modi accettati da 'report edit <target> [modo]'
_EDIT_MD_MODES = {"vsc", "vscode", "md", "markdown", "code", "testo"}
_EDIT_PDF_MODES = {"pdf"}

SEV_ORDER = ("critical", "high", "medium", "low", "info")
SEV_LABEL = {"critical": "Critica", "high": "Alta", "medium": "Media",
             "low": "Bassa", "info": "Info"}
SEV_RISK = {"critical": "critico", "high": "alto", "medium": "medio",
            "low": "basso", "info": "informativo"}


def severity_label_from_score(sc: float) -> str:
    """0.0-10.0 -> etichetta italiana della fascia CVSS."""
    try:
        from lib.cvss import severity_from_score
        return SEV_LABEL.get(severity_from_score(float(sc)), "")
    except Exception:  # noqa: BLE001
        return ""

BOX_TYPES = ("black", "grey", "white")
BOX_LABEL = {"black": "Black box", "grey": "Grey box", "white": "White box"}

# ---------------------------------------------------------------------------
# Stile del report (presets colore)
# ---------------------------------------------------------------------------

STYLE_PRESETS = {
    "default": {"label": "Default SLCtrl (logo + firma)", "color": "#0F4068"},
    "navy":   {"label": "Blu navy",            "color": "#0F4068"},
    "red":    {"label": "Rosso",              "color": "#8B1A1A"},
    "black":  {"label": "Nero",               "color": "#1F2429"},
    "green":  {"label": "Verde",              "color": "#1E5B38"},
    "yellow": {"label": "Giallo / ambra",     "color": "#8A6200"},
}
DEFAULT_AUTHOR = "Santarella Martina"
DEFAULT_COMPANY = "SLCtrl"
DEFAULT_ROLE = "Penetration Tester"
DEFAULT_SIGNATURE_IMG = "report/assets/firma.png"
DEFAULT_LOGO_IMG = "report/assets/slctrl-logo.png"


def default_style() -> dict:
    return {
        "preset": "default",
        "color": "",          # hex custom (vuoto = usa preset)
        "color2": "",         # hex accento secondario (vuoto = derivato)
        "author": "",
        "company": "",
        "role": "",
        "logo": "",           # path relativo (es. reports/<slug>/evidence/logo.png)
        "signature": "",      # path relativo immagine firma
    }


def effective_logo(style: dict) -> str:
    """Logo della cover: quello caricato, oppure il logo SLCtrl se preset default."""
    style = style or {}
    logo = (style.get("logo") or "").strip()
    if logo:
        return logo
    if style.get("preset", "default") == "default":
        return DEFAULT_LOGO_IMG
    return ""


def style_colors(style: dict) -> tuple[str, str]:
    """Ritorna (colore primario, colore accento) effettivi."""
    style = style or {}
    preset = STYLE_PRESETS.get(style.get("preset", "default"), STYLE_PRESETS["default"])
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
    preset = style.get("preset", "default")
    has_custom = bool(_norm_hex(style.get("color")) or _norm_hex(style.get("color2")))
    logo = effective_logo(style)
    if preset in ("navy", "default") and not has_custom and not logo:
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
    entry = {
        "name": name,
        "fullname": fullname,
        "type": mtype,
        "rank": rank_name,
        "severity": _msf_rank_to_sev(rank_int),
        "cves": cves,
        "description": (description or "").strip(),
        "date": date or "",
    }
    # suggerimenti per compilare TUTTI i campi del finding (offline)
    sug = _finding_suggest(
        {"title": name, "description": description, "severity": entry["severity"],
         "cves": cves, "msf": fullname},
        None, {"references": refs or [], "description": description},
        with_intel=False)
    entry.update({"cwe": sug["cwe"], "cvss": sug["cvss"],
                  "impact": sug["impact"], "remediation": sug["remediation"],
                  "refs_fmt": sug["refs"]})
    return entry


_MSF_CACHE_MEMO: dict = {}


def _msf_cache_entries() -> list[dict]:
    """Voci grezze della cache modules_metadata.json (parse memoizzato)."""
    cache = _msf_metadata_cache()
    if cache is None:
        return []
    try:
        mtime = cache.stat().st_mtime
    except OSError:
        return []
    if (_MSF_CACHE_MEMO.get("path") == str(cache)
            and _MSF_CACHE_MEMO.get("mtime") == mtime):
        return _MSF_CACHE_MEMO["entries"]
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
    _MSF_CACHE_MEMO.update(path=str(cache), mtime=mtime, entries=entries)
    return entries


def _msf_search_cache(cache: Path, query: str, limit: int) -> list[dict]:
    """Cerca nella cache modules_metadata.json (nessun processo, nessuna rete)."""
    entries = _msf_cache_entries()
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
# Fonti OFFLINE aggiuntive per i findings:
#   - Exploit-DB locale (files_exploits.csv, quello di searchsploit)
#   - template nuclei locali (~/nuclei-templates)
#   - CISA KEV + EPSS (file cachati in ~/.sealionconsole/intel/)
#   - note/vuln interne di SeaLion
# ---------------------------------------------------------------------------

INTEL_DIR = Path.home() / ".sealionconsole" / "intel"
KEV_JSON = INTEL_DIR / "kev.json"
EPSS_CSV = INTEL_DIR / "epss.csv.gz"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
_INTEL_MAX_AGE = 7 * 86400  # riscarica KEV/EPSS se più vecchi di 7 giorni

_EDB_CSV_CANDIDATES = (
    Path("/usr/share/exploitdb/files_exploits.csv"),
    Path("/opt/exploitdb/files_exploits.csv"),
    Path.home() / ".exploitdb" / "files_exploits.csv",
)

_NUCLEI_CANDIDATES = (
    Path(os.environ.get("NUCLEI_TEMPLATES", "")) if os.environ.get("NUCLEI_TEMPLATES") else None,
    Path.home() / "nuclei-templates",
    Path.home() / ".local" / "nuclei-templates",
    Path("/opt/nuclei-templates"),
)

# --- Exploit-DB (CSV locale di searchsploit) --------------------------------

_EDB_MEMO: dict = {}


def _edb_csv() -> Path | None:
    for cand in _EDB_CSV_CANDIDATES:
        if cand.is_file():
            return cand
    return None


def _edb_entries() -> list[dict]:
    """Righe del CSV Exploit-DB (parse memoizzato, ~46k exploit offline)."""
    csv_file = _edb_csv()
    if csv_file is None:
        return []
    try:
        mtime = csv_file.stat().st_mtime
    except OSError:
        return []
    if _EDB_MEMO.get("mtime") == mtime and _EDB_MEMO.get("path") == str(csv_file):
        return _EDB_MEMO["entries"]
    entries: list[dict] = []
    try:
        import csv as _csv
        with open(csv_file, newline="", encoding="utf-8",
                  errors="replace") as fh:
            for row in _csv.DictReader(fh):
                codes = str(row.get("codes") or "")
                cves = [m.group(0).upper() for m in _CVE_RE.finditer(codes)]
                entries.append({
                    "id": str(row.get("id") or "").strip(),
                    "title": str(row.get("description") or "").strip(),
                    "type": str(row.get("type") or "").strip(),
                    "platform": str(row.get("platform") or "").strip(),
                    "date": str(row.get("date_published") or "").strip(),
                    "verified": str(row.get("verified") or "").strip() == "1",
                    "cves": cves,
                    "path": str(row.get("file") or "").strip(),
                    "url": str(row.get("source_url") or "").strip(),
                })
    except OSError:
        return []
    _EDB_MEMO.update(path=str(csv_file), mtime=mtime, entries=entries)
    return entries


def _edb_search(query: str, limit: int = 10,
                cves: list[str] | None = None) -> list[dict]:
    """Cerca exploit per CVE e/o parole chiave (tutto offline)."""
    cves = [str(c).upper() for c in (cves or [])]
    terms = [t.lower() for t in query.split() if len(t.strip()) >= 3]
    out: list[dict] = []
    for e in _edb_entries():
        hit = bool(cves) and any(c in e["cves"] for c in cves)
        if not hit and terms:
            hay = f"{e['title']} {e['platform']} {e['type']}".lower()
            hit = all(t in hay for t in terms)
        if hit:
            out.append(e)
        if len(out) >= limit:
            break
    # prima i verificati, poi i più recenti
    out.sort(key=lambda e: (e["verified"], e["date"]), reverse=True)
    return out[:limit]

# --- template nuclei locali --------------------------------------------------

_NUCLEI_MEMO: dict = {}


def _nuclei_root() -> Path | None:
    for cand in _NUCLEI_CANDIDATES:
        if cand is not None and cand.is_dir():
            return cand
    return None


def _nuclei_cve_index() -> dict[str, Path]:
    """Indice CVE -> file template (i template CVE hanno il CVE nel nome)."""
    root = _nuclei_root()
    if root is None:
        return {}
    if _NUCLEI_MEMO.get("root") == str(root):
        return _NUCLEI_MEMO["index"]
    index: dict[str, Path] = {}
    try:
        for p in root.rglob("CVE-*.yaml"):
            m = _CVE_RE.search(p.stem)
            if m:
                index.setdefault(m.group(0).upper(), p)
    except OSError:
        pass
    _NUCLEI_MEMO.update(root=str(root), index=index)
    return index


def _nuclei_parse(path: Path) -> dict:
    """Estrae i campi utili dal YAML del template (regex, niente PyYAML)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    def _field(name: str) -> str:
        m = re.search(rf"^\s*{name}:\s*[\"']?([^\"'\n]+)[\"']?\s*$",
                      text, re.M)
        return m.group(1).strip() if m else ""

    sev = _field("severity").lower()
    return {
        "id": _field("id"),
        "name": _field("name"),
        "severity": sev if sev in SEV_ORDER else "",
        "description": _field("description"),
        "cvss": _field("cvss-score"),
        "cwe": (re.search(r"cwe-id:\s*\[?[\"']?(CWE-\d+)", text, re.I)
                or [None, ""])[1] if re.search(r"cwe-id", text, re.I) else "",
        "path": str(path),
    }


def _nuclei_for_cves(cves: list[str], limit: int = 5) -> list[dict]:
    index = _nuclei_cve_index()
    out: list[dict] = []
    for c in [str(x).upper() for x in cves or []]:
        p = index.get(c)
        if p is not None:
            info = _nuclei_parse(p)
            if info:
                info["cve"] = c
                out.append(info)
        if len(out) >= limit:
            break
    return out

# --- CISA KEV (JSON cachato) -------------------------------------------------

_KEV_MEMO: dict = {}


def _kev_cves() -> set[str]:
    """CVE note come attivamente sfruttate (catalogo CISA KEV cachato)."""
    if not KEV_JSON.is_file():
        return set()
    try:
        mtime = KEV_JSON.stat().st_mtime
    except OSError:
        return set()
    if _KEV_MEMO.get("mtime") == mtime:
        return _KEV_MEMO["cves"]
    cves: set[str] = set()
    try:
        data = json.loads(KEV_JSON.read_text(encoding="utf-8",
                                             errors="replace"))
        for v in data.get("vulnerabilities") or []:
            cid = str(v.get("cveID") or "").upper()
            if cid:
                cves.add(cid)
    except (json.JSONDecodeError, OSError):
        pass
    _KEV_MEMO.update(mtime=mtime, cves=cves)
    return cves

# --- EPSS (CSV gzippato cachato) ---------------------------------------------

_EPSS_MEMO: dict[str, float | None] = {}


def _epss_score(cve: str) -> float | None:
    """Probabilità di sfruttamento 0-1 (FIRST.org EPSS, cache locale)."""
    cve = cve.upper()
    if cve in _EPSS_MEMO:
        return _EPSS_MEMO[cve]
    score: float | None = None
    if EPSS_CSV.is_file():
        try:
            import gzip
            with gzip.open(EPSS_CSV, "rt", encoding="utf-8",
                           errors="replace") as fh:
                for line in fh:
                    if line.startswith(cve + ","):
                        score = float(line.split(",")[1])
                        break
        except (OSError, ValueError, IndexError):
            score = None
    _EPSS_MEMO[cve] = score
    return score

# --- note/vuln interne di SeaLion --------------------------------------------

_NOTES_MEMO: dict = {}


def _notes_corpus() -> list[tuple[str, str, str]]:
    """(relpath, nome, contenuto) delle note .md, lettura memoizzata."""
    roots = [PROJECT_ROOT / "notes", PROJECT_ROOT / "vuln"]
    try:
        sig = max((p.stat().st_mtime for root in roots if root.is_dir()
                   for p in root.rglob("*.md")), default=0.0)
    except OSError:
        sig = 0.0
    if _NOTES_MEMO.get("sig") == sig:
        return _NOTES_MEMO["corpus"]
    corpus: list[tuple[str, str, str]] = []
    for root in roots:
        if not root.is_dir():
            continue
        try:
            files = sorted(root.rglob("*.md"))
        except OSError:
            continue
        for p in files:
            try:
                body = p.read_text(encoding="utf-8", errors="replace").lower()
            except OSError:
                continue
            corpus.append((str(p.relative_to(PROJECT_ROOT)),
                           p.stem.lower(), body))
    _NOTES_MEMO.update(sig=sig, corpus=corpus)
    return corpus


def _notes_matches(cves: list[str], title: str, limit: int = 5) -> list[str]:
    """Note interne (notes/, vuln/) che citano le CVE o le parole del titolo."""
    cves = [str(c).lower() for c in (cves or [])]
    terms = [t.lower() for t in re.split(r"\W+", title or "")
             if len(t) >= 5][:4]
    if not cves and not terms:
        return []
    out: list[str] = []
    for rel, name, body in _notes_corpus():
        if any(c in name or c in body for c in cves) or \
           any(t in name for t in terms) or \
           (terms and all(t in body for t in terms)):
            out.append(rel)
        if len(out) >= limit:
            break
    return out

# --- aggregatore + download cache --------------------------------------------

def finding_intel(f: dict) -> dict:
    """Tutte le fonti offline che corrispondono al finding."""
    cves = [str(c).upper() for c in (f.get("cves") or []) if str(c).strip()]
    title = str(f.get("title") or "")
    desc = str(f.get("description") or "")
    query = f"{title} {desc}"
    kev_all = _kev_cves()
    return {
        "msf": _msf_module_for(f),
        "edb": _edb_search(query, limit=5, cves=cves),
        "nuclei": _nuclei_for_cves(cves),
        "kev": [c for c in cves if c in kev_all],
        "epss": {c: _epss_score(c) for c in cves
                 if _epss_score(c) is not None},
        "notes": _notes_matches(cves, title),
    }


def format_sources(intel: dict) -> str:
    """Riepilogo leggibile delle fonti (riga 'Fonti' del finding)."""
    parts: list[str] = []
    mod = intel.get("msf")
    if mod:
        path = str(mod.get("path") or mod.get("fullname")
                   or mod.get("ref_name") or "")
        path = re.sub(r"^/?modules/", "", path)
        parts.append(f"Metasploit `{path}`")
    for e in (intel.get("edb") or [])[:3]:
        ver = " ✓verified" if e.get("verified") else ""
        parts.append(f"Exploit-DB [EDB-{e['id']}](https://www.exploit-db.com/"
                     f"exploits/{e['id']}){ver}")
    for n in (intel.get("nuclei") or [])[:3]:
        sev = f" ({n['severity']})" if n.get("severity") else ""
        parts.append(f"nuclei `{n.get('id') or n.get('cve', '')}`{sev}")
    if intel.get("kev"):
        parts.append("[CISA KEV](https://www.cisa.gov/known-exploited-"
                     "vulnerabilities-catalog) ⚠️ sfruttata in the wild")
    for c, s in (intel.get("epss") or {}).items():
        parts.append(f"EPSS {s:.0%} ({c})")
    for note in (intel.get("notes") or [])[:3]:
        parts.append(f"nota interna `{note}`")
    return " · ".join(parts)


def _intel_refs(intel: dict) -> str:
    """URL extra per la riga 'Riferimenti' (Exploit-DB, template nuclei)."""
    out: list[str] = []
    for e in (intel.get("edb") or [])[:3]:
        out.append(f"https://www.exploit-db.com/exploits/{e['id']}")
    for n in (intel.get("nuclei") or [])[:3]:
        p = str(n.get("path") or "")
        root = _nuclei_root()
        if p and root and p.startswith(str(root)):
            rel = p[len(str(root)):].lstrip("/")
            out.append("https://github.com/projectdiscovery/"
                       f"nuclei-templates/blob/main/{rel}")
    dedup: list[str] = []
    for u in out:
        if u not in dedup:
            dedup.append(u)
    return " ".join(dedup)


def update_intel_cache(timeout: int = 15) -> None:
    """Scarica KEV + EPSS in ~/.sealionconsole/intel/ (se più vecchi di 7gg).

    Chiamata dall'auto-update all'avvio; in assenza di rete fallisce in
    silenzio e i provider usano l'ultima cache disponibile.
    """
    import urllib.request
    targets = ((KEV_JSON, KEV_URL), (EPSS_CSV, EPSS_URL))
    try:
        INTEL_DIR.mkdir(parents=True, exist_ok=True)
        for dest, url in targets:
            try:
                if dest.is_file() and \
                        time.time() - dest.stat().st_mtime < _INTEL_MAX_AGE:
                    continue
                tmp = dest.with_suffix(dest.suffix + ".tmp")
                with urllib.request.urlopen(url, timeout=timeout) as r, \
                        open(tmp, "wb") as out:
                    shutil.copyfileobj(r, out)
                tmp.replace(dest)
            except Exception:  # noqa: BLE001
                pass
    except OSError:
        pass

# ---------------------------------------------------------------------------
# Compilazione automatica dei campi del finding (SOLO dati locali, mai online)
# ---------------------------------------------------------------------------

_CWE_REF_RE = re.compile(r"CWE-(\d{1,5})", re.I)

# euristica CWE da titolo+descrizione (regex, numero CWE)
_CWE_GUESS = (
    (r"sql.?injection", "89"),
    (r"remote code execution|\brce\b|command (execution|injection)|code execution", "94"),
    (r"buffer overflow|stack overflow|heap overflow|out.of.bounds", "787"),
    (r"path traversal|directory traversal|file inclusion|\blfi\b|\brfi\b", "22"),
    (r"cross.?site scripting|\bxss\b", "79"),
    (r"cross.?site request|\bcsrf\b", "352"),
    (r"auth(entication|orization)? bypass|improper auth", "287"),
    (r"privilege escalation|privesc|elevation of privilege", "269"),
    (r"deseriali", "502"),
    (r"\bxxe\b|xml external", "611"),
    (r"default (credential|password)", "798"),
    (r"weak (ssl|tls|cipher|crypto)|obsolete (protocol|cipher)|deprecated (protocol|cipher)", "327"),
    (r"information (disclosure|leak)|info leak|sensitive data", "200"),
    (r"denial of service|\bdos\b", "400"),
    (r"spoofing|poisoning|\bllmnr\b|\bnbt.?ns\b|\bmdns\b", "290"),
    (r"cleartext|unencrypted|plain.?text (password|credential|transmission)", "319"),
    (r"weak password|brute ?force|password policy", "521"),
    (r"unrestricted upload|file upload", "434"),
    (r"outdated|unsupported (version|software)|end.of.life|missing patch", "1104"),
)

# punteggio CVSS 3.1 stimato dal rank MSF (da verificare su NVD)
_CVSS_BY_SEV = {"critical": "9.8", "high": "8.6", "medium": "6.5",
                "low": "3.7", "info": "0.0"}

_IMPACT_GUESS = (
    (r"sql.?injection",
     "Accesso non autorizzato al database: un attaccante può leggere, "
     "modificare o eliminare dati sensibili e, in alcune configurazioni, "
     "arrivare all'esecuzione di comandi sul sistema operativo sottostante."),
    (r"remote code execution|\brce\b|command (execution|injection)|code execution",
     "Esecuzione di codice arbitrario sul sistema target con i privilegi del "
     "servizio vulnerabile: un attaccante remoto può ottenere il controllo "
     "completo dell'host, compromettendo riservatezza, integrità e "
     "disponibilità dei dati, e usare la macchina come punto di appoggio "
     "verso altri sistemi della rete."),
    (r"buffer overflow|stack overflow|heap overflow|out.of.bounds",
     "Corruzione della memoria del processo vulnerabile, con possibile "
     "esecuzione di codice arbitrario e compromissione completa del sistema."),
    (r"path traversal|directory traversal|file inclusion|\blfi\b|\brfi\b",
     "Lettura (o inclusione) di file arbitrari dal filesystem del server, con "
     "possibile esposizione di credenziali, configurazioni e codice sorgente."),
    (r"cross.?site scripting|\bxss\b",
     "Esecuzione di script arbitrari nel browser delle vittime, con possibile "
     "furto di sessione e compromissione degli account utente."),
    (r"auth(entication|orization)? bypass|improper auth",
     "Aggiramento dei controlli di autenticazione: un attaccante può accedere "
     "a funzionalità e dati riservati senza possedere credenziali valide."),
    (r"privilege escalation|privesc|elevation of privilege",
     "Elevazione dei privilegi: un attaccante con accesso limitato può "
     "ottenere i privilegi di amministratore/SYSTEM sul sistema."),
    (r"deseriali",
     "Deserializzazione di dati ostili, con possibile esecuzione di codice "
     "arbitrario nel contesto dell'applicazione."),
    (r"default (credential|password)",
     "Accesso amministrativo immediato tramite credenziali predefinite note "
     "pubblicamente, con compromissione completa del dispositivo/servizio."),
    (r"weak (ssl|tls|cipher|crypto)|obsolete (protocol|cipher)",
     "Il traffico cifrato può essere intercettato e decifrato da un "
     "attaccante Man-in-the-Middle, esponendo credenziali e dati sensibili."),
    (r"information (disclosure|leak)|info leak|sensitive data",
     "Esposizione di informazioni sensibili (configurazioni, credenziali, "
     "dati interni) utili a pianificare attacchi più mirati."),
    (r"denial of service|\bdos\b",
     "Interruzione della disponibilità del servizio: un attaccante può "
     "rendere il sistema inutilizzabile per gli utenti legittimi."),
    (r"spoofing|poisoning|\bllmnr\b|\bnbt.?ns\b|\bmdns\b",
     "Intercettazione di credenziali di rete (hash NTLM) tramite risposte "
     "malevole ai broadcast di risoluzione nomi: gli hash catturati possono "
     "essere crackati offline o rigirati (relay) per autenticarsi ad altri "
     "sistemi del dominio."),
    (r"cleartext|unencrypted|plain.?text (password|credential|transmission)",
     "Credenziali e dati sensibili trasmessi in chiaro possono essere "
     "intercettati da un attaccante con accesso al segmento di rete."),
    (r"weak password|brute ?force|password policy",
     "Password deboli o prevedibili permettono a un attaccante di ottenere "
     "accesso tramite attacchi di forza bruta o password spraying."),
)

_IMPACT_BY_SEV = {
    "critical": ("Compromissione completa del sistema interessato, con "
                 "impatto critico su riservatezza, integrità e disponibilità "
                 "dei dati aziendali."),
    "high": ("Compromissione della sicurezza del sistema interessato, con "
             "potenziale impatto elevato su riservatezza, integrità e "
             "disponibilità dei dati."),
    "medium": ("Esposizione parziale del sistema: la vulnerabilità può "
               "facilitare attacchi mirati o essere combinata con altre "
               "debolezze per ottenere accessi più profondi."),
    "low": ("Impatto limitato sulla sicurezza complessiva, ma la "
            "vulnerabilità può fornire informazioni o condizioni utili a "
            "un attaccante motivato."),
    "info": ("Nessun impatto diretto: rilievo informativo utile per il "
             "miglioramento della postura di sicurezza."),
}

_REMEDIATION_GUESS = (
    (r"sql.?injection",
     "Applicare la patch del vendor (vedere riferimenti). In generale: "
     "utilizzare prepared statement / query parametrizzate, validare e "
     "filtrare tutti gli input lato server e applicare il principio del "
     "minimo privilegio all'account del database."),
    (r"default (credential|password)",
     "Modificare immediatamente le credenziali predefinite con password "
     "robuste e univoche, disabilitare gli account non necessari e "
     "verificare l'assenza di accessi pregressi nei log."),
    (r"weak (ssl|tls|cipher|crypto)|obsolete (protocol|cipher)",
     "Disabilitare protocolli e suite di cifratura obsoleti (SSLv2/v3, "
     "TLS 1.0/1.1, cifrari deboli), abilitare esclusivamente TLS 1.2+ con "
     "cifrari robusti e rinnovare i certificati se necessario."),
    (r"cross.?site scripting|\bxss\b",
     "Applicare encoding contestuale di tutti gli output, validare gli input "
     "e adottare una Content Security Policy restrittiva."),
    (r"denial of service|\bdos\b",
     "Applicare la patch del vendor, introdurre rate limiting e protezioni "
     "anti-flood a livello di rete e monitorare la disponibilità del servizio."),
    (r"spoofing|poisoning|\bllmnr\b|\bnbt.?ns\b|\bmdns\b",
     "Disabilitare LLMNR e NBT-NS su tutti gli host (via GPO), richiedere la "
     "firma SMB (SMB signing) su server e workstation e segmentare la rete "
     "per limitare i broadcast."),
    (r"cleartext|unencrypted|plain.?text (password|credential|transmission)",
     "Sostituire i protocolli in chiaro con alternative cifrate (es. SSH al "
     "posto di Telnet, HTTPS al posto di HTTP, LDAPS/SFTP) e disabilitare i "
     "servizi legacy non necessari."),
    (r"weak password|brute ?force|password policy",
     "Applicare una password policy robusta (lunghezza minima 12+ caratteri, "
     "nessuna password comune), abilitare il lockout degli account e valutare "
     "l'autenticazione multi-fattore (MFA)."),
)

_DEFAULT_REMEDIATION = (
    "Applicare gli aggiornamenti di sicurezza rilasciati dal vendor (vedere "
    "i riferimenti), verificandone l'effettiva installazione. Nel frattempo, "
    "limitare l'esposizione di rete del servizio ai soli host autorizzati "
    "tramite firewall/segmentazione e monitorare i log per tentativi di "
    "sfruttamento.")


def _msf_module_for(finding: dict) -> dict | None:
    """Voce grezza della cache MSF che corrisponde al finding (modulo o CVE)."""
    fullname = str(finding.get("msf") or "").strip().lower()
    cves = [str(c).upper() for c in (finding.get("cves") or [])]
    if not fullname and not cves:
        return None
    for e in _msf_cache_entries():
        path = str(e.get("path") or e.get("fullname")
                    or e.get("ref_name") or "").lower()
        refs = e.get("references") or e.get("refs") or []
        if isinstance(refs, str):
            refs = [refs]
        if fullname and (path == fullname or path.endswith("/" + fullname)):
            return e
        if cves:
            rtext = (" ".join(map(str, refs)) + " "
                     + str(e.get("name") or "")).upper()
            if any(c in rtext for c in cves):
                return e
    return None


def _fmt_msf_refs(refs: list, cves: list) -> str:
    """URL di riferimento: NVD per le CVE + bollettini/exploit dal modulo MSF."""
    out: list[str] = []
    for c in cves or []:
        c = str(c).upper()
        if c:
            out.append(f"https://nvd.nist.gov/vuln/detail/{c}")
    for r in refs or []:
        r = str(r).strip()
        up = r.upper()
        if not r or up.startswith(("CVE-", "CWE-")):
            continue
        if up.startswith("MSB-"):
            bid = r[4:]
            year = "20" + bid[2:4] if len(bid) >= 4 and bid[2:4].isdigit() else ""
            out.append("https://learn.microsoft.com/security-updates/"
                       f"securitybulletins/{year}/{bid.lower()}"
                       if year else bid)
        elif up.startswith("URL-"):
            out.append(r[4:])
        elif up.startswith("EDB-"):
            out.append(f"https://www.exploit-db.com/exploits/{r[4:]}")
        elif up.startswith("PACKETSTORM-"):
            out.append(f"https://packetstormsecurity.com/files/{r[12:]}")
    dedup: list[str] = []
    for u in out:
        if u not in dedup:
            dedup.append(u)
    return " ".join(dedup)


def _finding_suggest(f: dict, meta: dict | None,
                     mod: dict | None, with_intel: bool = True) -> dict:
    """Valori suggeriti per i campi del finding (100% offline, fonti locali).

    with_intel=False salta la scansione delle fonti extra (usato da
    _msf_entry, che costruisce suggerimenti per OGNI risultato di ricerca).
    """
    cves = [str(c).upper() for c in (f.get("cves") or []) if str(c).strip()]
    sev = f.get("severity", "info")
    if mod is None:
        mod = _msf_module_for(f)
    refs_list: list = []
    mod_desc = ""
    if mod:
        refs_list = mod.get("references") or mod.get("refs") or []
        if isinstance(refs_list, str):
            refs_list = [refs_list]
        mod_desc = str(mod.get("description") or "").strip()
    hay = f"{f.get('title', '')} {f.get('description', '')} {mod_desc}".lower()
    cwe = ""
    for r in refs_list:
        m = _CWE_REF_RE.search(str(r))
        if m:
            cwe = m.group(1)
            break
    if not cwe:
        for rx, num in _CWE_GUESS:
            if re.search(rx, hay, re.I):
                cwe = num
                break
    impact = next((t for rx, t in _IMPACT_GUESS if re.search(rx, hay, re.I)), "")
    if not impact:
        impact = _IMPACT_BY_SEV.get(sev, _IMPACT_BY_SEV["medium"])
    remediation = next((t for rx, t in _REMEDIATION_GUESS
                        if re.search(rx, hay, re.I)), "")
    if not remediation:
        remediation = _DEFAULT_REMEDIATION
    assets = ""
    if meta:
        hosts = [str(r.get("host", "")).strip()
                 for r in (meta.get("scope") or []) if str(r.get("host", "")).strip()]
        assets = ", ".join(hosts) or str(meta.get("domain") or "")
    # fonti offline aggiuntive: Exploit-DB, nuclei, KEV/EPSS, note interne
    intel = finding_intel(f) if with_intel else \
        {"msf": mod, "edb": [], "nuclei": [], "kev": [], "epss": {},
         "notes": []}
    if not cwe:
        for n in intel.get("nuclei") or []:
            m = re.search(r"(\d+)", str(n.get("cwe") or ""))
            if m:
                cwe = m.group(1)
                break
    cvss = _CVSS_BY_SEV.get(sev, "6.5")
    cvss_est = True
    for n in intel.get("nuclei") or []:
        if str(n.get("cvss") or "").strip():
            cvss = str(n["cvss"]).strip()
            cvss_est = False
            break
    refs = " ".join(x for x in (_fmt_msf_refs(refs_list, cves),
                                _intel_refs(intel)) if x)
    return {"cwe": cwe, "cvss": cvss, "cvss_est": cvss_est,
            "impact": impact, "remediation": remediation,
            "refs": refs, "assets": assets,
            "description": mod_desc,
            "sources": format_sources(intel)}


def _autofill_from_vector(f: dict) -> None:
    """Se c'è un vettore CVSS valido: calcola punteggio e severità mancanti."""
    vector = str(f.get("cvss_vector") or "").strip()
    if not vector:
        return
    try:
        from lib.cvss import score as cvss_score, severity_from_score, normalize
    except ImportError:
        return
    try:
        f["cvss_vector"] = normalize(vector)
        sc = cvss_score(vector)
    except ValueError:
        return  # vettore invalido: non bloccare, segnalato dal wizard
    if not str(f.get("cvss") or "").strip():
        f["cvss"] = f"{sc:.1f}"
    sev = str(f.get("severity") or "").strip().lower()
    if sev not in SEV_ORDER:
        f["severity"] = severity_from_score(sc)


def _autofill_from_nvd(f: dict) -> None:
    """Arricchimento ONLINE opzionale da NVD (se la macchina è connessa).

    Riempie solo i campi vuoti; offline fallisce in silenzio.
    """
    cves = [str(c).strip().upper() for c in (f.get("cves") or []) if str(c).strip()]
    if not cves:
        return
    needs = (not str(f.get("cvss") or "").strip()
             or not str(f.get("cvss_vector") or "").strip()
             or not str(f.get("cwe") or "").strip())
    if not needs:
        return
    try:
        from lib.nvd import nvd_lookup
    except ImportError:
        return
    data = nvd_lookup(cves[0])
    if not data:
        return
    if not str(f.get("cwe") or "").strip() and data.get("cwe"):
        f["cwe"] = data["cwe"]
    if not str(f.get("cvss_vector") or "").strip() and data.get("cvss_vector"):
        f["cvss_vector"] = data["cvss_vector"]
        _autofill_from_vector(f)
    if not str(f.get("cvss") or "").strip() and data.get("cvss"):
        f["cvss"] = str(data["cvss"])
    refs = str(f.get("refs") or "").strip()
    if not refs and data.get("refs"):
        f["refs"] = " ".join(data["refs"])


def _autofill_from_library(f: dict) -> None:
    """Fallback sulla libreria finding generici (offline): match per titolo."""
    if str(f.get("impact") or "").strip() and str(f.get("remediation") or "").strip():
        return
    title = str(f.get("title") or "").strip()
    if not title:
        return
    try:
        from lib.findinglib import library_search
    except ImportError:
        return
    results = library_search(title, limit=1)
    if not results:
        return
    entry = results[0]
    # match di sicurezza: almeno una parola del titolo deve coincidere
    twords = {w for w in re.split(r"\W+", title.lower()) if len(w) >= 4}
    ewords = {w for w in re.split(r"\W+", entry["title"].lower()) if len(w) >= 4}
    if not (twords & ewords):
        return
    if not str(f.get("description") or "").strip():
        f["description"] = entry["description"]
    if not str(f.get("impact") or "").strip():
        f["impact"] = entry["impact"]
    if not str(f.get("remediation") or "").strip():
        f["remediation"] = entry["remediation"]
    if not str(f.get("cwe") or "").strip() and entry.get("cwe"):
        f["cwe"] = entry["cwe"]
    if not str(f.get("refs") or "").strip() and entry.get("refs"):
        f["refs"] = " ".join(entry["refs"])
    if not str(f.get("cvss_vector") or "").strip() and entry.get("cvss_vector"):
        f["cvss_vector"] = entry["cvss_vector"]
        _autofill_from_vector(f)


def autofill_finding(f: dict, meta: dict | None = None) -> dict:
    """Completa i campi VUOTI del finding con i dati disponibili.

    Ordine delle fonti: vettore CVSS (calcolo locale) -> NVD (solo se online,
    riempie i vuoti) -> MSF/Exploit-DB/nuclei (offline) -> libreria finding
    generici (offline). Non sovrascrive mai il testo inserito dall'utente.
    """
    _autofill_from_vector(f)
    _autofill_from_nvd(f)
    _autofill_from_library(f)  # testi curati per i casi noti (Potato, XSS, ...)
    sug = _finding_suggest(f, meta, None)
    if not (f.get("description") or "").strip() and sug["description"]:
        f["description"] = sug["description"]
    if not (f.get("cwe") or "").strip() and sug["cwe"]:
        f["cwe"] = sug["cwe"]
    if not (f.get("cvss") or "").strip():
        f["cvss"] = (f"{sug['cvss']} (stima — verificare su NVD)"
                     if sug.get("cvss_est", True) else str(sug["cvss"]))
    if not (f.get("impact") or "").strip():
        f["impact"] = sug["impact"]
    if not (f.get("remediation") or "").strip():
        f["remediation"] = sug["remediation"]
    if not (f.get("assets") or "").strip():
        f["assets"] = sug["assets"]
    if not (f.get("refs") or "").strip():
        f["refs"] = sug["refs"]
    src = (f.get("sources") or "").strip()
    if src == "-":
        f["sources"] = ""  # "-" = nessuna fonte esplicita, non riempire
    elif not src:
        f["sources"] = sug["sources"]
    return f

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

SCHEMA_VERSION = 2


def default_meta(client: str, rtype: str, box: str, domain: str,
                 date_start: str = "", date_end: str = "") -> dict:
    return {
        "schema": SCHEMA_VERSION,
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
        # --- SLReport v2 ---
        "contacts": {"client": [], "team": []},
        "versions": [],
        "methodology": [],
        "compromised_hosts": [],
        "compromised_users": [],
        "credentials": [],
        "cleanup": [],
        "risk_override": "",
    }


def _migrate_meta(meta: dict) -> dict:
    """Porta un meta.json qualsiasi allo schema corrente (senza perdere dati)."""
    meta.setdefault("findings", [])
    meta.setdefault("scope", [])
    meta.setdefault("box", "black")
    meta.setdefault("domain", derive_domain(meta.get("client", "")))
    style = default_style()
    style.update(meta.get("style") or {})
    meta["style"] = style
    # --- SLReport v2 ---
    contacts = meta.get("contacts")
    if not isinstance(contacts, dict):
        contacts = {}
    contacts.setdefault("client", [])
    contacts.setdefault("team", [])
    meta["contacts"] = contacts
    for key in ("versions", "methodology", "compromised_hosts",
                "compromised_users", "credentials", "cleanup"):
        if not isinstance(meta.get(key), list):
            meta[key] = []
    meta.setdefault("risk_override", "")
    meta["schema"] = SCHEMA_VERSION
    return meta


def load_meta(slug: str) -> dict | None:
    mp = _meta_path(slug)
    if not mp.is_file():
        return None
    try:
        meta = json.loads(mp.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return _migrate_meta(meta)


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
    custom = (meta.get("approccio_custom") or "").strip()
    if custom:
        return custom.replace(DEFAULT_COMPANY, _company(meta))
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
                 ": Tabella: Dettagli del Perimetro")
        return intro + table
    rows = "\n".join(f"| `{r['host']}` | {r['desc']} |" for r in scope)
    table = ("\n\n| **Host/URL/Indirizzo IP** | **Descrizione** |\n"
             "|---------------------------|-----------------|\n"
             f"{rows}\n\n: Tabella: Dettagli del Perimetro")
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
    custom = (meta.get("panoramica_custom") or "").strip()
    if custom:
        return custom.replace(DEFAULT_COMPANY, _company(meta))
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
        ": Tabella: Riepilogo per Severità")
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
        + "\n".join(list_rows) + "\n\n: Tabella: Elenco dei Finding")
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
        alt = caption  # alt vuoto se non c'è didascalia: niente sottotitolo nel PDF
        blocks.append(f"![{alt}]({path})")
        if caption:
            blocks.append(f"*Figura: {caption}*")
    return "\n\n".join(blocks)


def _fmt_cvss_cell(f: dict) -> str:
    """'7.5 (Alta)' con eventuale marcatura di stima."""
    cvss = str(f.get("cvss") or "").strip()
    if not cvss:
        return "*—*"
    m = re.match(r"^(\d+(?:\.\d+)?)", cvss)
    if not m:
        return cvss
    sev = severity_label_from_score(float(m.group(1)))
    est = " (stima)" if "stima" in cvss else ""
    return f"{m.group(1)} ({sev}){est}"


def render_finding(idx: int, f: dict) -> str:
    sev = f.get("severity", "info")
    label = SEV_LABEL.get(sev, sev)
    head = f"## SLC-{idx:02d} – {f.get('title', 'Senza titolo')} – <span class=\"sev sev-{sev}\">{label}</span>"
    cves = [c for c in (f.get("cves") or []) if str(c).strip()]
    rows = [
        ("CWE", _fmt_cwe(f.get("cwe", ""))),
        ("Punteggio CVSS 3.1", _fmt_cvss_cell(f)),
    ]
    vector = str(f.get("cvss_vector") or "").strip()
    if vector:
        rows.append(("Vettore CVSS", f"`{vector}`"))
    if cves:
        rows.append(("CVE", ", ".join(str(c).upper() for c in cves)))
    mitre = [str(t).strip() for t in (f.get("mitre") or []) if str(t).strip()]
    if mitre:
        rows.append(("MITRE ATT&CK", ", ".join(mitre)))
    status = str(f.get("status") or "").strip().lower()
    if status in STATUS_LABEL:
        rows.append(("Stato", f'<span class="status-badge {STATUS_CLASS[status]}">'
                              f"{STATUS_LABEL[status]}</span>"))
    rows += [
        ("Descrizione (incl. causa)", f.get("description", "")),
        ("Impatto", f.get("impact", "")),
        ("Asset Interessati", f.get("assets", "")),
        ("Remediation", f.get("remediation", "")),
        ("Riferimenti", f.get("refs", "") or "*—*"),
    ]
    if (f.get("sources") or "").strip():
        rows.append(("Fonti", f["sources"]))
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
    # campi vuoti completati dai dati offline di MSF (senza toccare meta.json)
    filled = [autofill_finding(dict(f), meta) for f in findings]
    return "\n\n---\n\n".join(render_finding(i, f) for i, f in enumerate(filled, 1))


def render_firma(meta: dict) -> str:
    """Blocco firma finale: autore, azienda e immagine firma (sezione Stile)."""
    style = meta.get("style") or {}
    author = (style.get("author") or "").strip()
    company = (style.get("company") or "").strip()
    role = (style.get("role") or "").strip() or DEFAULT_ROLE
    sig_img = (style.get("signature") or "").strip()
    is_default = style.get("preset", "default") == "default"
    if not author and not company and not is_default:
        return ""  # niente blocco firma finché la sezione Stile è vuota
    if is_default:
        company = company or DEFAULT_COMPANY
    if not sig_img:
        sig_img = DEFAULT_SIGNATURE_IMG
    name = author or DEFAULT_AUTHOR
    role_line = role if not company else f"{role} — {company}"
    return ('<div class="signature">\n'
            f'<img src="{sig_img}" alt="Firma"><br>\n'
            f'<span class="sig-name">{name}</span><br>\n'
            f'<span class="sig-role">{role_line}</span>\n'
            '</div>')


# ---------------------------------------------------------------------------
# SLReport v2 — contatti, versioni, metodologia, rischio, appendici strutturate
# ---------------------------------------------------------------------------

SEV_HEX = {"critical": "#B71C1C", "high": "#C62828", "medium": "#E65100",
           "low": "#2E7D32", "info": "#1565C0"}

STATUS_LABEL = {"open": "Aperto", "fixed": "Risolto",
                "partial": "Parzialmente risolto", "retest": "In retest",
                "accepted": "Rischio accettato"}
STATUS_CLASS = {"open": "status-open", "fixed": "status-fixed",
                "partial": "status-partial", "retest": "status-retest",
                "accepted": "status-accepted"}

METHODOLOGIES = {
    "OSSTMM": ("OSSTMM (Open Source Security Testing Methodology Manual) — "
               "metodologia aperta per la misurazione operativa della sicurezza, "
               "con focus su visibilità, controlli e fiducia."),
    "PTES": ("PTES (Penetration Testing Execution Standard) — standard che "
             "definisce le fasi del penetration test: intelligence gathering, "
             "threat modeling, analisi delle vulnerabilità, exploitation e "
             "post-exploitation."),
    "OWASP": ("OWASP Testing Guide / OWASP Top 10 — linee guida di riferimento "
              "per il test delle applicazioni web e la classificazione dei "
              "rischi applicativi più comuni."),
    "NIST SP 800-115": ("NIST SP 800-115 (Technical Guide to Information "
                        "Security Testing and Assessment) — guida tecnica del "
                        "NIST per la pianificazione e l'esecuzione di test di "
                        "sicurezza."),
    "MITRE ATT&CK": ("MITRE ATT&CK — knowledge base delle tattiche e tecniche "
                     "di attacco osservate in the wild, usata per classificare "
                     "le attività offensive dell'assessment."),
}


def _contacts_table(title: str, rows: list[dict]) -> str:
    body = "\n".join(
        f"| {r.get('name', '')} | {r.get('role', '')} | {r.get('email', '')} |"
        for r in rows)
    return (f"| **{title}** | | |\n"
            "|---|---|---|\n"
            "| **Nome** | **Ruolo** | **Email** |\n"
            f"{body}\n\n: Tabella: {title}")


def render_contatti(meta: dict) -> str:
    contacts = meta.get("contacts") or {}
    client_rows = [r for r in (contacts.get("client") or [])
                   if str(r.get("name", "")).strip()]
    team_rows = [r for r in (contacts.get("team") or [])
                 if str(r.get("name", "")).strip()]
    parts = []
    if client_rows:
        parts.append(_contacts_table("Contatti del Cliente", client_rows))
    if team_rows:
        parts.append(_contacts_table(f"Contatto {_company(meta)}", team_rows))
    return "\n\n".join(parts)


def render_versioni(meta: dict) -> str:
    rows = [v for v in (meta.get("versions") or [])
            if str(v.get("version", "")).strip()]
    if not rows:
        return ""
    body = "\n".join(
        f"| {v.get('version', '')} | {v.get('date', '')} | "
        f"{v.get('author', '')} | {v.get('desc', '')} |" for v in rows)
    return ("| **Versione** | **Data** | **Autore** | **Descrizione** |\n"
            "|---|---|---|---|\n"
            f"{body}\n\n: Tabella: Storico delle versioni")


def render_metodologia(meta: dict) -> str:
    chosen = [m for m in (meta.get("methodology") or []) if m in METHODOLOGIES]
    if not chosen:
        return ""
    intro = ("L'assessment è stato condotto in conformità alle metodologie e "
             "agli standard di riferimento riconosciuti a livello "
             "internazionale:")
    items = "\n".join(f"- **{m}**: {METHODOLOGIES[m]}" for m in chosen)
    return f"{intro}\n\n{items}"


def overall_risk(meta: dict) -> str:
    """Rischio complessivo: override manuale oppure derivato dai conteggi."""
    override = (meta.get("risk_override") or "").strip().lower()
    if override in SEV_ORDER:
        return override
    counts = _sev_counts(meta.get("findings", []))
    if counts["critical"] > 0:
        return "critical"
    if counts["high"] > 0 or counts["medium"] >= 3:
        return "high"
    if counts["medium"] > 0:
        return "medium"
    if counts["low"] > 0:
        return "low"
    if counts["info"] > 0:
        return "info"
    return ""


def _sev_chart_html(counts: dict[str, int]) -> str:
    """Grafico a barre orizzontali delle severity (HTML+CSS, reso da weasyprint)."""
    total = sum(counts.values())
    if total == 0:
        return ""
    rows = []
    for sev in SEV_ORDER:
        n = counts[sev]
        pct = max(2.0, n / total * 100.0) if n else 0.0
        fill = (f'<div class="risk-fill" style="width:{pct:.1f}%;'
                f'background:{SEV_HEX[sev]}"></div>' if n else "")
        rows.append(
            f'<div class="risk-row"><span class="risk-label">{SEV_LABEL[sev]}</span>'
            f'<div class="risk-bar">{fill}</div>'
            f'<span class="risk-num">{n}</span></div>')
    return '<div class="risk-chart">' + "".join(rows) + "</div>"


def render_rischio(meta: dict) -> str:
    findings = meta.get("findings", [])
    if not findings:
        return ""
    counts = _sev_counts(findings)
    risk = overall_risk(meta)
    chart = _sev_chart_html(counts)
    if not risk:
        return chart
    label = SEV_LABEL[risk]
    badge = f'<span class="sev sev-{risk}">{label}</span>'
    return (f'{chart}\n\n<div class="risk-total">Il livello di rischio '
            f"complessivo dell'infrastruttura analizzata è valutato come "
            f"{badge}, considerando il numero, la severità e la concatenabilità "
            "dei finding identificati.</div>")


def render_appendice_host(meta: dict) -> str:
    rows = [h for h in (meta.get("compromised_hosts") or [])
            if str(h.get("host", "")).strip()]
    if not rows:
        return ""
    body = "\n".join(
        f"| {h.get('host', '')} | `{h.get('ip', '')}` | {h.get('os', '')} | "
        f"{h.get('access', '')} | {h.get('technique', '')} |" for h in rows)
    return ("| **Host** | **Indirizzo IP** | **Sistema operativo** | "
            "**Livello di accesso ottenuto** | **Tecnica** |\n"
            "|---|---|---|---|---|\n"
            f"{body}\n\n: Tabella: Host compromessi durante l'assessment")


def render_appendice_utenti(meta: dict) -> str:
    rows = [u for u in (meta.get("compromised_users") or [])
            if str(u.get("user", "")).strip()]
    if not rows:
        return ""
    body = "\n".join(
        f"| `{u.get('user', '')}` | {u.get('domain', '')} | "
        f"{u.get('access', '')} | {u.get('source', '')} |" for u in rows)
    return ("| **Utente** | **Dominio** | **Livello di accesso** | "
            "**Metodo di compromissione** |\n"
            "|---|---|---|---|\n"
            f"{body}\n\n: Tabella: Account compromessi durante l'assessment")


def render_appendice_bonifica(meta: dict) -> str:
    rows = [c for c in (meta.get("cleanup") or [])
            if str(c.get("desc", "")).strip()]
    if not rows:
        return ""
    body = "\n".join(
        f"| {c.get('desc', '')} | {c.get('status', '')} |" for c in rows)
    return ("| **Modifica / Artefatto** | **Stato della bonifica** |\n"
            "|---|---|\n"
            f"{body}\n\n: Tabella: Modifiche effettuate e attività di bonifica")


def render_appendice_password(meta: dict) -> str:
    rows = [c for c in (meta.get("credentials") or [])
            if str(c.get("value", "")).strip() or str(c.get("username", "")).strip()]
    if not rows:
        return ""
    body = "\n".join(
        f"| {c.get('title', '')} | {c.get('username', '')} | "
        f"{c.get('url', '')} | {c.get('notes', '')} | `{c.get('value', '')}` |"
        for c in rows)
    return ("| **Titolo** | **Nome utente** | **URL** | **Note** | "
            "**Valore / Password** |\n"
            "|---|---|---|---|---|\n"
            f"{body}\n\n: Tabella: Credenziali e password recuperate durante l'assessment")


_RENDERERS = {
    "contatti": render_contatti,
    "versioni": render_versioni,
    "metodologia": render_metodologia,
    "approccio": render_approccio,
    "perimetro": render_perimetro,
    "panoramica": render_panoramica,
    "riepilogo": render_riepilogo,
    "rischio": render_rischio,
    "findings": render_findings,
    "appendice_host": render_appendice_host,
    "appendice_utenti": render_appendice_utenti,
    "appendice_bonifica": render_appendice_bonifica,
    "appendice_password": render_appendice_password,
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
    date_report = (meta.get("date_report") or "").strip()
    if date_report:
        md_text = _sub("date", date_report, md_text)
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


_CAPTION_RE = re.compile(r"^:\s*Tabella(?:\s+\d+)?:", re.M)


def renumber_captions(md_text: str) -> str:
    """Rinumera le didascalie ': Tabella N:' in sequenza (1..n) nell'intero
    documento: corregge duplicati e numeri lasciati dal template."""
    counter = 0
    in_code = False
    out_lines = []
    for ln in md_text.split("\n"):
        if re.match(r"^\s*(```|~~~)", ln):
            in_code = not in_code
            out_lines.append(ln)
            continue
        if not in_code and _CAPTION_RE.match(ln):
            counter += 1
            ln = re.sub(r"^(:\s*)Tabella(?:\s+\d+)?:", rf"\g<1>Tabella {counter}:", ln)
        out_lines.append(ln)
    return "\n".join(out_lines)


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
    return renumber_captions(text + firma)


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
                    "date_end", "time_start", "time_end", "scope", "findings",
                    "style", "contacts", "versions", "methodology",
                    "compromised_hosts", "compromised_users", "credentials",
                    "cleanup", "risk_override"):
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
    text = text.replace("{{CONTATTI}}", render_contatti(meta))
    text = text.replace("{{VERSIONI}}", render_versioni(meta))
    text = text.replace("{{METODOLOGIA}}", render_metodologia(meta))
    text = text.replace("{{APPROCCIO}}", render_approccio(meta))
    text = text.replace("{{PERIMETRO}}", render_perimetro(meta))
    text = text.replace("{{PANORAMICA}}", render_panoramica(meta))
    text = text.replace("{{RIEPILOGO}}", render_riepilogo(meta))
    text = text.replace("{{RISCHIO}}", render_rischio(meta))
    text = text.replace("{{FINDINGS}}", render_findings(meta))
    text = text.replace("{{APP_HOST}}", render_appendice_host(meta))
    text = text.replace("{{APP_UTENTI}}", render_appendice_utenti(meta))
    text = text.replace("{{APP_BONIFICA}}", render_appendice_bonifica(meta))
    text = text.replace("{{APP_PASSWORD}}", render_appendice_password(meta))
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
    sev = (finding.get("severity") or "").strip().lower()
    if sev not in SEV_ORDER:
        sev = ""  # vuota: derivata dal vettore CVSS in autofill, o 'info'
    finding["cves"] = [str(c).strip().upper() for c in (finding.get("cves") or [])
                       if str(c).strip()]
    finding["mitre"] = [re.sub(r"^T", "T", str(t).strip().upper())
                        for t in (finding.get("mitre") or []) if str(t).strip()]
    status = (finding.get("status") or "").strip().lower()
    finding["status"] = status if status in STATUS_LABEL else ""
    finding["cvss_vector"] = str(finding.get("cvss_vector") or "").strip()
    finding["images"] = [{"path": str(im.get("path", "")).strip(),
                          "caption": str(im.get("caption", "")).strip()}
                         for im in (finding.get("images") or [])
                         if isinstance(im, dict) and str(im.get("path", "")).strip()]
    # completa i campi lasciati vuoti (CVSS dal vettore, NVD online, libreria, MSF)
    autofill_finding(finding, meta)
    if not finding.get("severity"):
        finding["severity"] = "info"
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
# Watcher: rebuild automatico del PDF quando cambia il .md
# ---------------------------------------------------------------------------

_WATCH_POLL = 2.0        # secondi tra un controllo e l'altro
_WATCH_DEBOUNCE = 1.5    # attesa dopo l'ultima modifica prima di rebuildare
_WATCH_MAX_AGE = 8 * 3600  # il watcher si spegne da solo dopo 8 ore


def _watch_paths(slug: str) -> tuple[Path, Path]:
    folder = REPORTS_DIR / slug
    return folder / ".watch.pid", folder / ".watch.log"


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def watcher_running(slug: str) -> bool:
    pid_file, _ = _watch_paths(slug)
    try:
        pid = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        return False
    return _pid_alive(pid)


def start_watcher(slug: str) -> tuple[bool, str]:
    """Avvia (se non già attivo) il rebuild automatico del PDF al salvataggio del .md."""
    if watcher_running(slug):
        return True, "auto-rebuild già attivo"
    pid_file, log_file = _watch_paths(slug)
    try:
        log = open(log_file, "a", encoding="utf-8")
        proc = subprocess.Popen(
            [sys.executable, "-m", "lib.report", "--watch", slug],
            cwd=PROJECT_ROOT, stdin=subprocess.DEVNULL,
            stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        pid_file.write_text(str(proc.pid))
        return True, f"auto-rebuild attivo (pid {proc.pid}): il PDF si aggiorna a ogni salvataggio del .md"
    except OSError as e:
        return False, f"Impossibile avviare il watcher: {e}"


def stop_watcher(slug: str) -> tuple[bool, str]:
    pid_file, _ = _watch_paths(slug)
    try:
        pid = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        return False, "Nessun watcher attivo."
    if _pid_alive(pid):
        try:
            os.kill(pid, 15)
        except OSError as e:
            return False, f"Impossibile fermare il watcher: {e}"
    pid_file.unlink(missing_ok=True)
    return True, "Auto-rebuild fermato."


def _watch_daemon(slug: str) -> int:
    """Loop del watcher (processo figlio): rebuild del PDF a ogni modifica del .md."""
    rep = find_report(slug)
    if rep is None:
        return 1
    md = Path(rep["md"])
    pid_file, _ = _watch_paths(slug)
    started = time.time()

    def log(msg: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] {msg}", flush=True)

    log(f"watcher avviato su {md.name}")
    last = md.stat().st_mtime if md.is_file() else 0.0
    while md.is_file() and time.time() - started < _WATCH_MAX_AGE:
        time.sleep(_WATCH_POLL)
        # fermato dall'utente (pidfile rimosso o riassegnato)
        try:
            if int(pid_file.read_text().strip()) != os.getpid():
                break
        except (OSError, ValueError):
            break
        try:
            mtime = md.stat().st_mtime
        except OSError:
            continue
        if mtime == last:
            continue
        last = mtime
        time.sleep(_WATCH_DEBOUNCE)  # debounce: attende la fine del salvataggio
        try:
            if load_meta(slug):
                sync_report(slug)
            ok, msg = build_report(slug)
            log(("PDF aggiornato" if ok else f"build fallito: {msg}"))
        except Exception as e:  # noqa: BLE001
            log(f"errore: {e}")
    pid_file.unlink(missing_ok=True)
    log("watcher terminato")
    return 0


# ---------------------------------------------------------------------------
# Editor esterno / build PDF
# ---------------------------------------------------------------------------

def _find_editor() -> str | None:  # noqa: F811
    for cand in _VSCODE_CANDIDATES:
        exe = shutil.which(cand)
        if exe:
            return exe
    return None


def _win_path(p: Path) -> str | None:
    """Percorso Windows di un file WSL (via wslpath), None se non disponibile."""
    wslpath = shutil.which("wslpath")
    if not wslpath:
        return None
    try:
        r = subprocess.run([wslpath, "-w", str(p)],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _try_launch_pdf_editor(pdf: Path) -> tuple[bool, str]:
    """Primo tentativo di apertura con gli editor Linux noti."""
    for cand, extra_args in _PDF_EDITOR_CANDIDATES:
        exe = shutil.which(cand)
        if exe:
            try:
                subprocess.Popen(
                    [exe, *extra_args, str(pdf)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                return True, f"Aperto in {cand}: {pdf}"
            except OSError:
                continue
    return False, ""


def _has_gui() -> bool:
    """True se c'è un display grafico (Linux nativo o WSLg)."""
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) \
        or Path("/mnt/wslg").is_dir()


def _install_pdf_editor() -> bool:
    """Installa automaticamente l'editor PDF (apt) se il sistema lo supporta."""
    if not shutil.which("apt-get") or not _has_gui():
        return False
    print(f"\033[94m[*]\033[0m Nessun editor PDF trovato: installo "
          f"\033[1m{_PDF_EDITOR_AUTO_PACKAGE}\033[0m (apt)…")
    try:
        r = subprocess.run(
            ["sudo", "apt-get", "install", "-y", _PDF_EDITOR_AUTO_PACKAGE],
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def _open_pdf(pdf: Path) -> tuple[bool, str]:
    """Apre il PDF in un editor: LibreOffice Draw/Xournal++ su Linux
    (auto-installato se mancante), altrimenti (WSL) l'app Windows
    associata ai .pdf (Acrobat, Word, ...)."""
    ok, msg = _try_launch_pdf_editor(pdf)
    if ok:
        return True, msg
    # Nessun editor: prova l'installazione automatica, poi riprova
    if _install_pdf_editor():
        ok, msg = _try_launch_pdf_editor(pdf)
        if ok:
            return True, msg
    # Fallback WSL: app Windows predefinita per i .pdf
    win = _win_path(pdf)
    pwsh = shutil.which("powershell.exe")
    if win and pwsh:
        try:
            subprocess.Popen(
                [pwsh, "-NoProfile", "-Command", f"Start-Process '{win}'"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return True, (f"Aperto con l'app Windows predefinita: {pdf}\n"
                          "  (per modificarlo 'tipo Word': aprilo con Word/Acrobat)")
        except OSError:
            pass
    if win and shutil.which("explorer.exe"):
        try:
            subprocess.Popen(
                ["explorer.exe", win],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return True, f"Aperto con Windows: {pdf}"
        except OSError:
            pass
    xdg = shutil.which("xdg-open")
    if xdg:
        subprocess.Popen([xdg, str(pdf)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
        return True, f"Aperto con il visualizzatore predefinito: {pdf}"
    return False, (f"Nessun editor PDF trovato e installazione automatica non riuscita.\n"
                   f"Apri manualmente: {pdf}\n"
                   f"Installa un editor con: sudo apt install {_PDF_EDITOR_AUTO_PACKAGE} "
                   "(oppure xournalpp)")


def _ensure_pdf_fresh(rep: dict) -> tuple[bool, str]:
    """Garantisce che il PDF esista e sia aggiornato rispetto al .md."""
    md = Path(rep["md"])
    pdf = md.with_suffix(".pdf")
    if pdf.is_file() and pdf.stat().st_mtime >= md.stat().st_mtime:
        return True, str(pdf)
    if load_meta(rep["slug"]):
        sync_report(rep["slug"])
    return build_report(rep["slug"])


def edit_report(name: str | None, mode: str | None = None) -> tuple[bool, str]:
    rep = find_report(name)
    if rep is None:
        return False, "Report non trovato. Usa 'report list' per vedere quelli esistenti."
    mode = (mode or "md").strip().lower()

    if mode in _EDIT_PDF_MODES:
        ok, msg = _ensure_pdf_fresh(rep)
        if not ok:
            return False, f"Impossibile generare il PDF: {msg}"
        opened, open_msg = _open_pdf(Path(msg))
        watch_ok, watch_msg = start_watcher(rep["slug"])
        suffix = f"\n  {watch_msg}" if watch_ok else ""
        return opened, open_msg + suffix

    # modalità testo: VS Code (o derivati) sul .md
    folder = str(Path(rep["md"]).parent)
    editor = _find_editor() or shutil.which("code.cmd")
    if not editor:
        return False, ("VS Code non trovato nel PATH (cercati: " +
                       ", ".join(_VSCODE_CANDIDATES) + ").\n"
                       f"Apri manualmente: {folder}")
    try:
        subprocess.Popen(
            [editor, folder],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as e:
        return False, f"Impossibile avviare {editor}: {e}"
    watch_ok, watch_msg = start_watcher(rep["slug"])
    suffix = f"\n  {watch_msg}" if watch_ok else ""
    return True, f"Aperto in {Path(editor).name}: {folder}{suffix}"


def render_report_html(md_text: str, meta: dict | None = None) -> tuple[bool, str]:
    """Renderizza il markdown in HTML standalone con la STESSA pipeline del PDF
    (pandoc + template slctrl + override di stile), ma con il CSS inline
    invece che come <link>: usata per l'anteprima WYSIWYG nel browser,
    così l'anteprima è identica al documento finale.
    Ritorna (ok, html | messaggio di errore)."""
    meta = meta or {}
    pandoc = shutil.which("pandoc")
    if not pandoc:
        local = Path.home() / ".local" / "bin" / "pandoc"
        pandoc = str(local) if local.is_file() else None
    if not pandoc:
        return False, "pandoc non trovato. Installalo: sudo apt install pandoc"

    md_text = filter_empty_sections(md_text)
    tmp_md = tempfile.NamedTemporaryFile(
        mode="w", suffix=".md", dir=PROJECT_ROOT, delete=False, encoding="utf-8",
        prefix=".report-preview-")
    tmp_md.write(md_text)
    tmp_md.close()
    tmp_md_path = Path(tmp_md.name)

    # Stessa logica del build: stile custom + logo/azienda nella cover
    style = meta.get("style") or {}
    extra_css = style_overrides_css(meta)
    company = (style.get("company") or "").strip()
    logo = effective_logo(style)
    html_text = TEMPLATE_HTML.read_text(encoding="utf-8")
    if logo:
        html_text = html_text.replace(
            '<div class="cover-client">',
            f'<img class="cover-logo" src="{html_escape_attr(logo)}" alt="Logo"><br>\n'
            '    <div class="cover-client">', 1)
    if company and company != DEFAULT_COMPANY:
        html_text = html_text.replace(DEFAULT_COMPANY, company)
    tmp_tpl = tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", dir=PROJECT_ROOT, delete=False, encoding="utf-8",
        prefix=".report-preview-tpl-")
    tmp_tpl.write(html_text)
    tmp_tpl.close()
    tmp_tpl_path = Path(tmp_tpl.name)

    tmp_out = tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", dir=PROJECT_ROOT, delete=False, encoding="utf-8")
    tmp_out.close()
    tmp_out_path = Path(tmp_out.name)
    try:
        r = subprocess.run(
            [pandoc, str(tmp_md_path), "--standalone",
             "--from", "markdown-tex_math_dollars",
             "--template", str(tmp_tpl_path),
             "--toc", "--toc-depth=2",
             "--no-highlight",
             "-o", str(tmp_out_path)],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            return False, f"pandoc fallito:\n{r.stderr.strip()}"
        out = tmp_out_path.read_text(encoding="utf-8")
    except subprocess.TimeoutExpired:
        return False, "Timeout durante il rendering dell'anteprima."
    except Exception as e:  # noqa: BLE001
        return False, f"Errore durante il rendering: {e}"
    finally:
        tmp_md_path.unlink(missing_ok=True)
        tmp_tpl_path.unlink(missing_ok=True)
        tmp_out_path.unlink(missing_ok=True)

    # CSS inline (stesso file del build + override di stile)
    css_text = TEMPLATE_CSS.read_text(encoding="utf-8")
    if extra_css:
        css_text += "\n" + extra_css
    out = out.replace("</head>", "<style>\n" + css_text + "\n</style>\n</head>", 1)
    return True, out


def render_template_html() -> tuple[bool, str]:
    """Anteprima WYSIWYG del template vuoto, con dati di esempio:
    stessa pipeline pandoc + slctrl del PDF finale."""
    client, rtype, domain = "Nome Cliente", "Penetration Test Interno", "CLIENTE.LOCAL"
    months = ("gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno",
              "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre")
    now = datetime.datetime.now()
    today = f"{now.day} {months[now.month - 1]} {now.year}"
    meta = default_meta(client, rtype, "black", domain, "", "")
    text = TEMPLATE_MD.read_text(encoding="utf-8")
    text = text.replace("{{CLIENT}}", client)
    text = text.replace("{{RTYPE}}", rtype)
    text = text.replace("{{DATE}}", today)
    text = text.replace("{{DOMAIN}}", domain)
    text = text.replace("{{SLUG}}", "nome-cliente")
    text = text.replace("{{CONTATTI}}", render_contatti(meta))
    text = text.replace("{{VERSIONI}}", render_versioni(meta))
    text = text.replace("{{METODOLOGIA}}", render_metodologia(meta))
    text = text.replace("{{APPROCCIO}}", render_approccio(meta))
    text = text.replace("{{PERIMETRO}}", render_perimetro(meta))
    text = text.replace("{{PANORAMICA}}", render_panoramica(meta))
    text = text.replace("{{RIEPILOGO}}", render_riepilogo(meta))
    text = text.replace("{{RISCHIO}}", render_rischio(meta))
    text = text.replace("{{FINDINGS}}", render_findings(meta))
    text = text.replace("{{APP_HOST}}", render_appendice_host(meta))
    text = text.replace("{{APP_UTENTI}}", render_appendice_utenti(meta))
    text = text.replace("{{APP_BONIFICA}}", render_appendice_bonifica(meta))
    text = text.replace("{{APP_PASSWORD}}", render_appendice_password(meta))
    text = text.replace("{{FIRMA}}", render_firma(meta))
    return render_report_html(text, meta)


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
    logo = effective_logo(style)
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
    # html template: sempre rigenerato (metadati PDF + logo/azienda custom)
    author = (style.get("author") or "").strip() or DEFAULT_AUTHOR
    meta_tags = (
        f'<meta name="author" content="{html_escape_attr(author)}">\n'
        f'<meta name="description" content="{html_escape_attr((meta.get("rtype") or "Penetration Test") + " — " + (meta.get("client") or rep["slug"]))}">\n'
        f'<meta name="keywords" content="penetration test, security assessment, {html_escape_attr(meta.get("client") or "")}">\n'
        '<meta name="generator" content="SLCtrl SLReport">\n'
    )
    html_text = TEMPLATE_HTML.read_text(encoding="utf-8")
    html_text = html_text.replace("</head>", meta_tags + "</head>", 1)
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
             "--from", "markdown-tex_math_dollars",
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
    print(f"  report edit {slug}     # apri in VS Code per il testo libero (PDF auto-aggiornato)")
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
    refs = r.get("refs_fmt") or \
        " ".join(f"https://nvd.nist.gov/vuln/detail/{c}" for c in r["cves"])
    if not refs:
        refs = f"https://www.rapid7.com/db/modules/{r['fullname']}"
    return {
        "title": r["name"].replace("_", " ").strip().title() or r["fullname"],
        "severity": r["severity"],
        "cves": r["cves"],
        "cwe": r.get("cwe", ""),
        "cvss": f"{r['cvss']} (stima)" if r.get("cvss") else "",
        "description": r["description"] or f"Modulo Metasploit: {r['fullname']}",
        "impact": r.get("impact", ""),
        "remediation": r.get("remediation", ""),
        "refs": refs,
        "msf": r["fullname"],
    }


def _ask_library_prefill() -> dict:
    """Cerca nella libreria di finding generici (offline) e prepara i campi."""
    try:
        from lib.findinglib import library_search, finding_from_library
    except ImportError:
        return {}
    try:
        q = _ask("Cerca nella libreria finding (es. xss, potato, smbv1 — invio per saltare)")
    except KeyboardInterrupt:
        raise
    if not q:
        return {}
    results = library_search(q, limit=8)
    if not results:
        print("  \033[93m[~]\033[0m Nessuna voce in libreria per questa ricerca.")
        return {}
    print(f"  \033[92m[+]\033[0m {len(results)} voci in libreria:\n")
    for i, e in enumerate(results, 1):
        cat = f"[{e['category']}] " if e.get("category") else ""
        cvss = f" — CVSS {e['cvss']:.1f}" if "cvss" in e else ""
        print(f"    [{i}] \033[1m{e['title']}\033[0m ({cat}"
              f"{SEV_LABEL.get(e.get('severity',''), e.get('severity',''))}{cvss})")
        if e.get("description"):
            print(f"        {e['description'][:110]}")
    try:
        pick = _ask("Usa la voce n. (invio per nessuna)")
    except KeyboardInterrupt:
        raise
    if not pick.isdigit() or not (1 <= int(pick) <= len(results)):
        return {}
    return finding_from_library(results[int(pick) - 1])


def _ask_cvss_vector() -> str:
    """Chiede un vettore CVSS 3.1 e mostra subito punteggio/severità calcolati."""
    try:
        from lib.cvss import CVSSError, describe
    except ImportError:
        return ""
    try:
        v = _ask("Vettore CVSS 3.1 (es. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H — invio per omettere)")
    except KeyboardInterrupt:
        raise
    if not v:
        return ""
    try:
        d = describe(v)
    except CVSSError as e:
        print(f"  \033[91m[!]\033[0m Vettore non valido: {e}")
        return ""
    print(f"  \033[92m[+]\033[0m Punteggio calcolato: {d['score']:.1f} "
          f"({SEV_LABEL.get(d['severity'], '')})")
    return d["vector"]


def interactive_add_finding(slug: str) -> int:
    rep = find_report(slug)
    if rep is None:
        print("\033[91m[!]\033[0m Report non trovato. Usa 'report list'.", file=sys.stderr)
        return 1
    slug = rep["slug"]
    print(f"\n\033[1mNuovo finding — {rep['client']}\033[0m\n")
    while True:
        try:
            pre = _ask_library_prefill()
            if pre:
                print("  \033[92m[+]\033[0m Campi precompilati dalla libreria (modifica ciò che serve).")
            if not pre:
                pre = _ask_msf_prefill()
                if pre:
                    print("  \033[92m[+]\033[0m Campi precompilati da Metasploit (modifica ciò che serve).")
            title = _ask("Titolo del finding", pre.get("title", ""))
            if not title:
                print("Annullato (titolo vuoto).")
                return 1
            print("  Severità: 1) Critica  2) Alta  3) Media  4) Bassa  5) Info  "
                  "0) dal vettore CVSS")
            sev_default = {v: str(i) for i, v in enumerate(
                ("critical", "high", "medium", "low", "info"), 1)}.get(pre.get("severity", "high"), "2")
            sev_n = _ask("Scelta", sev_default)
            severity = {"1": "critical", "2": "high", "3": "medium", "4": "low",
                        "5": "info"}.get(sev_n, pre.get("severity", ""))
            cvss_vector = _ask_cvss_vector() or pre.get("cvss_vector", "")
            cves = pre.get("cves") or []
            cve_raw = _ask("CVE (separate da virgola, invio per omettere)",
                           ", ".join(cves))
            cves = [c.strip().upper() for c in cve_raw.split(",") if c.strip()]
            cwe = _ask("CWE (solo numero, es. 522 — invio per omettere)",
                       pre.get("cwe", ""))
            cvss = _ask("Punteggio CVSS 3.1 (vuoto = dal vettore; invio per omettere)",
                        pre.get("cvss", ""))
            mitre_raw = _ask("MITRE ATT&CK (es. T1190, T1059 — invio per omettere)",
                             ", ".join(pre.get("mitre") or []))
            mitre = [t.strip().upper() for t in mitre_raw.split(",") if t.strip()]
            status_raw = _ask("Stato (open/fixed/partial/retest/accepted)", "open")
            desc = _ask("Descrizione (incl. causa)", pre.get("description", ""))
            impact = _ask("Impatto", pre.get("impact", ""))
            assets = _ask("Asset interessati", load_meta(slug).get("domain", ""))
            remediation = _ask("Remediation", pre.get("remediation", ""))
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
                   "cvss_vector": cvss_vector, "cves": cves, "mitre": mitre,
                   "status": status_raw, "description": desc, "impact": impact,
                   "assets": assets, "remediation": remediation, "refs": refs,
                   "evidence": evidence, "images": images, "msf": pre.get("msf", ""),
                   "library_id": pre.get("library_id", "")}
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
    print("  report add <nome|num>           Wizard: aggiungi un finding (libreria + MSF + NVD)")
    print("  report lib [ricerca]            Libreria finding generici offline (xss, potato...)")
    print("  report sync <nome|num>          Rigenera i blocchi automatici nel .md")
    print("  report edit <nome|num> [modo]   Modifica il report:")
    print("  \033[90m                              vsc / vscode / md (default): VS Code sul .md")
    print("  \033[90m                              pdf: apre il PDF in un editor (LibreOffice, Word...)\033[0m")
    print("  \033[90m                              In entrambi i casi il PDF si riaggiorna da solo")
    print("  \033[90m                              a ogni salvataggio del .md (auto-rebuild)\033[0m")
    print("  report watch <nome|num>         Attiva l'auto-rebuild del PDF")
    print("  report unwatch <nome|num>       Disattiva l'auto-rebuild")
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
    print("  - 'report add' precompila da: libreria finding (offline, vuln/library/),")
    print("    db LOCALE di Metasploit (offline), NVD (solo se la macchina è online)")
    print("  - Il vettore CVSS 3.1 calcola da solo punteggio e severità")
    print("  - Le sezioni lasciate vuote non compaiono nel PDF (né titoli né spazi)")
    print("  - 'report edit' (testo) cerca nel PATH: " + ", ".join(_VSCODE_CANDIDATES))
    print("  - 'report edit <nome> pdf' cerca: " +
          ", ".join(c for c, _ in _PDF_EDITOR_CANDIDATES) +
          f" — se mancano, installa da solo {_PDF_EDITOR_AUTO_PACKAGE} (apt);")
    print("    su WSL senza GUI apre l'app Windows predefinita")
    print("  - Con 'report edit' il PDF si rebuilda da solo a ogni salvataggio del .md")
    print("    (watcher in background, log in reports/<cliente>/.watch.log)")
    print("  - Su SLWeb: wizard guidato sezione per sezione in \033[96m/report\033[0m")
    print()


def cmd_lib(query: str | None) -> int:
    """Cerca/elenca la libreria di finding generici (offline)."""
    try:
        from lib.findinglib import library_search, library_entries
    except ImportError:
        print("\033[91m[!]\033[0m Libreria non disponibile.", file=sys.stderr)
        return 1
    if query:
        results = library_search(query, limit=15)
        if not results:
            print(f"\nNessuna voce per '{query}'. Prova: xss, sqli, potato, smbv1, keepass...\n")
            return 1
    else:
        results = library_entries()
        if not results:
            print("\nLibreria vuota: aggiungi file .md in vuln/library/\n")
            return 1
    print(f"\n\033[1mLibreria finding\033[0m — {len(results)} voci"
          + (f" per '{query}'" if query else "") + ":\n")
    last_cat = None
    for e in results:
        if not query and e.get("category") != last_cat:
            last_cat = e.get("category")
            print(f"  \033[94;1m{last_cat}\033[0m")
        cvss = f"CVSS {e['cvss']:.1f}" if "cvss" in e else "—"
        sev = SEV_LABEL.get(e.get("severity", ""), "?")
        prefix = "    " if not query else "  "
        print(f"{prefix}\033[1m{e['id']}\033[0m — {e['title']} "
              f"(\033[96m{sev}\033[0m, {cvss})")
    print("\nUsa la voce da wizard: '\033[96mreport add <report>\033[0m' → cerca in libreria.\n")
    return 0


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

    if action == "lib":
        return cmd_lib(target)

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
        # Modi: report edit <target> [pdf|vsc|vscode|md]  oppure  report edit pdf <target>
        mode = None
        if target and target.strip().lower() in _EDIT_MD_MODES | _EDIT_PDF_MODES:
            target, mode = extra, target
        elif extra and extra.strip().lower() in _EDIT_MD_MODES | _EDIT_PDF_MODES:
            mode = extra
        ok, msg = edit_report(target, mode)
        print(("\033[92m[+]\033[0m " if ok else "\033[91m[!]\033[0m ") + msg)
        return 0 if ok else 1

    if action in ("watch", "unwatch"):
        rep = find_report(target)
        if rep is None:
            print("\033[91m[!]\033[0m Report non trovato.", file=sys.stderr)
            return 1
        if action == "watch":
            ok, msg = start_watcher(rep["slug"])
        else:
            ok, msg = stop_watcher(rep["slug"])
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


# ---------------------------------------------------------------------------
# Entry point per il watcher: python -m lib.report --watch <slug>
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--watch":
        sys.exit(_watch_daemon(sys.argv[2]))
    print("Uso: python -m lib.report --watch <slug>", file=sys.stderr)
    sys.exit(2)
