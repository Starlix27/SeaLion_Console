"""Libreria di finding generici (offline): vuln/library/*.md.

Ogni file è un Markdown con frontmatter YAML:

    ---
    title: "Cross-Site Scripting (XSS) riflesso"
    aliases: ["xss", ...]
    category: "Web"
    cwe: "79"
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    severity: "medium"            # derivata dal vettore (coerenza verificata)
    mitre: ["T1059.007"]
    refs: ["https://..."]
    ---
    ## Descrizione / ## Impatto / ## Remediation

I finding di libreria NON richiedono una CVE precisa: sono schede riusabili
(per XSS, RottenPotato, SMBv1, ...) che precompilano il wizard e che
l'utente adatta al caso specifico.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

import yaml

from lib.cvss import score as cvss_score, severity_from_score, validate as cvss_validate

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LIBRARY_DIR = PROJECT_ROOT / "vuln" / "library"

SECTIONS = ("descrizione", "impatto", "remediation")

_MEMO: dict = {}


def slugify(title: str) -> str:
    s = unicodedata.normalize("NFKD", title.lower()).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", s).strip("-")[:60]


def _parse_file(path: Path) -> dict | None:
    """Frontmatter YAML + sezioni ## Descrizione/Impatto/Remediation."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", text, re.S)
    if not m:
        return None
    try:
        meta = yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        return None
    if not isinstance(meta, dict) or not str(meta.get("title") or "").strip():
        return None
    body = m.group(2)
    # estrae le sezioni "## Titolo" -> contenuto
    secs: dict[str, str] = {}
    cur: str | None = None
    buf: list[str] = []
    for line in body.splitlines():
        h = re.match(r"^##\s+(.+?)\s*$", line)
        if h:
            if cur is not None:
                secs[cur] = "\n".join(buf).strip()
            cur, buf = h.group(1).strip().lower(), []
        elif cur is not None:
            buf.append(line)
    if cur is not None:
        secs[cur] = "\n".join(buf).strip()
    entry = {
        "id": path.stem,
        "title": str(meta.get("title") or "").strip(),
        "aliases": [str(a) for a in (meta.get("aliases") or [])],
        "category": str(meta.get("category") or "").strip(),
        "cwe": str(meta.get("cwe") or "").strip(),
        "cvss_vector": str(meta.get("cvss_vector") or "").strip(),
        "severity": str(meta.get("severity") or "").strip().lower(),
        "mitre": [str(t) for t in (meta.get("mitre") or [])],
        "refs": [str(r) for r in (meta.get("refs") or [])],
        "description": secs.get("descrizione", ""),
        "impact": secs.get("impatto", ""),
        "remediation": secs.get("remediation", ""),
        "path": str(path),
    }
    # severità derivata dal vettore se possibile (coerenza garantita)
    if cvss_validate(entry["cvss_vector"]):
        entry["cvss"] = cvss_score(entry["cvss_vector"])
        entry["severity"] = severity_from_score(entry["cvss"])
    return entry


def library_entries() -> list[dict]:
    """Tutte le voci della libreria (parse memoizzato su mtime)."""
    if not LIBRARY_DIR.is_dir():
        return []
    try:
        files = sorted(LIBRARY_DIR.glob("*.md"))
        sig = tuple((p.name, p.stat().st_mtime) for p in files)
    except OSError:
        return []
    if _MEMO.get("sig") == sig:
        return _MEMO["entries"]
    entries = [e for e in (_parse_file(p) for p in files) if e]
    _MEMO.clear()
    _MEMO.update(sig=sig, entries=entries)
    return entries


def library_get(entry_id: str) -> dict | None:
    for e in library_entries():
        if e["id"] == entry_id:
            return e
    return None


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKD", s.lower()).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", " ", s).strip()


def _score_entry(e: dict, q_raw: str, terms: list[str]) -> float:
    """Punteggio di match: alias esatti > alias parziali > titolo > testo."""
    title_n = _norm(e["title"])
    aliases_n = [_norm(a) for a in e["aliases"]]
    q_n = _norm(q_raw)
    sc = 0.0
    if q_n:
        if q_n in aliases_n:
            sc += 100.0
        elif any(q_n == a or q_n in a.split() for a in aliases_n for a in [a]):
            sc += 80.0
        elif any(q_n in a for a in aliases_n):
            sc += 60.0
        if q_n == title_n:
            sc += 70.0
        elif q_n in title_n:
            sc += 50.0
    hay_title = f" {title_n} "
    hay_all = _norm(" ".join([e["title"], " ".join(e["aliases"]),
                              e["category"], e["description"]]))
    for t in terms:
        tn = _norm(t)
        if not tn:
            continue
        if f" {tn} " in hay_title:
            sc += 12.0
        if any(tn in a or a in tn for a in aliases_n if len(a) >= 3):
            sc += 15.0
        if tn in hay_all:
            sc += 4.0
    return sc


def library_search(query: str, limit: int = 10) -> list[dict]:
    """Ricerca offline: capisce alias tecnici ('rottenpotato', 'xss', 'smbv1')."""
    q = (query or "").strip()
    entries = library_entries()
    if not q:
        return entries[:limit]
    terms = [t for t in re.split(r"\W+", q) if len(t) >= 2]
    scored = [(_score_entry(e, q, terms), e) for e in entries]
    scored = [x for x in scored if x[0] > 0]
    scored.sort(key=lambda x: -x[0])
    return [e for _, e in scored[:limit]]


def finding_from_library(entry: dict) -> dict:
    """Voce di libreria -> dict finding pronto per report add / wizard."""
    return {
        "title": entry["title"],
        "severity": entry["severity"],
        "cwe": entry["cwe"],
        "cvss_vector": entry["cvss_vector"],
        "cvss": (f"{entry['cvss']:.1f}" if "cvss" in entry else ""),
        "cves": [],
        "mitre": list(entry.get("mitre") or []),
        "description": entry["description"],
        "impact": entry["impact"],
        "remediation": entry["remediation"],
        "refs": " ".join(entry.get("refs") or []),
        "library_id": entry["id"],
    }
