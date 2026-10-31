"""Arricchimento ONLINE (opzionale) dei finding via API NVD 2.0.

- Offline-first: se la rete non c'è (o scade il timeout) ritorna None e
  tutto il resto della pipeline continua con i dati locali (MSF/EDB/nuclei).
- Cache su disco in ~/.sealionconsole/intel/nvd/<CVE>.json (30 giorni).
- Mai eccezioni verso il chiamante: qualsiasi errore -> None.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from pathlib import Path

INTEL_DIR = Path.home() / ".sealionconsole" / "intel"
NVD_CACHE = INTEL_DIR / "nvd"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
_CACHE_MAX_AGE = 30 * 86400  # 30 giorni
_TIMEOUT = 5.0               # secondi: la UI non deve bloccarsi

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
_UA = {"User-Agent": "SLCtrl-SeaLion/1.0 (pentest reporting)"}


def _cache_path(cve: str) -> Path:
    return NVD_CACHE / f"{cve.upper()}.json"


def _read_cache(cve: str) -> dict | None:
    p = _cache_path(cve)
    try:
        if p.is_file() and time.time() - p.stat().st_mtime < _CACHE_MAX_AGE:
            data = json.loads(p.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) and data.get("cve") else None
    except (OSError, json.JSONDecodeError):
        return None
    return None


def _write_cache(cve: str, data: dict) -> None:
    try:
        NVD_CACHE.mkdir(parents=True, exist_ok=True)
        _cache_path(cve).write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass


def _parse_nvd(payload: dict) -> dict | None:
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return None
    cve_obj = (vulns[0] or {}).get("cve") or {}
    cve_id = str(cve_obj.get("id") or "").upper()
    if not cve_id:
        return None
    desc = ""
    for d in cve_obj.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = str(d.get("value") or "").strip()
            break
    # CVSS 3.1 (preferito) -> 3.0
    cvss, vector = "", ""
    metrics = cve_obj.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        lst = metrics.get(key) or []
        if lst:
            data = (lst[0] or {}).get("cvssData") or {}
            if data.get("baseScore") is not None:
                cvss = str(data["baseScore"])
                vector = str(data.get("vectorString") or "")
                break
    # CWE
    cwe = ""
    for w in cve_obj.get("weaknesses") or []:
        for d in w.get("description") or []:
            val = str(d.get("value") or "")
            m = re.search(r"CWE-(\d+)", val)
            if m and m.group(1) not in ("NVD-noinfo",):
                cwe = m.group(1)
                break
        if cwe:
            break
    refs = []
    for r in cve_obj.get("references") or []:
        url = str((r or {}).get("url") or "").strip()
        if url:
            refs.append(url)
    return {"cve": cve_id, "cvss": cvss, "cvss_vector": vector,
            "cwe": cwe, "description": desc, "refs": refs[:5]}


def nvd_lookup(cve: str) -> dict | None:
    """Dati NVD di una CVE: {cve, cvss, cvss_vector, cwe, description, refs}.

    Ritorna None se offline, non trovata o qualsiasi errore. Cache 30gg.
    """
    cve = (cve or "").strip().upper()
    if not _CVE_RE.match(cve):
        return None
    cached = _read_cache(cve)
    if cached is not None:
        return cached
    try:
        req = urllib.request.Request(NVD_API + cve, headers=_UA)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            payload = json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 - offline, DNS, timeout, rate limit...
        return None
    data = _parse_nvd(payload)
    if data is not None:
        _write_cache(cve, data)
    return data
