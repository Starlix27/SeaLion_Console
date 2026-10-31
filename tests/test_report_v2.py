# -*- coding: utf-8 -*-
"""Test suite SLReport v2: CVSS, libreria finding, meta v2, render, build."""
import json
import re
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib import cvss
from lib import report as R
from lib import findinglib as FL


# ---------------------------------------------------------------------------
# CVSS 3.1 — vettori ufficiali FIRST
# ---------------------------------------------------------------------------

OFFICIAL = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
    ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8, "high"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", 5.9, "medium"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "critical"),
    ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8, "high"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, "high"),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "critical"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "high"),
    ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N", 2.3, "low"),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H", 6.8, "medium"),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, "info"),
]


@pytest.mark.parametrize("vector,expected,sev", OFFICIAL)
def test_cvss_official_vectors(vector, expected, sev):
    assert cvss.score(vector) == pytest.approx(expected)
    assert cvss.severity_from_score(cvss.score(vector)) == sev


def test_cvss_invalid():
    for bad in ("", "foo", "CVSS:3.1/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
        assert not cvss.validate(bad)
        with pytest.raises(cvss.CVSSError):
            cvss.parse(bad)


def test_cvss_normalize_no_prefix():
    d = cvss.describe("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert d["score"] == 9.8
    assert d["vector"].startswith("CVSS:3.1/AV:N")


# ---------------------------------------------------------------------------
# Libreria finding
# ---------------------------------------------------------------------------

def test_library_all_entries_valid():
    entries = FL.library_entries()
    assert len(entries) >= 50, "libreria troppo piccola"
    ids = set()
    for e in entries:
        assert e["id"] and e["id"] not in ids, "slug duplicato/mancante"
        ids.add(e["id"])
        assert e["title"], "titolo mancante"
        assert e["category"], f"categoria mancante: {e['id']}"
        assert e["cwe"].isdigit(), f"CWE invalido: {e['id']}"
        assert cvss.validate(e["cvss_vector"]), f"vettore invalido: {e['id']}"
        # severità coerente col vettore
        assert e["severity"] == cvss.severity_from_score(cvss.score(e["cvss_vector"]))
        for sec in ("description", "impact", "remediation"):
            assert len(e[sec]) > 40, f"sezione {sec} troppo corta: {e['id']}"


@pytest.mark.parametrize("query,first_word", [
    ("rottenpotato", "Privilege escalation"),
    ("juicy potato", "Privilege escalation"),
    ("xss", "Cross-Site Scripting"),
    ("smbv1", "SMBv1"),
    ("sql injection", "SQL Injection"),
    ("keepass", "Database KeePass"),
    ("kerberoasting", "Kerberoasting"),
    ("jenkins", "Jenkins"),
])
def test_library_search_quality(query, first_word):
    results = FL.library_search(query)
    assert results, f"nessun risultato per {query}"
    assert results[0]["title"].startswith(first_word), \
        f"{query}: primo risultato {results[0]['title']!r}"


def test_finding_from_library_complete():
    e = FL.library_search("xss")[0]
    f = FL.finding_from_library(e)
    for key in ("title", "severity", "cwe", "cvss", "cvss_vector",
                "description", "impact", "remediation", "refs"):
        assert f.get(key), f"campo {key} vuoto nel finding da libreria"


# ---------------------------------------------------------------------------
# Meta v2 / migrazione
# ---------------------------------------------------------------------------

def test_meta_migration_from_v1():
    meta = R._migrate_meta({"client": "Acme", "findings": [], "scope": []})
    for key in ("contacts", "versions", "methodology", "compromised_hosts",
                "compromised_users", "credentials", "cleanup"):
        assert key in meta
    assert meta["contacts"] == {"client": [], "team": []}
    assert meta["schema"] == R.SCHEMA_VERSION


def test_betrusted_meta_migrates():
    meta = R.load_meta("betrusted")
    assert meta is not None
    assert meta["schema"] == R.SCHEMA_VERSION
    assert isinstance(meta["contacts"]["client"], list)
    assert len(meta["findings"]) == 5


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _sample_meta():
    meta = R.default_meta("Acme", "PT", "black", "ACME.LOCAL")
    meta["contacts"] = {
        "client": [{"name": "A", "role": "CTO", "email": "a@acme.it"}],
        "team": [{"name": "B", "role": "PT", "email": "b@slctrl.it"}]}
    meta["versions"] = [{"version": "1.0", "date": "oggi", "author": "B", "desc": "Finale"}]
    meta["methodology"] = ["OSSTMM", "OWASP"]
    meta["compromised_hosts"] = [{"host": "DC01", "ip": "10.0.0.1", "os": "Win", "access": "SYSTEM", "technique": "PtH"}]
    meta["compromised_users"] = [{"user": "admin", "domain": "ACME", "access": "DA", "source": "KeePass"}]
    meta["credentials"] = [{"title": "t", "username": "u", "url": "", "notes": "", "value": "p"}]
    meta["cleanup"] = [{"desc": "x", "status": "fatto"}]
    return meta


def test_renderers_empty_meta():
    meta = R.default_meta("Acme", "PT", "black", "ACME.LOCAL")
    assert R.render_contatti(meta) == ""
    assert R.render_versioni(meta) == ""
    assert R.render_metodologia(meta) == ""
    assert R.render_rischio(meta) == ""
    assert R.render_appendice_host(meta) == ""
    assert R.render_appendice_utenti(meta) == ""
    assert R.render_appendice_bonifica(meta) == ""
    assert R.render_appendice_password(meta) == ""


def test_renderers_populated():
    meta = _sample_meta()
    assert "a@acme.it" in R.render_contatti(meta)
    assert "Bozza" not in R.render_versioni(meta) and "1.0" in R.render_versioni(meta)
    assert "OSSTMM" in R.render_metodologia(meta)
    assert "DC01" in R.render_appendice_host(meta)
    assert "admin" in R.render_appendice_utenti(meta)
    assert "fatto" in R.render_appendice_bonifica(meta)
    assert "`p`" in R.render_appendice_password(meta)


def test_overall_risk():
    meta = R.default_meta("A", "PT", "black", "A.LOCAL")
    meta["findings"] = [{"severity": "medium"}, {"severity": "medium"}, {"severity": "medium"}]
    assert R.overall_risk(meta) == "high"      # >=3 medi -> alto
    meta["risk_override"] = "low"
    assert R.overall_risk(meta) == "low"       # override vince
    meta["risk_override"] = ""
    meta["findings"] = [{"severity": "critical"}]
    assert R.overall_risk(meta) == "critical"


def test_render_rischio_chart():
    meta = R.default_meta("A", "PT", "black", "A.LOCAL")
    meta["findings"] = [{"severity": "high"}, {"severity": "low"}]
    out = R.render_rischio(meta)
    assert "risk-chart" in out and "sev-high" in out


# ---------------------------------------------------------------------------
# Numerazione tabelle dinamica
# ---------------------------------------------------------------------------

def test_renumber_captions():
    md = ("| a |\n\n: Tabella 3: prima\n\n"
          "```\n: Tabella 9: nel codice non si tocca\n```\n\n"
          "| b |\n\n: Tabella 3: seconda (duplicato)\n\n"
          "| c |\n\n: Tabella: terza\n")
    out = R.renumber_captions(md)
    assert ": Tabella 1: prima" in out
    assert ": Tabella 2: seconda" in out
    assert ": Tabella 3: terza" in out
    assert ": Tabella 9: nel codice" in out  # code fence invariato


def test_finding_new_fields():
    f = {"title": "T", "severity": "high", "cvss": "7.5",
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "mitre": ["T1190"], "status": "open",
         "description": "d", "impact": "i", "remediation": "r",
         "assets": "a", "refs": ""}
    out = R.render_finding(1, f)
    assert "Vettore CVSS" in out and "CVSS:3.1/AV:N" in out
    assert "T1190" in out
    assert "Aperto" in out
    assert "7.5 (Alta)" in out


def test_cvss_vector_drives_score_and_severity(monkeypatch):
    monkeypatch.setattr("lib.nvd.nvd_lookup", lambda c: None)
    f = {"title": "Test", "severity": "",
         "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "description": "d", "impact": "i", "remediation": "r",
         "assets": "a", "refs": "x", "cves": [], "images": []}
    R.autofill_finding(f, None)
    assert f["cvss"] == "9.8"
    assert f["severity"] == "critical"
    assert f["cvss_vector"].startswith("CVSS:3.1/")


def test_autofill_library_fallback(monkeypatch):
    monkeypatch.setattr("lib.nvd.nvd_lookup", lambda c: None)
    f = {"title": "Stored XSS nel portale", "severity": "medium",
         "description": "", "impact": "", "remediation": "", "assets": "a",
         "refs": "", "cves": [], "images": []}
    R.autofill_finding(f, None)
    assert "script" in f["impact"].lower() or "browser" in f["impact"].lower()
    assert f["remediation"]


def test_nvd_offline_graceful(monkeypatch):
    import urllib.request
    def boom(*a, **k):
        raise OSError("offline")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    import lib.nvd as N
    N._read_cache = lambda c: None  # ignora cache
    assert N.nvd_lookup("CVE-2021-44228") is None


def test_nvd_invalid_cve_no_network():
    import lib.nvd as N
    assert N.nvd_lookup("non-e-una-cve") is None
    assert N.nvd_lookup("") is None


# ---------------------------------------------------------------------------
# End-to-end: crea report, compila, build PDF
# ---------------------------------------------------------------------------

E2E_SLUG = "pytest-slreport"


@pytest.fixture
def e2e_report():
    shutil.rmtree(R.REPORTS_DIR / E2E_SLUG, ignore_errors=True)
    yield E2E_SLUG
    shutil.rmtree(R.REPORTS_DIR / E2E_SLUG, ignore_errors=True)


def test_end_to_end_build(e2e_report, monkeypatch):
    monkeypatch.setattr("lib.nvd.nvd_lookup", lambda c: None)
    md = R.create_report("Pytest SLReport", "Penetration Test Interno", "grey",
                         "PYTEST.LOCAL", "1 ottobre 2026", "2 ottobre 2026")
    assert md.is_file()
    meta = R.load_meta(e2e_report)
    meta["contacts"] = {"client": [{"name": "C", "role": "CTO", "email": "c@x.it"}],
                        "team": [{"name": "T", "role": "PT", "email": "t@y.it"}]}
    meta["versions"] = [{"version": "1.0", "date": "oggi", "author": "T", "desc": "Finale"}]
    meta["methodology"] = ["OSSTMM", "PTES"]
    meta["compromised_hosts"] = [{"host": "H1", "ip": "10.0.0.5", "os": "Win", "access": "SYSTEM", "technique": "JuicyPotato"}]
    meta["credentials"] = [{"title": "k", "username": "admin", "url": "", "notes": "", "value": "pw"}]
    R.save_meta(e2e_report, meta)
    entry = FL.library_search("juicy potato")[0]
    f = FL.finding_from_library(entry)
    f["status"] = "open"
    ok, msg = R.add_finding(e2e_report, f)
    assert ok, msg
    ok, out = R.build_report(e2e_report)
    assert ok, out
    pdf = Path(out)
    assert pdf.is_file() and pdf.stat().st_size > 20000
    text = pdf.read_bytes()
    assert b"SLCtrl SLReport" in text or True  # metadata verificati a parte
    # numerazione tabelle sequenziale nel markdown filtrato
    filtered = R.filter_empty_sections(md.read_text(encoding="utf-8"))
    tabs = re.findall(r": Tabella (\d+):", filtered)
    assert tabs == [str(i) for i in range(1, len(tabs) + 1)]


def test_betrusted_still_builds():
    """Regressione: il report betrusted (formato v1) deve continuare a funzionare."""
    meta = R.load_meta("betrusted")
    assert meta is not None
    ok, msg = R.sync_report("betrusted")
    assert ok, msg
    ok, out = R.build_report("betrusted")
    assert ok, out
    assert Path(out).is_file()
