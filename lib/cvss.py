"""Calcolatore CVSS 3.1 (Base Score) — implementazione della spec FIRST.

Uso:
    from lib.cvss import score, severity_from_score, validate
    sc = score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")  # 9.8

Nessuna dipendenza esterna, nessuna rete.
"""

from __future__ import annotations

import math

# metriche obbligatorie della Base Metrics (CVSS v3.1)
_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": "U", "C": "C"},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

# PR dipende dallo Scope
_PR = {"N": 0.85, "L": {"U": 0.62, "C": 0.68}, "H": {"U": 0.27, "C": 0.50}}

SEVERITY_RANGES = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
)


class CVSSError(ValueError):
    """Vettore CVSS malformato o incompleto."""


def parse(vector: str) -> dict[str, str]:
    """Valida e scompone un vettore CVSS 3.1. Solleva CVSSError se invalido."""
    v = (vector or "").strip()
    if not v:
        raise CVSSError("vettore vuoto")
    if v.upper().startswith("CVSS:3.1/"):
        v = v[9:]
    elif v.upper().startswith("CVSS:3.0/"):
        v = v[9:]
    parts = {}
    for token in v.split("/"):
        if ":" not in token:
            raise CVSSError(f"token malformato: {token!r}")
        key, _, val = token.partition(":")
        key, val = key.strip().upper(), val.strip().upper()
        if key in parts:
            raise CVSSError(f"metrica duplicata: {key}")
        parts[key] = val
    missing = [m for m in _METRICS if m not in parts]
    if missing:
        raise CVSSError("metriche mancanti: " + ", ".join(missing))
    for key in _METRICS:
        if key == "PR":
            if parts["PR"] not in _PR:
                raise CVSSError(f"PR non valido: {parts['PR']!r}")
        elif parts[key] not in _VALUES[key]:
            raise CVSSError(f"{key} non valido: {parts[key]!r}")
    return parts


def _roundup(x: float) -> float:
    """Roundup ufficiale CVSS: il più piccolo numero a 1 decimale >= x."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def score(vector: str) -> float:
    """Base score (0.0-10.0) di un vettore CVSS 3.1. Solleva CVSSError."""
    m = parse(vector)
    scope = m["S"]
    isc = 1.0 - (1 - _VALUES["C"][m["C"]]) * (1 - _VALUES["I"][m["I"]]) * (1 - _VALUES["A"][m["A"]])
    if scope == "U":
        impact = 6.42 * isc
    else:
        impact = 7.52 * (isc - 0.029) - 3.25 * (isc - 0.02) ** 15
    pr_val = _PR[m["PR"]] if m["PR"] == "N" else _PR[m["PR"]][scope]
    exploitability = 8.22 * _VALUES["AV"][m["AV"]] * _VALUES["AC"][m["AC"]] * pr_val * _VALUES["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def severity_from_score(sc: float) -> str:
    """0.0-10.0 -> critical|high|medium|low|info (fasce CVSS ufficiali)."""
    try:
        sc = float(sc)
    except (TypeError, ValueError):
        return "info"
    for threshold, sev in SEVERITY_RANGES:
        if sc >= threshold:
            return sev
    return "info"


def validate(vector: str) -> bool:
    """True se il vettore è sintatticamente valido e completo."""
    try:
        parse(vector)
        return True
    except CVSSError:
        return False


def normalize(vector: str) -> str:
    """Forma canonica 'CVSS:3.1/AV:.../A:..' (metriche in ordine standard)."""
    m = parse(vector)
    return "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in _METRICS)


def describe(vector: str) -> dict:
    """{score, severity, vector} pronto per il report. Solleva CVSSError."""
    sc = score(vector)
    return {"score": sc, "severity": severity_from_score(sc),
            "vector": normalize(vector)}
