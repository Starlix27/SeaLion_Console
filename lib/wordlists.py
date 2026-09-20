"""Ricerca automatica delle wordlist nel filesystem.

Invece di assumere che SecLists viva solo in /usr/share/seclists, questo
modulo risolve i percorsi delle wordlist cercando nelle posizioni tipiche
del sistema operativo:

  1. variabili d'ambiente (SECLISTS_PATH, SEALION_WORDLISTS)
  2. percorsi dei pacchetti (Kali/Parrot/BlackArch: /usr/share/seclists,
     /usr/share/wordlists/...) e clone git (/opt/SecLists, ~/SecLists, ...)
  3. directory del progetto SeaLion (wordlists/, lib/)
  4. database di locate(1), se disponibile
  5. find con profondità limitata su /usr/share, /usr/local/share, /opt

I risultati positivi sono tenuti in cache su disco
(~/.cache/sealion/wordlists.json), quelli negativi solo in memoria per
pochi minuti (così una `install seclists` fatta nel frattempo viene vista).

Uso:
    from lib import wordlists
    path = wordlists.find_wordlist("/usr/share/seclists/Discovery/Web-Content/common.txt")
    if path is None:
        print(wordlists.fix_hint("/usr/share/seclists/Discovery/Web-Content/common.txt"))
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

# Componenti che segnano l'inizio della parte relativa di un path SecLists
_SECLISTS_TOP = (
    "Discovery", "Passwords", "Usernames", "Fuzzing", "Web-Shells",
    "Miscellaneous", "Pattern-Matching", "Payloads-All-The-Things",
    "AI-LLM-Testing",
)

# Radici in cui può trovarsi un'installazione/clone di SecLists
_BASE_CANDIDATES = (
    "/usr/share/seclists",            # pacchetto apt Kali/Parrot
    "/usr/share/wordlists/seclists",
    "/usr/share/wordlists/SecLists",
    "/usr/share/SecLists",
    "/usr/local/share/seclists",
    "/usr/local/share/SecLists",
    "/opt/SecLists",
    "/opt/seclists",
    "/usr/share/wordlists/SecLists-master",
    "/snap/seclists/current",
)

# Directory "piatte" di wordlist (rockyou, dirb, john, metasploit, ...)
_FLAT_DIRS = (
    "/usr/share/wordlists",
    "/usr/share/dirb/wordlists",
    "/usr/share/dirbuster",
    "/usr/share/john",
    "/usr/local/share/wordlists",
)

# Radici per il find di fallback (profondità limitata)
_SEARCH_ROOTS = ("/usr/share", "/usr/local/share", "/opt")

_FIND_TIMEOUT = 10            # secondi massimi per il find di fallback
_MEM_TTL_NEG = 120            # i "non trovato" in memoria scadono dopo 2 minuti
_DISK_TTL = 30 * 24 * 3600    # i "trovato" su disco valgono 30 giorni

_MISS = object()
_mem: dict[str, tuple[float, str | None]] = {}
_disk: dict[str, list] | None = None


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _cache_file() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "sealion" / "wordlists.json"


def _load_disk() -> dict:
    global _disk
    if _disk is None:
        try:
            data = json.loads(_cache_file().read_text())
            _disk = data if isinstance(data, dict) else {}
        except Exception:
            _disk = {}
    return _disk


def _save_disk() -> None:
    try:
        path = _cache_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(_disk or {}))
    except Exception:
        pass


def _cache_get(key: str):
    """Ritorna il path trovato, None (mancante) o _MISS se non in cache."""
    entry = _mem.get(key)
    if entry:
        ts, val = entry
        if val is not None and os.path.isfile(val):
            return val
        if val is None and time.time() - ts < _MEM_TTL_NEG:
            return None
    disk = _load_disk()
    entry = disk.get(key)
    if entry:
        try:
            ts, val = entry
        except (TypeError, ValueError):
            disk.pop(key, None)
            return _MISS
        if time.time() - ts < _DISK_TTL and val and os.path.isfile(val):
            _mem[key] = (time.time(), val)
            return val
        disk.pop(key, None)
    return _MISS


def _cache_put(key: str, val: str | None) -> None:
    _mem[key] = (time.time(), val)
    if val:
        disk = _load_disk()
        disk[key] = [time.time(), val]
        _save_disk()


def clear_cache() -> None:
    """Svuota la cache (es. dopo aver installato nuove wordlist)."""
    _mem.clear()
    global _disk
    _disk = {}
    try:
        _cache_file().unlink(missing_ok=True)
    except Exception:
        pass


def _candidate_bases() -> list[Path]:
    bases: list[Path] = []
    for var in ("SECLISTS_PATH", "SEALION_WORDLISTS"):
        val = os.environ.get(var)
        if val:
            bases.append(Path(val).expanduser())
    bases += [Path(b) for b in _BASE_CANDIDATES]
    home = Path.home()
    bases += [home / "SecLists", home / "seclists", home / "wordlists" / "SecLists"]
    root = _project_root()
    bases += [root / "wordlists", root / "tool" / "seclists" / "SecLists"]
    seen: set[str] = set()
    out: list[Path] = []
    for b in bases:
        s = str(b)
        if s not in seen:
            seen.add(s)
            out.append(b)
    return out


def _flat_dirs() -> list[Path]:
    dirs = [Path(d) for d in _FLAT_DIRS]
    root = _project_root()
    dirs += [root / "wordlists", root / "loot", root / "lib"]
    return [d for d in dirs if d.is_dir()]


def _seclists_rel(path: str) -> str | None:
    """Estrae la porzione relativa SecLists (es. Discovery/Web-Content/common.txt)."""
    parts = [p for p in path.split("/") if p]
    lowered = [p.lower() for p in parts]
    for i, comp in enumerate(lowered):
        if comp in {t.lower() for t in _SECLISTS_TOP}:
            return "/".join(parts[i:])
    return None


def _prefer(matches: list[str]) -> str | None:
    """Tra più corrispondenze preferisce percorsi seclists/wordlists, poi il più corto."""
    if not matches:
        return None
    def rank(p: str) -> tuple[int, int]:
        low = p.lower()
        if "seclists" in low:
            group = 0
        elif "wordlist" in low:
            group = 1
        else:
            group = 2
        return (group, len(p))
    return sorted(matches, key=rank)[0]


def _search_locate(name: str) -> str | None:
    try:
        out = subprocess.run(
            ["locate", "-b", f"\\{name}"],
            capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    # alcune versioni di locate fanno substring-match anche con -b '\nome':
    # accetta solo corrispondenze esatte sul basename
    matches = [ln.strip() for ln in out.stdout.splitlines()
               if ln.strip() and os.path.basename(ln.strip()) == name
               and os.path.isfile(ln.strip())]
    return _prefer(matches)


def _search_find(name: str) -> str | None:
    roots = [r for r in _SEARCH_ROOTS if os.path.isdir(r)]
    if not roots:
        return None
    try:
        out = subprocess.run(
            ["find", *roots, "-maxdepth", "8", "-type", "f", "-name", name],
            capture_output=True, text=True, timeout=_FIND_TIMEOUT,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    matches = [ln.strip() for ln in out.stdout.splitlines()
               if ln.strip() and os.path.basename(ln.strip()) == name]
    return _prefer(matches)


def find_wordlist(path: str) -> str | None:
    """Cerca una wordlist nel sistema operativo.

    Accetta un path assoluto (es. /usr/share/seclists/Discovery/...) o
    relativo (es. Discovery/Web-Content/common.txt) e ritorna il path reale
    di un file esistente, oppure None se non trovato.
    """
    if not path:
        return None
    path = os.path.expanduser(path.strip())

    if os.path.isfile(path):
        return path

    cached = _cache_get(path)
    if cached is not _MISS:
        return cached

    name = os.path.basename(path)
    rel = _seclists_rel(path)
    if rel is None and not path.startswith("/"):
        rel = path

    found: str | None = None

    # 1. basi candidate: join con la porzione relativa, poi per basename
    for base in _candidate_bases():
        if rel and (base / rel).is_file():
            found = str(base / rel)
            break
        if (base / name).is_file():
            found = str(base / name)
            break

    # 2. directory piatte di wordlist (rockyou, dirb, ...)
    if not found:
        for d in _flat_dirs():
            if (d / name).is_file():
                found = str(d / name)
                break

    # 3. ricerca ricorsiva nelle basi esistenti (layout non standard)
    if not found:
        for base in _candidate_bases():
            if not base.is_dir():
                continue
            try:
                hit = next(base.rglob(name), None)
            except (PermissionError, OSError):
                hit = None
            if hit is not None:
                found = str(hit)
                break

    # 4. locate (database mlocate), se disponibile
    if not found:
        found = _search_locate(name)

    # 5. find con profondità limitata sulle radici comuni
    if not found:
        found = _search_find(name)

    _cache_put(path, found)
    return found


def seclists_base() -> str | None:
    """Ritorna la radice SecLists trovata sul sistema, se presente."""
    for base in _candidate_bases():
        if (base / "Discovery").is_dir() or (base / "Passwords").is_dir():
            return str(base)
    return None


def _find_compressed_variant(name: str) -> str | None:
    """Cerca la variante .gz della wordlist (es. rockyou.txt.gz di Kali)."""
    gz = name + ".gz"
    for d in _flat_dirs():
        if (d / gz).is_file():
            return str(d / gz)
    return None


def fix_hint(path: str) -> str:
    """Suggerimento pratico quando una wordlist non viene trovata."""
    name = os.path.basename(path)
    gz = _find_compressed_variant(name)
    if gz:
        return (f"trovata solo compressa: {gz}\n"
                f"        ↳ decomprimi con: sudo gunzip -k {gz}")
    if _seclists_rel(path):
        return ("installa SecLists con: install seclists   (dalla console slconsole)\n"
                "        ↳ oppure: sudo apt install seclists")
    return ("cerca manualmente con: locate -b " + name +
            "  oppure scaricala nella cartella wordlists/ del progetto")
