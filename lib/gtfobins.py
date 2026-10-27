"""gtfobins — consultazione offline del database GTFOBins (gtfobins.org).

Uso nella console:
    gtfobins                     Guida
    gtfobins <binario>           Tutte le funzioni note (es. gtfobins find)
    gtfobins <binario> <fn>      Solo una funzione (es. gtfobins bash reverse-shell)
    gtfobins <binario> <contesto>  Solo i payload per quel contesto:
                                 sudo | suid | capabilities | unprivileged
                                 (es. gtfobins find suid)
    gtfobins list                Elenca i binari nel database locale
    gtfobins search <testo>      Cerca binari per nome
    gtfobins update              Aggiorna la copia locale (git pull)

Il database si installa con 'install gtfobins' (clone del repo ufficiale
https://github.com/GTFOBins/GTFOBins.github.io in ~/.sealionconsole/tools/gtfobins).
Fonte e crediti: https://gtfobins.org
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

DATA_DIR = Path.home() / ".sealionconsole" / "tools" / "gtfobins" / "repo" / "_gtfobins"

_FN_ORDER = [
    "shell", "reverse-shell", "bind-shell", "command", "privilege-escalation",
    "file-read", "file-write", "download", "upload", "library-load", "inherit",
]

_CTX_ORDER = ["sudo", "suid", "capabilities", "unprivileged"]

_CTX_HINTS = {
    "sudo": "esegui come root se compare in sudo -l",
    "suid": "vale se il binario ha il bit SUID",
    "capabilities": "vale se il binario ha capabilities (getcap)",
    "unprivileged": "funziona anche da utente normale",
}


# ---------------------------------------------------------------- parsing

def _load_entry(stem: str) -> dict | None:
    """Carica il front matter YAML di un binario (formato GTFOBins v2)."""
    f = DATA_DIR / stem
    if not f.is_file():
        f = DATA_DIR / f"{stem}.md"  # vecchie versioni del repo
        if not f.is_file():
            return None
    text = f.read_text(encoding="utf-8", errors="replace")
    parts = text.split("---", 2)
    if len(parts) < 2 or parts[0].strip():
        return None
    try:
        import yaml
    except ImportError:
        print("Serve PyYAML:  sudo apt install python3-yaml   (o pip install pyyaml)")
        return None
    try:
        data = yaml.safe_load(parts[1])
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _functions(stem: str, _depth: int = 0) -> dict:
    data = _load_entry(stem) or {}
    alias = data.get("alias")
    if alias and _depth < 3:
        return _functions(str(alias), _depth + 1)
    fns = data.get("functions")
    return fns if isinstance(fns, dict) else {}


def _alias_of(stem: str) -> str | None:
    data = _load_entry(stem) or {}
    alias = data.get("alias")
    return str(alias) if alias else None


def _all_binaries() -> list[str]:
    if not DATA_DIR.is_dir():
        return []
    return sorted(p.stem if p.suffix == ".md" else p.name
                  for p in DATA_DIR.iterdir() if p.is_file())


# ---------------------------------------------------------------- output

def _print_code(code: str, prefix: str = "  ") -> None:
    for line in code.strip("\n").splitlines():
        print(f"{prefix}\033[93m{line}\033[0m")


def _ctx_badges(contexts: dict) -> str:
    out = []
    for ctx in _CTX_ORDER:
        if ctx in (contexts or {}):
            out.append(ctx)
    return "  \033[90m[" + " · ".join(out) + "]\033[0m" if out else ""


def _print_entry(entry: dict) -> None:
    if not isinstance(entry, dict):
        return
    comment = (entry.get("comment") or "").strip()
    if comment:
        for line in comment.splitlines():
            print(f"  \033[90m# {line}\033[0m")
    code = entry.get("code") or ""
    if code:
        _print_code(code)
    contexts = entry.get("contexts") or {}
    print(_ctx_badges(contexts) or "", end="")
    if contexts:
        print()
    for ctx in _CTX_ORDER:
        override = contexts.get(ctx)
        if isinstance(override, dict) and override.get("code"):
            print(f"  \033[96m[{ctx}]\033[0m")
            _print_code(override["code"], prefix="    ")


def _print_context_view(stem: str, functions: dict, ctx: str) -> int:
    """Mostra solo i payload validi per un contesto (sudo/suid/…)."""
    print(f"\033[1;92m{stem}\033[0m — contesto \033[1;96m{ctx}\033[0m "
          f"\033[90m({_CTX_HINTS.get(ctx, '')})\033[0m")
    print(f"\033[90mfonte: https://gtfobins.org/#{stem}\033[0m")
    found = False
    for fn in [f for f in _FN_ORDER if f in functions] + sorted(set(functions) - set(_FN_ORDER)):
        for entry in functions.get(fn) or []:
            contexts = entry.get("contexts") or {}
            if ctx not in contexts:
                continue
            found = True
            print(f"\n\033[1;96m== {fn}\033[0m")
            override = contexts.get(ctx)
            if isinstance(override, dict) and override.get("code"):
                _print_code(override["code"])
            elif entry.get("code"):
                _print_code(entry["code"])
            comment = (entry.get("comment") or "").strip()
            if comment:
                for line in comment.splitlines():
                    print(f"  \033[90m# {line}\033[0m")
    if not found:
        print(f"\nNessun payload '{ctx}' per {stem}.")
        return 1
    print()
    return 0


def _print_functions(stem: str, filt: str | None = None) -> int:
    functions = _functions(stem)
    if not functions:
        print(f"Nessuna entry GTFOBins per '{stem}'. Prova: gtfobins search {stem}")
        return 1

    names = [f for f in _FN_ORDER if f in functions]
    names += sorted(f for f in functions if f not in _FN_ORDER)

    if filt and filt in _CTX_ORDER:
        return _print_context_view(stem, functions, filt)

    if filt:
        if filt not in functions:
            print(f"'{stem}' non ha la funzione '{filt}'.")
            print(f"Funzioni: {', '.join(names)} — contesti: {', '.join(_CTX_ORDER)}")
            return 1
        names = [filt]

    alias = _alias_of(stem)
    if alias:
        print(f"\033[90m'{stem}' è un alias di '{alias}'.\033[0m")

    print(f"\033[1;92m{stem}\033[0m — {len(functions)} funzioni: {', '.join(sorted(functions))}")
    print(f"\033[90mfonte: https://gtfobins.org/#{stem}\033[0m")
    for fn in names:
        print(f"\n\033[1;96m== {fn}\033[0m")
        for entry in functions.get(fn) or []:
            _print_entry(entry)
    print()
    return 0


def _print_help() -> None:
    print(__doc__.strip())


def _ensure_installed() -> bool:
    if DATA_DIR.is_dir():
        return True
    print("Database GTFOBins non installato — lo installo…")
    import sealion
    tool = sealion.find_tool("gtfobins")
    if tool is None:
        print("Tool gtfobins non trovato nel catalogo.")
        return False
    return sealion.run_install(tool) == 0 and DATA_DIR.is_dir()


# ---------------------------------------------------------------- comando

def cmd_gtfobins(args: argparse.Namespace, state=None) -> int:
    extra = list(getattr(args, "args", []) or [])
    if not extra or extra[0] in ("-h", "--help", "help"):
        _print_help()
        return 0

    if not _ensure_installed():
        return 1

    cmd = extra[0].lower()

    if cmd == "update":
        repo = DATA_DIR.parent
        if not (repo / ".git").exists():
            print("Copia scaricata senza git: reinstalla con 'install gtfobins'.")
            return 1
        print("Aggiornamento database GTFOBins…")
        return subprocess.run(["git", "-C", str(repo), "pull", "--ff-only"], check=False).returncode

    if cmd == "list":
        bins = _all_binaries()
        print(f"{len(bins)} binari nel database locale:\n")
        cols = 5
        for i in range(0, len(bins), cols):
            print("  ".join(f"{b:<18}" for b in bins[i:i + cols]))
        return 0

    if cmd == "search":
        if len(extra) < 2:
            print("Uso: gtfobins search <testo>")
            return 1
        needle = extra[1].lower()
        hits = [b for b in _all_binaries() if needle in b.lower()]
        if not hits:
            print(f"Nessun binario trovato per '{extra[1]}'.")
            return 1
        print(f"{len(hits)} risultati per '{extra[1]}':")
        for b in hits:
            alias = _alias_of(b)
            if alias:
                print(f"  \033[92m{b:<20}\033[0m \033[90m→ alias di {alias}\033[0m")
                continue
            fns = sorted(_functions(b))
            print(f"  \033[92m{b:<20}\033[0m {', '.join(fns)}")
        return 0

    # gtfobins <binario> [funzione|contesto]
    binary = cmd
    filt = extra[1].lower() if len(extra) > 1 else None
    return _print_functions(binary, filt)
