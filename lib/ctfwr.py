"""ctf-wr — pipeline ricognizione→attacco per web challenge CTF.

Comandi console:
    ctf-wr -u URL                 Scan completo (dirs → params → scan → xss → sqli → ssti)
    ctf-wr -u URL -c "session=X"  Dietro autenticazione
    ctf-wr -u URL --skip xss      Salta fasi
    ctf-wr -h                     Aiuto dello script

Lo script vive in tool/ctf-web-recon; se non installato, viene installato
al primo utilizzo. Le dipendenze mancanti (dalfox, sstimap, …) vengono
saltate con un avviso: installale con `install ctf-web-toolkit`.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

SCRIPT = Path.home() / ".sealionconsole" / "tools" / "ctf-web-recon" / "ctf-web-recon.sh"


def cmd_ctf_wr(args: argparse.Namespace, state=None) -> int:
    extra = list(getattr(args, "args", []) or [])

    if not SCRIPT.exists():
        print("ctf-web-recon non installato — lo installo…")
        import sealion
        tool = sealion.find_tool("ctf-web-recon")
        if tool is None:
            print("Tool ctf-web-recon non trovato nel catalogo.")
            return 1
        rc = sealion.run_install(tool)
        if rc != 0:
            return rc

    if not extra:
        print("Uso: ctf-wr -u URL [-o outdir] [-c \"cookie\"] [--skip fasi] [--fast]")
        print("     ctf-wr -h per l'aiuto completo dello script")
        return 0

    try:
        return subprocess.run(["bash", str(SCRIPT), *extra]).returncode
    except KeyboardInterrupt:
        print("\nInterrotto.")
        return 130
