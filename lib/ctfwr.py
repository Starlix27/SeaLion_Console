"""ctf-wr — pipeline ricognizione→attacco per web challenge CTF.

Uso nella console:
    ctf-wr                          Guida completa (fasi, opzioni, esempi)
    ctf-wr -u URL                   Scan completo: dirs → params → scan → xss → sqli → ssti
    ctf-wr -u URL ssti              Esegue SOLO la fase SSTI
    ctf-wr -u URL xss sqli          Esegue SOLO XSS e SQLi
    ctf-wr -u URL -p name           Parametro noto, senza discovery
    ctf-wr -u URL --skip dirs,scan  Tutte le fasi TRANNE quelle indicate
    ctf-wr -u URL -c "session=X"    Dietro autenticazione
    ctf-wr -u URL --fast            Timeout ridotti
    ctf-wr deps                     Tabella dipendenze (cosa c'è, cosa manca)
    ctf-wr deps --install           Installa le dipendenze mancanti

Le fasi di attacco testano: i parametri passati con -p, la query nell'URL,
i form HTML della pagina, i parametri trovati da arjun — e in fallback una
lista di nomi comuni. arjun e sstimap sono opzionali: senza arjun params
usa form HTML + nomi comuni; senza sstimap ssti usa il probe built-in.

Prima di partire, ctf-wr controlla i tool delle fasi richieste: se ne manca
uno spiega perché la fase non partirebbe (o in cosa sarebbe limitata) e
propone di installarlo subito (-y per non chiedere, --no-install per
proseguire con quello che c'è).

Lo script vive in tool/ctf-web-recon; se non installato, viene installato
al primo utilizzo (script + alias ~/.local/bin/ctf-wr).
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

    try:
        # Senza argomenti (o con -h) lo script stampa la guida completa.
        return subprocess.run(["bash", str(SCRIPT), *extra]).returncode
    except KeyboardInterrupt:
        print("\nInterrotto.")
        return 130
