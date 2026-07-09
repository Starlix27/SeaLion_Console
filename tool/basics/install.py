"""Installer for Basics — downloads LinPEAS from GitHub."""

import subprocess
import sys
from pathlib import Path

LINPEAS_URL = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"


def install(dest: Path) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / "linpeas.sh"

    print(f"Scaricamento LinPEAS in {out} ...")
    rc = subprocess.run(
        ["curl", "-fsSL", "-o", str(out), LINPEAS_URL],
        check=False,
    ).returncode

    if rc != 0:
        print("Errore durante il download di LinPEAS.", file=sys.stderr)
        return rc

    out.chmod(0o755)
    print(f"LinPEAS scaricato: {out}")
    return 0


ENTRY_POINT = "{dest}/linpeas.sh"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
