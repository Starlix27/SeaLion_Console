"""Installer for NetExec (CrackMapExec) — network exploitation framework."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["python3", "-m", "pip", "install", "--break-system-packages",
         "git+https://github.com/Pennyw0rth/NetExec"],
        check=True,
    )
    print("NetExec installato con successo.")
    return 0


ENTRY_POINT = "nxc"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
