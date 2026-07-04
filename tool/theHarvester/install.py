"""Installer for theHarvester — OSINT gathering tool."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["python3", "-m", "pip", "install", "--break-system-packages", "theHarvester"],
        check=True,
    )
    print("theHarvester installato con successo.")
    return 0


ENTRY_POINT = "theHarvester"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
