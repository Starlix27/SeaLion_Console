"""Installer for medusa — parallel network login auditor."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["sudo", "apt-get", "update", "-qq"],
        check=False,
    )
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "medusa"],
        check=True,
    )
    print("medusa installato con successo.")
    return 0


ENTRY_POINT = "medusa"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
