"""Installer for Hydra — network login brute-forcer."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["sudo", "apt-get", "update", "-qq"],
        check=False,
    )
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "hydra"],
        check=True,
    )
    print("Hydra installato con successo.")
    return 0


ENTRY_POINT = "hydra"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
