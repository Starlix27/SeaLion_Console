"""Installer for Nmap — network scanner."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["sudo", "apt-get", "update", "-qq"],
        check=False,
    )
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "nmap"],
        check=True,
    )
    print("Nmap installato con successo.")
    return 0


ENTRY_POINT = "nmap"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
