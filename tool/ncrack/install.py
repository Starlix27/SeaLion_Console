"""Installer for ncrack — network authentication cracker."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["sudo", "apt-get", "update", "-qq"],
        check=False,
    )
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "ncrack"],
        check=True,
    )
    print("ncrack installato con successo.")
    return 0


ENTRY_POINT = "ncrack"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
