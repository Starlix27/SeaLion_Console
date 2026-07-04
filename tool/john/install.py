"""Installer for John the Ripper — password cracker."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(["sudo", "apt-get", "update", "-qq"], check=False)
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "john"],
        check=True,
    )
    print("John the Ripper installato con successo.")
    return 0


ENTRY_POINT = "john"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
