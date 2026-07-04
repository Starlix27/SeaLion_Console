"""Installer for Hashcat — advanced password recovery."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(["sudo", "apt-get", "update", "-qq"], check=False)
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "hashcat"],
        check=True,
    )
    print("Hashcat installato con successo.")
    return 0


ENTRY_POINT = "hashcat"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
