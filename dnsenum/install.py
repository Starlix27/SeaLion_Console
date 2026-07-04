"""Installer for dnsenum — DNS enumeration tool."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(["sudo", "apt-get", "update", "-qq"], check=False)
    subprocess.run(["sudo", "apt-get", "install", "-y", "dnsenum"], check=True)
    print("dnsenum installato con successo.")
    return 0


ENTRY_POINT = "dnsenum"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
