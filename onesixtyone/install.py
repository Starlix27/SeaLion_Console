"""Installer for onesixtyone — SNMP community string scanner."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(["sudo", "apt-get", "update", "-qq"], check=False)
    subprocess.run(["sudo", "apt-get", "install", "-y", "onesixtyone"], check=True)
    print("onesixtyone installato con successo.")
    return 0


ENTRY_POINT = "onesixtyone"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
