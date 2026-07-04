"""Installer for WHOIS — domain lookup tool."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(["sudo", "apt-get", "update", "-qq"], check=False)
    subprocess.run(["sudo", "apt-get", "install", "-y", "whois"], check=True)
    print("WHOIS installato con successo.")
    return 0


ENTRY_POINT = "whois"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
