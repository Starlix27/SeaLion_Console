"""Installer for Metasploit Framework (msfconsole)."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["sudo", "apt-get", "update", "-qq"],
        check=False,
    )
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "metasploit-framework"],
        check=True,
    )
    print("Metasploit Framework installato con successo.")
    return 0


ENTRY_POINT = "msfconsole"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
