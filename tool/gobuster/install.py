"""Installer for Gobuster — directory/DNS/VHost fuzzer."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["sudo", "apt-get", "update", "-qq"],
        check=False,
    )
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "gobuster"],
        check=True,
    )
    print("Gobuster installato con successo.")
    return 0


ENTRY_POINT = "gobuster"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
