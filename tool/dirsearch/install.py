"""Installer for dirsearch — web path scanner."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["sudo", "apt-get", "update", "-qq"],
        check=False,
    )
    result = subprocess.run(
        ["sudo", "apt-get", "install", "-y", "dirsearch"],
        capture_output=True,
    )
    if result.returncode == 0:
        print("dirsearch installato con successo.")
        return 0
    subprocess.run(
        ["pip3", "install", "dirsearch"],
        check=True,
    )
    print("dirsearch installato con successo via pip.")
    return 0


ENTRY_POINT = "dirsearch"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
