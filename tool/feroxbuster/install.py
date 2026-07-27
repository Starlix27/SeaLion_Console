"""Installer for feroxbuster — recursive content discovery tool."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["sudo", "apt-get", "update", "-qq"],
        check=False,
    )
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "feroxbuster"],
        check=True,
    )
    print("feroxbuster installato con successo.")
    return 0


ENTRY_POINT = "feroxbuster"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
