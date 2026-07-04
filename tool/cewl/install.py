"""Installer for CeWL — custom word list generator."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(["sudo", "apt-get", "update", "-qq"], check=False)
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "cewl"],
        check=True,
    )
    print("CeWL installato con successo.")
    return 0


ENTRY_POINT = "cewl"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
