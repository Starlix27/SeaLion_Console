"""Installer for xfreerdp — free RDP client for Linux."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["sudo", "apt-get", "update", "-qq"],
        check=False,
    )
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "freerdp2-x11"],
        check=True,
    )
    print("xfreerdp installato con successo.")
    return 0


ENTRY_POINT = "xfreerdp"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
