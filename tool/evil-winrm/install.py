"""Installer for Evil-WinRM — WinRM pentesting shell."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "ruby", "ruby-dev", "build-essential"],
        check=True,
    )
    subprocess.run(
        ["sudo", "gem", "install", "evil-winrm"],
        check=True,
    )
    print("Evil-WinRM installato con successo.")
    return 0


ENTRY_POINT = "evil-winrm"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
