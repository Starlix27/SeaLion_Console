"""Installer for ffuf — fast web fuzzer."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["sudo", "apt-get", "update", "-qq"],
        check=False,
    )
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "ffuf"],
        check=True,
    )
    print("ffuf installato con successo.")
    return 0


ENTRY_POINT = "ffuf"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
