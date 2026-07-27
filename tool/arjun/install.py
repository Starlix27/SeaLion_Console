"""Installer for arjun — HTTP parameter discovery tool."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["pip3", "install", "arjun"],
        check=True,
    )
    print("arjun installato con successo.")
    return 0


ENTRY_POINT = "arjun"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
