"""Installer for Recon-ng — web reconnaissance framework."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["python3", "-m", "pip", "install", "--break-system-packages",
         "git+https://github.com/lanmaster53/recon-ng.git"],
        check=True,
    )
    print("Recon-ng installato con successo.")
    return 0


ENTRY_POINT = "recon-ng"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
