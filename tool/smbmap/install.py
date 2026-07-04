"""Installer for SMBMap — SMB share permissions enumerator."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["python3", "-m", "pip", "install", "--break-system-packages",
         "git+https://github.com/ShawnDEvans/smbmap"],
        check=True,
    )
    print("SMBMap installato con successo.")
    return 0


ENTRY_POINT = "smbmap"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
