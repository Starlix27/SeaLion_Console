"""Installer for Impacket — Python network protocol library."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["python3", "-m", "pip", "install", "--break-system-packages",
         "git+https://github.com/fortra/impacket"],
        check=True,
    )
    print("Impacket installato con successo.")
    return 0


ENTRY_POINT = "impacket-smbclient"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
