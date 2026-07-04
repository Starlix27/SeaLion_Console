"""Installer for Shodan — search engine for Internet-connected devices."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["python3", "-m", "pip", "install", "--break-system-packages", "shodan"],
        check=True,
    )
    print("Shodan installato con successo.")
    print("Ricorda di inizializzare con: shodan init TUA_API_KEY")
    return 0


ENTRY_POINT = "shodan"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
