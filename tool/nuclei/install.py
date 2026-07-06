"""Installer for Nuclei — fast vulnerability scanner."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["sudo", "apt-get", "update", "-qq"],
        check=False,
    )
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "golang"],
        check=False,
    )
    subprocess.run(
        ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
        check=True,
    )
    print("Nuclei installato con successo.")
    print("Assicurati che ~/go/bin sia nel PATH.")
    return 0


ENTRY_POINT = "nuclei"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
