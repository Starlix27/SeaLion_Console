"""Installer for Scrapy — web crawling framework."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["python3", "-m", "pip", "install", "--break-system-packages", "scrapy"],
        check=True,
    )
    print("Scrapy installato con successo.")
    return 0


ENTRY_POINT = "scrapy"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
