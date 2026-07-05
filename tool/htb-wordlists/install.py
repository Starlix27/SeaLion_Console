"""Installer for HTB Wordlists — custom wordlists for HackTheBox."""

import subprocess
import sys
from pathlib import Path

DOWNLOAD_URL = "https://file.ax/d/admkbkg6"


def install(dest: Path) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    archive = dest / "htb-wordlists.zip"

    print(f"Download da {DOWNLOAD_URL}...")
    try:
        subprocess.run(
            ["wget", "-O", str(archive), DOWNLOAD_URL],
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        subprocess.run(
            ["curl", "-L", "-o", str(archive), DOWNLOAD_URL],
            check=True,
        )

    subprocess.run(["unzip", "-o", str(archive), "-d", str(dest)], check=True)
    archive.unlink(missing_ok=True)
    print(f"Wordlist HTB estratte in {dest}")
    return 0


ENTRY_POINT = ""


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
