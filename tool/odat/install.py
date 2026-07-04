"""Installer for ODAT — Oracle Database Attacking Tool."""

import subprocess
import sys
from pathlib import Path

REPO_URL = "https://github.com/quentinhardy/odat.git"


def install(dest: Path) -> int:
    subprocess.run(
        ["sudo", "apt-get", "update", "-qq"],
        check=False,
    )
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "git", "python3-pip",
         "python3-dev", "build-essential", "libaio1", "python3-scapy"],
        check=True,
    )
    repo_dir = dest / "odat"
    if repo_dir.exists():
        subprocess.run(["git", "-C", str(repo_dir), "pull", "--ff-only"], check=False)
    else:
        subprocess.run(["git", "clone", REPO_URL, str(repo_dir)], check=True)
        subprocess.run(["git", "-C", str(repo_dir), "submodule", "init"], check=False)
        subprocess.run(["git", "-C", str(repo_dir), "submodule", "update"], check=False)
    subprocess.run(
        ["python3", "-m", "pip", "install", "--break-system-packages",
         "python-libnmap", "colorlog", "termcolor", "passlib",
         "pycryptodome", "openpyxl"],
        check=True,
    )
    print("ODAT installato con successo.")
    return 0


ENTRY_POINT = "python3 \"{dest}/odat/odat.py\""


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
