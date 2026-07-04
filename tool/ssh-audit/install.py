"""Installer for ssh-audit — SSH configuration auditor."""

import subprocess
import sys
from pathlib import Path

REPO_URL = "https://github.com/jtesta/ssh-audit.git"


def install(dest: Path) -> int:
    subprocess.run(["sudo", "apt-get", "install", "-y", "git"], check=True)
    repo_dir = dest / "ssh-audit"
    if repo_dir.exists():
        subprocess.run(["git", "-C", str(repo_dir), "pull", "--ff-only"], check=False)
    else:
        subprocess.run(["git", "clone", REPO_URL, str(repo_dir)], check=True)
    print("ssh-audit installato con successo.")
    return 0


ENTRY_POINT = "python3 \"{dest}/ssh-audit/ssh-audit.py\""


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
