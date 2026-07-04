"""Installer for rdp-sec-check — RDP security checker."""

import subprocess
import sys
from pathlib import Path

REPO_URL = "https://github.com/CiscoCXSecurity/rdp-sec-check.git"


def install(dest: Path) -> int:
    subprocess.run(["sudo", "apt-get", "install", "-y", "git", "perl"], check=True)
    subprocess.run(["sudo", "cpan", "Encoding::BER"], check=False)
    repo_dir = dest / "rdp-sec-check"
    if repo_dir.exists():
        subprocess.run(["git", "-C", str(repo_dir), "pull", "--ff-only"], check=False)
    else:
        subprocess.run(["git", "clone", REPO_URL, str(repo_dir)], check=True)
    print("rdp-sec-check installato con successo.")
    return 0


ENTRY_POINT = "perl \"{dest}/rdp-sec-check/rdp-sec-check.pl\""


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
