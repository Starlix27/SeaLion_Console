"""Installer for Nikto — web server vulnerability scanner."""

import subprocess
import sys
from pathlib import Path

REPO_URL = "https://github.com/sullo/nikto"


def install(dest: Path) -> int:
    subprocess.run(
        ["sudo", "apt-get", "update", "-qq"],
        check=False,
    )
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "perl", "git"],
        check=True,
    )

    repo_dir = dest / "nikto"
    if repo_dir.exists():
        print(f"Repo già presente in {repo_dir}, aggiorno…")
        subprocess.run(["git", "-C", str(repo_dir), "pull", "--ff-only"], check=False)
    else:
        subprocess.run(
            ["git", "clone", REPO_URL, str(repo_dir)],
            check=True,
        )

    entry = repo_dir / "program" / "nikto.pl"
    if entry.exists():
        entry.chmod(0o755)

    print("Nikto installato con successo.")
    return 0


ENTRY_POINT = "perl \"{dest}/nikto/program/nikto.pl\""


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
