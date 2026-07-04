"""Installer for FinalRecon — web reconnaissance tool."""

import subprocess
import sys
from pathlib import Path

REPO_URL = "https://github.com/thewhiteh4t/FinalRecon.git"


def install(dest: Path) -> int:
    subprocess.run(
        ["sudo", "apt-get", "install", "-y", "git", "python3-pip"],
        check=True,
    )
    repo_dir = dest / "FinalRecon"
    if repo_dir.exists():
        subprocess.run(["git", "-C", str(repo_dir), "pull", "--ff-only"], check=False)
    else:
        subprocess.run(["git", "clone", REPO_URL, str(repo_dir)], check=True)
    req = repo_dir / "requirements.txt"
    if req.exists():
        subprocess.run(
            ["python3", "-m", "pip", "install", "--break-system-packages", "-r", str(req)],
            check=True,
        )
    entry = repo_dir / "finalrecon.py"
    if entry.exists():
        entry.chmod(0o755)
    print("FinalRecon installato con successo.")
    return 0


ENTRY_POINT = "python3 \"{dest}/FinalRecon/finalrecon.py\""


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
