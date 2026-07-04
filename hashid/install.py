"""Installer for hashID — hash identifier."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["python3", "-m", "pip", "install", "--break-system-packages", "hashid"],
        check=True,
    )
    print("hashID installato con successo.")
    return 0


ENTRY_POINT = "hashid"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
