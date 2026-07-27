"""Installer for wfuzz — web application fuzzer."""

import subprocess
import sys
from pathlib import Path


def install(dest: Path) -> int:
    subprocess.run(
        ["pip3", "install", "wfuzz"],
        check=True,
    )
    print("wfuzz installato con successo.")
    return 0


ENTRY_POINT = "wfuzz"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
