"""Installer for wafw00f — WAF detection tool."""

import subprocess
import sys
from pathlib import Path

PACKAGE = "git+https://github.com/EnableSecurity/wafw00f"


def install(dest: Path) -> int:
    subprocess.run(
        ["python3", "-m", "pip", "install", "--break-system-packages", PACKAGE],
        check=True,
    )
    print("wafw00f installato con successo.")
    return 0


ENTRY_POINT = "wafw00f"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
