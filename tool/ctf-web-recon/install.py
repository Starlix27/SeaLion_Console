"""Installer for ctf-web-recon — unified recon-to-attack pipeline for web CTFs."""

import shutil
import sys
from pathlib import Path

USER_BIN = Path.home() / ".local" / "bin"


def install(dest: Path) -> int:
    src = Path(__file__).parent / "ctf-web-recon.sh"
    dst = dest / "ctf-web-recon.sh"
    shutil.copy2(src, dst)
    dst.chmod(0o755)
    print(f"Script copiato in {dst}")

    # Alias breve: ctf-wr
    USER_BIN.mkdir(parents=True, exist_ok=True)
    alias = USER_BIN / "ctf-wr"
    alias.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f'exec bash "{dst}" "$@"\n',
        encoding="utf-8",
    )
    alias.chmod(0o755)
    print(f"Alias creato: {alias} (comando breve: ctf-wr)")

    print("Dipendenze opzionali: ffuf arjun nuclei dalfox sqlmap sstimap")
    print("(quelle mancanti vengono saltate — installale con: install ctf-web-toolkit)")
    return 0


ENTRY_POINT = "bash {dest}/ctf-web-recon.sh"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
