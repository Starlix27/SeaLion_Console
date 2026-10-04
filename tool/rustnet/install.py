"""Installer for RustNet — TUI network monitor (Rust)."""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ASSET_URL = "https://github.com/domcyrus/rustnet/releases/download/v1.6.0/rustnet-v1.6.0-x86_64-unknown-linux-gnu.tar.gz"


def install(dest: Path) -> int:
    # 1. cargo, se disponibile
    if shutil.which("cargo"):
        subprocess.run(["cargo", "install", "rustnet"], check=True)
        print("RustNet installato con successo (cargo).")
        return 0
    # 2. binario precompilato dai rilasci GitHub
    with tempfile.TemporaryDirectory() as td:
        archive = Path(td) / "rustnet.tar.gz"
        subprocess.run(["curl", "-fsSL", "-o", str(archive), ASSET_URL], check=True)
        subprocess.run(["tar", "-xzf", str(archive), "-C", td], check=True)
        binary = next(p for p in Path(td).rglob("rustnet") if p.is_file())
        subprocess.run(["sudo", "install", "-m", "0755", str(binary),
                        "/usr/local/bin/rustnet"], check=True)
    print("RustNet installato con successo (binario precompilato).")
    return 0


ENTRY_POINT = "rustnet"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
