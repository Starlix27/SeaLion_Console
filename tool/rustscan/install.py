"""Installer for RustScan — fast port scanner (Rust)."""

import shutil
import subprocess
import sys
from pathlib import Path

DEB_URL = "https://github.com/RustScan/RustScan/releases/download/2.4.1/rustscan.deb.zip"


def install(dest: Path) -> int:
    # 1. pacchetto di sistema (Kali/Parrot)
    subprocess.run(["sudo", "apt-get", "update", "-qq"], check=False)
    if subprocess.run(["sudo", "apt-get", "install", "-y", "rustscan"],
                      check=False).returncode == 0 and shutil.which("rustscan"):
        print("RustScan installato con successo (apt).")
        return 0
    # 2. cargo, se disponibile
    if shutil.which("cargo"):
        subprocess.run(["cargo", "install", "rustscan"], check=True)
        print("RustScan installato con successo (cargo).")
        return 0
    # 3. .deb precompilato dai rilasci GitHub
    tmp = Path("/tmp/rustscan-install")
    tmp.mkdir(exist_ok=True)
    archive = tmp / "rustscan.deb.zip"
    subprocess.run(["curl", "-fsSL", "-o", str(archive), DEB_URL], check=True)
    subprocess.run(["unzip", "-o", str(archive), "-d", str(tmp)], check=True)
    deb = next(tmp.glob("*.deb"))
    subprocess.run(["sudo", "dpkg", "-i", str(deb)], check=True)
    print("RustScan installato con successo (deb).")
    return 0


ENTRY_POINT = "rustscan"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
