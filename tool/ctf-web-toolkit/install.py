"""Installer for ctf-web-toolkit — all missing web CTF tools in one shot."""

import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

USER_BIN = Path.home() / ".local" / "bin"


def _pip(args: list[str]) -> None:
    """pip install che sopravvive agli ambienti externally-managed (PEP 668)."""
    rc = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--user", *args], check=False
    ).returncode
    if rc != 0:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--user",
             "--break-system-packages", *args],
            check=True,
        )


def _wrapper(name: str, body: str) -> None:
    USER_BIN.mkdir(parents=True, exist_ok=True)
    p = USER_BIN / name
    p.write_text(f"#!/usr/bin/env bash\nset -euo pipefail\n{body}\n", encoding="utf-8")
    p.chmod(0o755)
    print(f"  wrapper: {p}")


def _install_dalfox(dest: Path) -> None:
    if shutil.which("dalfox"):
        print("[=] dalfox gia' presente, skip.")
        return
    print("[*] dalfox (binario da GitHub)…")
    with urllib.request.urlopen(
        "https://api.github.com/repos/hahwul/dalfox/releases/latest", timeout=30
    ) as r:
        rel = json.load(r)
    asset = next(
        a for a in rel["assets"]
        if "linux-x86_64" in a["name"] and a["name"].endswith(".tar.gz")
    )
    with tempfile.TemporaryDirectory() as td:
        tgz = Path(td) / "dalfox.tar.gz"
        urllib.request.urlretrieve(asset["browser_download_url"], tgz)
        with tarfile.open(tgz) as tf:
            tf.extractall(td, filter="data")
        binary = next(Path(td).rglob("dalfox"))
        USER_BIN.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, USER_BIN / "dalfox")
        (USER_BIN / "dalfox").chmod(0o755)
    print("  dalfox -> ~/.local/bin/dalfox")


def _install_sstimap(dest: Path) -> None:
    target = dest / "SSTImap"
    if target.exists():
        print("[=] SSTImap gia' presente, skip.")
    else:
        print("[*] SSTImap (git clone)…")
        subprocess.run(
            ["git", "clone", "--depth", "1",
             "https://github.com/vladko312/SSTImap.git", str(target)],
            check=True,
        )
    _pip(["-r", str(target / "requirements.txt")])
    _wrapper("sstimap", f'exec python3 "{target}/sstimap.py" "$@"')


def _install_xsstrike(dest: Path) -> None:
    target = dest / "XSStrike"
    if target.exists():
        print("[=] XSStrike gia' presente, skip.")
    else:
        print("[*] XSStrike (git clone)…")
        subprocess.run(
            ["git", "clone", "--depth", "1",
             "https://github.com/s0md3v/XSStrike.git", str(target)],
            check=True,
        )
    _pip(["-r", str(target / "requirements.txt")])
    _wrapper("xsstrike", f'exec python3 "{target}/XSStrike/xsstrike.py" "$@"')


def _install_dirsearch(dest: Path) -> None:
    if shutil.which("dirsearch"):
        print("[=] dirsearch gia' presente, skip.")
        return
    print("[*] dirsearch (pip)…")
    _pip(["dirsearch"])


def _install_zap(dest: Path) -> None:
    if shutil.which("zaproxy") or shutil.which("zap"):
        print("[=] ZAP gia' presente, skip.")
        return
    print("[*] OWASP ZAP (apt, richiede sudo)…")
    subprocess.run(["sudo", "apt-get", "update", "-qq"], check=False)
    subprocess.run(["sudo", "apt-get", "install", "-y", "zaproxy"], check=False)


def install(dest: Path) -> int:
    if not shutil.which("git"):
        subprocess.run(["sudo", "apt-get", "install", "-y", "git"], check=False)

    for step in (
        _install_dalfox,
        _install_sstimap,
        _install_xsstrike,
        _install_dirsearch,
        _install_zap,
    ):
        try:
            step(dest)
        except Exception as exc:  # un tool fallito non blocca gli altri
            print(f"[!] {step.__name__}: installazione fallita ({exc})")

    print("\nFatto. Se ~/.local/bin non e' nel PATH, aggiungilo al tuo shell rc.")
    return 0


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
