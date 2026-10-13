"""Installer for IVRE — self-hosted alternative to Shodan/ZoomEye/Censys (Docker)."""

import shutil
import subprocess
import sys
from pathlib import Path

IMAGES = ["ivre/db", "ivre/web", "ivre/client"]


def _docker_cmd() -> list[str] | None:
    """Ritorna il comando docker da usare (con sudo se serve), o None."""
    if not shutil.which("docker"):
        return None
    if subprocess.run(["docker", "info"], capture_output=True).returncode == 0:
        return ["docker"]
    print("Utente non nel gruppo docker: i comandi useranno sudo.")
    return ["sudo", "docker"]


def install(dest: Path) -> int:
    docker = _docker_cmd()
    if docker is None:
        print("Docker non trovato.", file=sys.stderr)
        print("Installalo con:  sudo apt install docker.io", file=sys.stderr)
        print("Poi avvialo con: sudo systemctl enable --now docker", file=sys.stderr)
        return 1

    dest.mkdir(parents=True, exist_ok=True)
    (dest / "ivre-share").mkdir(exist_ok=True)

    src = Path(__file__).resolve().parent / "ivre.sh"
    shutil.copy2(src, dest / "ivre.sh")
    (dest / "ivre.sh").chmod(0o755)

    for image in IMAGES:
        print(f"\nPull di {image}…")
        rc = subprocess.run(docker + ["pull", image], check=False).returncode
        if rc != 0:
            print(f"Errore nel pull di {image}.", file=sys.stderr)
            print("Se il demone non risponde: sudo systemctl start docker", file=sys.stderr)
            return rc

    print()
    print("IVRE installato con successo.")
    print("  ivre init          # avvia lo stack, scarica GeoIP e inizializza il DB")
    print("  ivre up            # avvia IVRE (web UI su http://127.0.0.1:2728)")
    print("  ivre scan <target> # nmap + import nel DB (solo target autorizzati!)")
    print("  ivre help          # tutti i comandi")
    return 0


ENTRY_POINT = "bash {dest}/ivre.sh"


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
