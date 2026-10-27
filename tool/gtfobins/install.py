"""Installer for GTFOBins — copia locale offline del database gtfobins.org."""

import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

REPO = "https://github.com/GTFOBins/GTFOBins.github.io.git"
TARBALL = "https://github.com/GTFOBins/GTFOBins.github.io/archive/refs/heads/master.tar.gz"


def _clone_git(dest: Path) -> int:
    print(f"Clonazione di {REPO} (shallow)…")
    rc = subprocess.run(
        ["git", "clone", "--depth", "1", REPO, str(dest / "repo")],
        check=False,
    ).returncode
    return rc


def _download_tarball(dest: Path) -> int:
    print(f"git non trovato: scarico lo snapshot {TARBALL}…")
    try:
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        urllib.request.urlretrieve(TARBALL, tmp_path)
        repo_dir = dest / "repo"
        repo_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tmp_path) as tar:
            for m in tar.getmembers():
                parts = m.name.split("/", 1)
                if len(parts) == 2 and parts[1]:
                    m.name = parts[1]
                    tar.extract(m, repo_dir, filter="data")
        tmp_path.unlink(missing_ok=True)
        print("Nota: senza git non potrai aggiornare con 'gtfobins update' (riscarica con 'install gtfobins').")
        return 0
    except Exception as exc:
        print(f"Errore nel download: {exc}", file=sys.stderr)
        return 1


def install(dest: Path) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    repo_dir = dest / "repo"
    if repo_dir.exists():
        shutil.rmtree(repo_dir)

    rc = _clone_git(dest) if shutil.which("git") else _download_tarball(dest)
    if rc != 0:
        return rc

    data = repo_dir / "_gtfobins"
    if not data.is_dir():
        print("Errore: directory _gtfobins non trovata nel repo.", file=sys.stderr)
        return 1

    n = len([p for p in data.iterdir() if p.is_file()])
    print()
    print(f"GTFOBins installato: {n} binari disponibili offline.")
    print("  gtfobins find            # tutte le funzioni per un binario")
    print("  gtfobins find suid       # solo il payload SUID")
    print("  gtfobins list            # elenco binari")
    print("  gtfobins update          # aggiorna il database")
    print("Fonte: https://gtfobins.org")
    return 0


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
