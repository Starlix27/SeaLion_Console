"""Installer for SecLists — wordlist collection di sistema in /usr/share/seclists."""

import subprocess
import sys
from pathlib import Path

ENTRY_POINT = ""

TARGET = Path("/usr/share/seclists")
REPO = "https://github.com/danielmiessler/SecLists.git"


def _seclists_ok(path: Path) -> bool:
    """True se la directory esiste e contiene davvero le wordlist."""
    try:
        if not path.is_dir():
            return False
        if (path / "Discovery").is_dir() or (path / "Passwords").is_dir():
            return True
        return any(path.iterdir())
    except OSError:
        return False


def _write_pointer(dest: Path) -> None:
    """Lascia un rimando nella cartella della console (così non resta vuota)."""
    try:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "PERCORSO.txt").write_text(
            "SecLists è installato a livello di sistema in:\n\n"
            f"    {TARGET}\n\n"
            "Le wordlist NON sono in questa cartella: questa è solo un\n"
            "segnaposto creato dalla console. Usa i file in /usr/share/seclists.\n",
            encoding="utf-8",
        )
    except OSError:
        pass


def install(dest: Path) -> int:
    if _seclists_ok(TARGET):
        print(f"SecLists è già installato in {TARGET}")
        _write_pointer(dest)
        return 0

    # Se esiste ma è vuota (o mezza rotta), la rimuoviamo: apt/git ripartono puliti
    if TARGET.is_dir():
        print(f"{TARGET} esiste ma è vuota: la pulisco e reinstallo…")
        subprocess.run(["sudo", "rm", "-rf", str(TARGET)], check=False)

    # 1) apt (Kali/Parrot/Debian): installa direttamente in /usr/share/seclists
    try:
        subprocess.check_call(["sudo", "apt", "install", "-y", "seclists"])
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("apt non disponibile o pacchetto non trovato.")

    # 2) Fallback: git clone, se apt non ha popolato la directory
    if not _seclists_ok(TARGET):
        print("apt non ha installato i file, clono da GitHub…")
        try:
            subprocess.run(["sudo", "rm", "-rf", str(TARGET)], check=False)
            subprocess.check_call(
                ["sudo", "git", "clone", "--depth", "1", REPO, str(TARGET)]
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            print(f"Errore durante il clone: {exc}", file=sys.stderr)

    # 3) Verifica finale
    if not _seclists_ok(TARGET):
        print(f"Errore: {TARGET} è ancora vuota o assente.", file=sys.stderr)
        return 1

    print(f"\n✓ SecLists installato in {TARGET}")
    print("  (la cartella della console contiene solo un segnaposto: i file stanno in /usr/share/seclists)")
    _write_pointer(dest)
    return 0


if __name__ == "__main__":
    sys.exit(install(Path.cwd()))
