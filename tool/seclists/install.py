import subprocess
import sys
from pathlib import Path

ENTRY_POINT = ""

def install(dest):
    target = Path("/usr/share/seclists")
    if target.exists():
        print("SecLists è già installato in /usr/share/seclists")
        return 0
    # Try apt first (Kali/Parrot)
    try:
        subprocess.check_call(["sudo", "apt", "install", "-y", "seclists"])
        return 0
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    # Fallback: git clone
    print("apt non disponibile, clono da GitHub...")
    subprocess.check_call(["sudo", "git", "clone", "--depth", "1",
        "https://github.com/danielmiessler/SecLists.git", str(target)])
    return 0

if __name__ == "__main__":
    install(Path.cwd())
