"""Utility condivise della console SeaLion."""

from __future__ import annotations

import os
import tempfile
from shutil import which


def wsl_command_script(shell_cmd: str) -> str | None:
    """Scrive shell_cmd in uno script .sh e ritorna il path.

    Su WSL, wt.exe/cmd.exe ri-parsano la command line e rompono i doppi
    apici annidati (errore 0x80070002, "Impossibile trovare il file"):
    passando a wsl.exe solo il path di uno script non serve quoting.
    Lo script si auto-elimina alla fine.
    """
    try:
        fd, path = tempfile.mkstemp(prefix="sealion_", suffix=".sh")
        with os.fdopen(fd, "w") as f:
            f.write("#!/bin/sh\n_main() {\n" + shell_cmd + "\n}\n_main\nrm -f \"$0\"\n")
        return path
    except OSError:
        return None


def windows_terminal_argv(title: str, shell_cmd: str) -> list[str] | None:
    """Argv per lanciare shell_cmd in una nuova tab/finestra Windows da WSL.

    Preferisce Windows Terminal (wt.exe), altrimenti cmd.exe come launcher.
    """
    script = wsl_command_script(shell_cmd)
    if not script:
        return None
    wsl_args = ["wsl.exe"]
    distro = os.environ.get("WSL_DISTRO_NAME")
    if distro:
        wsl_args += ["-d", distro]
    wsl_args += ["-e", "sh", script]
    wt = which("wt.exe")
    if wt:
        return [wt, "new-tab", "--title", title] + wsl_args
    cmd = which("cmd.exe")
    if cmd:
        return [cmd, "/c"] + wsl_args
    return None
