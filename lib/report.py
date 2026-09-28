"""Gestione dei report di penetration test (template SLCtrl).

Comandi console:
    report                       Stato / aiuto
    report new "Cliente" [tipo]  Crea un nuovo report dal template
    report list                  Elenca i report esistenti
    report edit <nome|num>       Apre il report in VS Code (o derivati)
    report build <nome|num>      Genera il PDF (pandoc + weasyprint)
    report path <nome|num>       Mostra il percorso del report
    report help                  Aiuto dettagliato
"""

from __future__ import annotations

import argparse
import datetime
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_ROOT = PROJECT_ROOT / "report"
REPORTS_DIR = PROJECT_ROOT / "reports"
TEMPLATE_MD = REPORT_ROOT / "template.md"
TEMPLATE_HTML = REPORT_ROOT / "template" / "slctrl.html"
TEMPLATE_CSS = REPORT_ROOT / "template" / "slctrl.css"

_VSCODE_CANDIDATES = ("code", "codium", "vscodium", "code-insiders", "cursor")


# ---------------------------------------------------------------------------
# Core helpers (shared with http_server / SLWeb)
# ---------------------------------------------------------------------------

def slugify(client: str) -> str:
    """Converte il nome del cliente in uno slug filesystem-safe."""
    s = unicodedata.normalize("NFKD", client).encode("ascii", "ignore").decode()
    s = re.sub(r"[^a-zA-Z0-9]+", "-", s).strip("-").lower()
    return s or "report"


def report_md_path(slug: str) -> Path:
    return REPORTS_DIR / slug / f"{slug}-report.md"


def _read_client(md_file: Path) -> str:
    """Estrae il campo `client` dal front-matter YAML."""
    try:
        head = md_file.read_text(encoding="utf-8", errors="replace")[:2000]
    except OSError:
        return ""
    m = re.search(r'^client:\s*"(.*?)"', head, re.M)
    return m.group(1) if m else ""


def list_reports() -> list[dict]:
    """Elenca i report esistenti con metadati."""
    out: list[dict] = []
    if not REPORTS_DIR.is_dir():
        return out
    for d in sorted(REPORTS_DIR.iterdir(), key=lambda p: p.name.lower()):
        if not d.is_dir() or d.name.startswith("."):
            continue
        md = d / f"{d.name}-report.md"
        if not md.is_file():
            cands = sorted(d.glob("*.md"))
            md = cands[0] if cands else md
        if not md.is_file():
            continue
        pdf = md.with_suffix(".pdf")
        ev_dir = d / "evidence"
        n_ev = len([f for f in ev_dir.iterdir() if f.is_file()]) if ev_dir.is_dir() else 0
        out.append({
            "slug": d.name,
            "client": _read_client(md),
            "md": str(md),
            "pdf": str(pdf) if pdf.is_file() else None,
            "evidence": n_ev,
            "mtime": md.stat().st_mtime,
        })
    return out


def find_report(name: str | None) -> dict | None:
    """Risolve un report per slug (anche parziale) o numero (da list)."""
    reports = list_reports()
    if not reports:
        return None
    if not name:
        return reports[0] if len(reports) == 1 else None
    name = name.strip().lower()
    if name.isdigit():
        idx = int(name) - 1
        return reports[idx] if 0 <= idx < len(reports) else None
    slug = slugify(name)
    for r in reports:
        if r["slug"] == slug or r["client"].lower() == name:
            return r
    for r in reports:  # match parziale
        if slug in r["slug"] or name in r["client"].lower():
            return r
    return None


def create_report(client: str, rtype: str = "Penetration Test Interno") -> Path:
    """Crea un nuovo report dal template. Ritorna il path del .md."""
    client = client.strip()
    if not client:
        raise ValueError("Nome cliente vuoto")
    if not TEMPLATE_MD.is_file():
        raise FileNotFoundError(f"Template non trovato: {TEMPLATE_MD}")
    slug = slugify(client)
    out_dir = REPORTS_DIR / slug
    out = out_dir / f"{slug}-report.md"
    if out.exists():
        raise FileExistsError(f"Report già esistente: {out}")
    (out_dir / "evidence").mkdir(parents=True, exist_ok=True)

    months = ("gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno",
              "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre")
    now = datetime.datetime.now()
    today = f"{now.day} {months[now.month - 1]} {now.year}"

    text = TEMPLATE_MD.read_text(encoding="utf-8")
    text = text.replace('client: "Nome Cliente S.r.l."', f'client: "{client}"', 1)
    text = text.replace('report-title: "Penetration Test Interno"', f'report-title: "{rtype}"', 1)
    text = re.sub(r'^date: ".*"', f'date: "{today}"', text, count=1, flags=re.M)
    out.write_text(text, encoding="utf-8")
    return out


def _find_editor() -> str | None:
    """Trova VS Code o un derivato nel PATH."""
    for cand in _VSCODE_CANDIDATES:
        exe = shutil.which(cand)
        if exe:
            return exe
    return None


def edit_report(name: str | None) -> tuple[bool, str]:
    """Apre la cartella del report in VS Code (o derivato)."""
    rep = find_report(name)
    if rep is None:
        return False, "Report non trovato. Usa 'report list' per vedere quelli esistenti."
    folder = str(Path(rep["md"]).parent)
    editor = _find_editor() or shutil.which("code.cmd")
    if editor:
        try:
            subprocess.Popen(
                [editor, folder],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return True, f"Aperto in {Path(editor).name}: {folder}"
        except OSError as e:
            return False, f"Impossibile avviare {editor}: {e}"
    return False, ("VS Code non trovato nel PATH (cercati: " +
                   ", ".join(_VSCODE_CANDIDATES) + ").\n"
                   f"Apri manualmente: {folder}")


def build_report(name: str | None) -> tuple[bool, str]:
    """Compila il report in PDF con pandoc + weasyprint."""
    rep = find_report(name)
    if rep is None:
        return False, "Report non trovato. Usa 'report list' per vedere quelli esistenti."
    md = Path(rep["md"])
    out_pdf = md.with_suffix(".pdf")

    pandoc = shutil.which("pandoc")
    if not pandoc:
        local = Path.home() / ".local" / "bin" / "pandoc"
        pandoc = str(local) if local.is_file() else None
    if not pandoc:
        return False, "pandoc non trovato. Installalo: sudo apt install pandoc"
    weasy = shutil.which("weasyprint")
    use_module = False
    if not weasy:
        try:
            import weasyprint  # noqa: F401
            use_module = True
        except ImportError:
            return False, ("weasyprint non trovato. Installalo: sudo apt install weasyprint "
                           "oppure pip install weasyprint")

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", dir=PROJECT_ROOT, delete=False, encoding="utf-8")
    tmp.close()
    tmp_path = Path(tmp.name)
    try:
        r = subprocess.run(
            [pandoc, str(md), "--standalone",
             "--template", str(TEMPLATE_HTML),
             "--css", str(TEMPLATE_CSS),
             "--toc", "--toc-depth=2",
             "--syntax-highlighting=none",
             "-o", str(tmp_path)],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            return False, f"pandoc fallito:\n{r.stderr.strip()}"
        if use_module:
            from weasyprint import HTML as _WH
            _WH(filename=str(tmp_path), base_url=str(PROJECT_ROOT)).write_pdf(str(out_pdf))
        else:
            r = subprocess.run([weasy, str(tmp_path), str(out_pdf)],
                               cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=180)
            if r.returncode != 0:
                return False, f"weasyprint fallito:\n{r.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return False, "Timeout durante la compilazione del PDF."
    except Exception as e:  # noqa: BLE001
        return False, f"Errore durante il build: {e}"
    finally:
        tmp_path.unlink(missing_ok=True)
    return True, str(out_pdf)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_report_help() -> None:
    print()
    print("\033[1mreport — Report di Penetration Test (template SLCtrl)\033[0m")
    print()
    print("  \033[92;1mUso:\033[0m")
    print('  report new "Cliente" [tipo]   Crea un nuovo report dal template')
    print("  report list                   Elenca i report esistenti")
    print("  report edit <nome|num>        Apre il report in VS Code (o derivati)")
    print("  report build <nome|num>       Genera il PDF (pandoc + weasyprint)")
    print("  report path <nome|num>        Mostra il percorso del file .md")
    print()
    print("  \033[92;1mEsempi:\033[0m")
    print('  report new "Acme Corp"')
    print('  report new "Acme Corp" "Web Application Penetration Test"')
    print("  report edit acme-corp")
    print("  report build 1")
    print()
    print("  \033[92;1mNote:\033[0m")
    print("  - I report vivono in \033[96mreports/<cliente>/\033[0m dentro il progetto SeaLion")
    print("  - Screenshot ed evidenze in \033[96mreports/<cliente>/evidence/\033[0m")
    print('  - Severità: <span class="sev sev-high">Alta</span>')
    print("    (sev-critical, sev-high, sev-medium, sev-low, sev-info)")
    print("  - 'report edit' cerca nel PATH: " + ", ".join(_VSCODE_CANDIDATES))
    print("  - Su SLWeb: anteprima e gestione dalla pagina \033[96m/report\033[0m")
    print()


def cmd_report(args: argparse.Namespace, state=None) -> int:
    action = (getattr(args, "action", None) or "").strip().lower()
    target = getattr(args, "target", None)
    extra = " ".join(getattr(args, "extra", []) or []).strip() or None

    if action in ("", "help", "-h", "--help"):
        if not action:
            reports = list_reports()
            print(f"\nReport esistenti: \033[1m{len(reports)}\033[0m  (cartella reports/)")
            print("Digita '\033[96mreport help\033[0m' per i comandi, '\033[96mreport new \"Cliente\"\033[0m' per iniziare.\n")
            return 0
        _print_report_help()
        return 0

    if action == "new":
        client = target
        if not client:
            print('Uso: report new "Nome Cliente" ["Tipo di test"]', file=sys.stderr)
            return 1
        try:
            out = create_report(client, extra or "Penetration Test Interno")
        except (ValueError, FileExistsError, FileNotFoundError) as e:
            print(f"\033[91m[!]\033[0m {e}", file=sys.stderr)
            return 1
        slug = out.parent.name
        print(f"\n\033[92m[+]\033[0m Report creato: \033[96m{out}\033[0m")
        print(f"\033[92m[+]\033[0m Evidenze in:    reports/{slug}/evidence/")
        print("\nProssimi passi:")
        print(f"  report edit {slug}     # apri in VS Code e compila")
        print(f"  report build {slug}    # genera il PDF\n")
        return 0

    if action == "list":
        reports = list_reports()
        if not reports:
            print("\nNessun report. Creane uno con: \033[96mreport new \"Nome Cliente\"\033[0m\n")
            return 0
        print(f"\nReport esistenti ({len(reports)}):\n")
        for i, r in enumerate(reports, 1):
            pdf_tag = "  \033[92m[PDF]\033[0m" if r["pdf"] else ""
            ev_tag = f"  \033[90m({r['evidence']} evidenze)\033[0m" if r["evidence"] else ""
            client = r["client"] or r["slug"]
            print(f"  [{i}] \033[1m{r['slug']}\033[0m — {client}{pdf_tag}{ev_tag}")
        print()
        return 0

    if action == "edit":
        ok, msg = edit_report(target)
        print(("\033[92m[+]\033[0m " if ok else "\033[91m[!]\033[0m ") + msg)
        return 0 if ok else 1

    if action == "build":
        if not target:
            print("Uso: report build <nome|num>", file=sys.stderr)
            return 1
        print("Compilazione PDF in corso…")
        ok, msg = build_report(target)
        if ok:
            print(f"\033[92m[+]\033[0m PDF generato: \033[96m{msg}\033[0m")
        else:
            print(f"\033[91m[!]\033[0m {msg}", file=sys.stderr)
        return 0 if ok else 1

    if action == "path":
        rep = find_report(target)
        if rep is None:
            print("\033[91m[!]\033[0m Report non trovato.", file=sys.stderr)
            return 1
        print(rep["md"])
        return 0

    print(f"Azione sconosciuta: {action}. Digita 'report help'.", file=sys.stderr)
    return 1
