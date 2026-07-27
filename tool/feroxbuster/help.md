# Feroxbuster — Recursive Content Discovery

**Feroxbuster** è un tool di content discovery scritto in Rust. Velocissimo, supporta ricorsione automatica, filtri avanzati e resume delle scansioni.

---

## A cosa serve?

- **Directory / file bruting** con ricorsione automatica
- **Fuzzing ricorsivo** — quando trova una directory, ci entra e continua a scansionare
- **Scansioni resilienti** — salva lo stato e può riprendere dopo un'interruzione

---

## Come usarlo

### Directory fuzzing base

```bash
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

### Con estensioni

```bash
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,txt,bak -t 50
```

### Senza ricorsione

```bash
feroxbuster -u http://target.com/api -w /usr/share/seclists/Discovery/Web-Content/common.txt --no-recursion
```

### Filtri

```bash
# Filtra per status code
feroxbuster -u http://target.com -w wordlist.txt -C 404,403

# Filtra per dimensione risposta
feroxbuster -u http://target.com -w wordlist.txt -S 0

# Filtra per numero di parole
feroxbuster -u http://target.com -w wordlist.txt -W 12
```

---

## Opzioni utili

| Flag | Descrizione |
|------|-------------|
| `-u` | URL target |
| `-w` | Wordlist |
| `-x php,txt` | Estensioni da aggiungere |
| `-t 50` | Thread (default 50) |
| `-d 3` | Profondità ricorsione (default 4) |
| `--no-recursion` | Disabilita ricorsione |
| `-C 404,403` | Escludi status code |
| `-S 0` | Escludi risposte di N byte |
| `-W 12` | Escludi risposte con N parole |
| `-k` | Ignora errori SSL |
| `-o output.txt` | Salva output |
| `--resume-from state.json` | Riprendi scansione |
| `-p http://127.0.0.1:8080` | Proxy (Burp) |
| `-H "Cookie: session=abc"` | Header custom |
| `-r` | Segui redirect |

---

## Differenze con gobuster/ffuf

| | feroxbuster | gobuster | ffuf |
|---|---|---|---|
| Ricorsione | Automatica | No | Sì (manuale) |
| Resume | Sì | No | No |
| Velocità | Molto veloce (Rust) | Veloce (Go) | Veloce (Go) |
| Filtri | Status/size/words/lines | Status | Status/size/words/lines/regex |

> Fonte: https://github.com/epi052/feroxbuster
