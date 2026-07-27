# Dirsearch — Web Path Scanner

**Dirsearch** è un directory/file bruter scritto in Python. Facile da usare, con molte estensioni built-in e supporto per ricorsione.

---

## A cosa serve?

- **Directory / file discovery** su web server
- **Scansione multi-estensione** con liste built-in
- **Fuzzing ricorsivo** con profondità configurabile

---

## Come usarlo

### Scansione base

```bash
dirsearch -u http://target.com
```

### Con wordlist custom e estensioni

```bash
dirsearch -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -e php,txt,bak -t 50
```

### Ricorsione

```bash
dirsearch -u http://target.com -r -R 3 -e php,txt
```

### Con proxy (Burp)

```bash
dirsearch -u http://target.com --proxy http://127.0.0.1:8080
```

---

## Opzioni utili

| Flag | Descrizione |
|------|-------------|
| `-u` | URL target |
| `-w` | Wordlist (ha una wordlist built-in di default) |
| `-e php,txt` | Estensioni |
| `-t 50` | Thread |
| `-r` | Ricorsione abilitata |
| `-R 3` | Profondità ricorsione |
| `-x 403,404` | Escludi status code |
| `-i 200,301` | Includi solo questi status code |
| `--proxy` | Proxy HTTP |
| `-H "Cookie: x=y"` | Header custom |
| `-o output.txt` | Salva output |
| `--format json` | Formato output (plain, json, xml, csv) |
| `-f` | Forza estensioni su ogni parola |
| `--random-agent` | User-Agent random |

---

## Vantaggi

- Wordlist built-in di qualità (non serve SecLists per iniziare)
- Molto semplice per un primo giro veloce
- Supporto per più target contemporaneamente (`-l urls.txt`)

> Fonte: https://github.com/maurosoria/dirsearch
