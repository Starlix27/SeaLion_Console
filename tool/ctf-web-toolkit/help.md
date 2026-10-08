# ctf-web-toolkit — Tutti i tool web per CTF in un colpo solo

Installa i tool che mancano per le web challenge CTF.

| Tool | Attacco | Metodo di installazione |
|---|---|---|
| dalfox | XSS scanner (headless) | binario da GitHub → `~/.local/bin` |
| SSTImap | SSTI → RCE | git clone + pip |
| XSStrike | XSS scanner | git clone + pip |
| dirsearch | directory discovery | pip |
| zaproxy | scanner generalista OWASP | apt |

Già presenti sul sistema: sqlmap, nmap, nikto, gobuster, ffuf, feroxbuster, wfuzz, nuclei, commix, hydra, Burp Suite.

## Uso

Dalla console SeaLion:

```
install ctf-web-toolkit
```

Al termine i comandi `dalfox`, `sstimap`, `xsstrike`, `dirsearch` e `zap` saranno disponibili nel PATH (`~/.local/bin`).
