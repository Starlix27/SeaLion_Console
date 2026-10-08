# ctf-web-recon — Pipeline ricognizione→attacco per web CTF

Un solo comando che concatena tutti i tool di attacco web in stile ricognizione: mappa il target e poi prova gli attacchi standard su ogni parametro trovato.

## Fasi

1. **dirs** — `ffuf`: directory e file nascosti (wordlist seclists, auto-calibration)
2. **params** — `arjun`: parametri nascosti sull'URL base + primi endpoint trovati
3. **scan** — `nuclei`: CVE e misconfigurazioni (severity medium+)
4. **xss** — `dalfox`: XSS verificato via headless browser su ogni URL con parametri
5. **sqli** — `sqlmap`: SQLi level 1 / risk 1 su ogni URL con parametri
6. **ssti** — `sstimap`: template injection su ogni URL con parametri

Ogni fase scrive file nella cartella di output; alla fine viene generato `report.md` con il riepilogo dei finding.

I tool mancanti vengono saltati con un avviso — installali tutti con `install ctf-web-toolkit`.

## Uso

```bash
ctf-wr -u http://target                      # scan completo
ctf-wr -u http://target -o mia-out           # cartella output custom
ctf-wr -u http://target -c "session=XXX"     # dietro autenticazione
ctf-wr -u http://target --skip sqli,ssti     # salta fasi
ctf-wr -u http://target --fast               # timeout ridotti
```

## Note

- I finding vanno sempre **verificati a mano**: i tool danno candidati, non flag
- Dopo il report, l'approfondimento manuale tipico: `sqlmap -u TARGET --dbs`, `sstimap -u TARGET --os-shell`, payload XSS custom verso webhook.site
- Per i bug custom (logica, DOM clobbering, race condition) serve Burp + cervello
