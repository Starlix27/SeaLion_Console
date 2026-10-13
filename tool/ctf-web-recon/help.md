# ctf-web-recon — ricognizione + attacco per web CTF

Un comando che mappa il target e prova gli attacchi web standard su ogni parametro che trova (form HTML inclusi). Output in `./ctf-recon-<timestamp>/` con `report.md` finale.

## Uso

```bash
ctf-wr -u URL [fasi...] [opzioni]
```

**Fasi** — se omesse le esegue tutte; se ne scrivi una o più esegue solo quelle:

| fase | cosa fa | tool |
|---|---|---|
| `dirs` | directory e file nascosti | ffuf |
| `params` | parametri nascosti | form HTML + arjun |
| `scan` | CVE e misconfigurazioni | nuclei |
| `xss` | cross-site scripting | dalfox |
| `sqli` | SQL injection | sqlmap |
| `ssti` | template injection | probe built-in + sstimap |

**Opzioni:** `-c "k=v"` cookie · `-p nome` parametro noto (ripetibile) · `-o dir` output · `--fast` timeout ridotti · `--skip x,y` salta fasi

## Esempi

```bash
ctf-wr -u http://target                 # tutto
ctf-wr -u http://target ssti            # solo SSTI
ctf-wr -u http://target xss sqli        # solo XSS e SQLi
ctf-wr -u http://target/search -p q     # parametro noto, niente discovery
ctf-wr -u http://target -c "session=X" --fast
```

## Note

- Le fasi di attacco testano: `-p`, form HTML della pagina, parametri da arjun, altrimenti una lista di nomi comuni
- La fase `ssti` ha un **probe built-in** che funziona anche senza sstimap; all'avvio vedi subito quali tool mancano (`install ctf-web-toolkit` per averli tutti)
- I finding vanno **verificati a mano**: i tool danno candidati, non flag
