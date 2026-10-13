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

**Opzioni:** `-c "k=v"` cookie · `-p nome` parametro noto (ripetibile) · `-o dir` output · `--fast` timeout ridotti · `--skip x,y` salta fasi · `-y` installa dipendenze senza chiedere · `--no-install` non installare nulla

## Esempi

```bash
ctf-wr -u http://target                 # tutto
ctf-wr -u http://target ssti            # solo SSTI
ctf-wr -u http://target xss sqli        # solo XSS e SQLi
ctf-wr -u http://target/search -p q     # parametro noto, niente discovery
ctf-wr -u http://target -c "session=X" --fast
```

## Dipendenze

All'avvio ctf-wr mostra lo stato di ogni fase e, se manca un tool, spiega **perché** la fase non partirebbe (o in cosa sarebbe limitata) e propone di installarlo subito:

```bash
ctf-wr deps               # tabella: cosa c'è e cosa manca
ctf-wr deps --install     # installa tutto il necessario
```

`arjun` e `sstimap` sono opzionali: senza arjun la fase `params` usa form HTML e nomi comuni; senza sstimap la fase `ssti` usa il **probe built-in**. In alternativa, dalla console SeaLion: `install ctf-web-toolkit`.

## Note

- Le fasi di attacco testano: `-p`, query nell'URL, form HTML della pagina, parametri da arjun, altrimenti una lista di nomi comuni
- Gli errori dei tool finiscono in `errors.log` nella cartella di output: se una fase non produce nulla, guarda lì
- I finding vanno **verificati a mano**: i tool danno candidati, non flag
