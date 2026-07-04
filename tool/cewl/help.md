# CeWL — Custom Word List Generator

**CeWL** scannerizza un sito web e crea una wordlist personalizzata basata sulle parole trovate nel contenuto. Perfetto per generare dizionari mirati per il password cracking.

---

## A cosa serve?

- **Wordlist da siti:** Estrae parole dal contenuto web
- **Personalizzazione:** Filtra per lunghezza minima e profondità di crawling
- **Email harvesting:** Può estrarre indirizzi email

---

## Come usarlo

### Generare wordlist base

```bash
cewl https://www.target.com -w wordlist.txt
```

### Con lunghezza minima 6 caratteri e profondità 4

```bash
cewl https://www.target.com -d 4 -m 6 --lowercase -w wordlist.txt
```

### Estrarre anche email

```bash
cewl https://www.target.com -e --email_file emails.txt
```

### Contare parole nella lista

```bash
wc -l wordlist.txt
```

> Fonte: https://github.com/digininja/CeWL
