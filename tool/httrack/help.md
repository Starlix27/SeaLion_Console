# HTTrack — Website Copier / Mirror

**HTTrack** clona un intero sito web localmente, mantenendo la struttura di directory, link e file. Utile nella fase di recon per analisi offline del contenuto, ricerca di file nascosti, commenti nel codice e informazioni sensibili.

---

## A cosa serve?

- **Mirror completo:** Scarica l'intero sito (HTML, CSS, JS, immagini, PDF, ecc.)
- **Analisi offline:** Cerca credenziali, path, commenti, endpoint API senza fare rumore
- **Struttura directory:** Rivela l'organizzazione interna del sito (cartelle, file nascosti)
- **Ricerca post-download:** grep su tutto il sito per trovare token, password, email, path interni

---

## Come usarlo

### Mirror base

```bash
httrack http://target.com -O /output/target
```

### Mirror con profondita' limitata

```bash
httrack http://target.com -O /output/target -r3
```

### Solo file specifici (es. PDF, backup, config)

```bash
httrack http://target.com -O /output/target "+*.pdf" "+*.bak" "+*.zip" "+*.conf" "+*.sql"
```

### Mirror silenzioso (no interattivo)

```bash
httrack http://target.com -O /output/target --quiet -r4
```

### Restare nel dominio (no link esterni)

```bash
httrack http://target.com -O /output/target -%e0
```

---

## Analisi post-download

```bash
# Cerca credenziali e informazioni sensibili nel mirror
grep -ri 'password\|passwd\|secret\|api.key\|token' /output/target/
grep -ri 'admin\|login\|dashboard' /output/target/
grep -ri '<!--' /output/target/ | head -50              # Commenti HTML (spesso contengono info utili)
find /output/target/ -name "*.bak" -o -name "*.old" -o -name "*.zip" -o -name "*.sql"
```

> Fonte: https://www.httrack.com
