**Nikto** è un vulnerabilty scanner open source specifico per **web server**. Il suo scopo principale è individuare potenziali minacce, configurazioni errate e file pericolosi o obsoleti su un sito o server web.

Ecco un riassunto rapido di cosa fa e come si usa.

---

## A cosa serve?

Nikto esegue una scansione rapida del target alla ricerca di oltre 6.700 elementi vulnerabili. In particolare, serve a trovare:

* **Configurazioni errate:** File di configurazione lasciati esposti o server non aggiornati.
* **File e script pericolosi:** File residui di installazioni, script di test o vulnerabilità note nei CMS (come WordPress, Joomla, ecc.).
* **Software obsoleto:** Versioni di server web (Apache, Nginx, IIS) vecchie e vulnerabili.
* **Problemi di header:** Assenza di header di sicurezza (X-Frame-Options, X-Content-Type-Options, ecc.).

> ⚠️ **Nota bene:** Nikto **non è uno strumento silenzioso**. Genera moltissimo traffico nei file di log del server, quindi viene facilmente rilevato da qualsiasi sistema di difesa (IDS/IPS o WAF). Usalo solo su sistemi di tua proprietà o su cui hai un'esplicita autorizzazione.

---

## Come usarlo (Comandi principali)

Nikto si usa esclusivamente da **riga di comando** (terminale). La sintassi base è semplicissima.

### 1. Scansione base di un sito (HTTP)

Per scansionare un host sulla porta standard (80):

```bash
nikto -h http://www.esempio.com

```

*(Puoi usare sia il nome del dominio che l'indirizzo IP).*

### 2. Scansione su porta specifica o HTTPS (SSL)

Se il sito usa HTTPS (porta 443) o un'altra porta specifica, basta indicarla nel comando:

```bash
nikto -h https://www.esempio.com -ssl

```

Oppure specificando una porta diversa (es. 8080):

```bash
nikto -h 192.168.1.50 -p 8080

```

### 3. Salvare i risultati in un file

Le scansioni possono essere lunghe. Per salvare il report in un formato leggibile (es. HTML o testo):

```bash
nikto -h http://www.esempio.com -o report.html -Format htm

```

### 4. Scansione di più target insieme

Se hai una lista di siti o IP salvati in un file di testo (`lista.txt`), puoi scansionarli tutti in sequenza:

```bash
nikto -h lista.txt

```