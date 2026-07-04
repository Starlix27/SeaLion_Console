# Scrapy — Web Crawling Framework

**Scrapy** è un framework Python potente e flessibile per costruire crawler web personalizzati. Usato nella sicurezza per mappare siti, estrarre link, email, commenti e file nascosti.

---

## A cosa serve?

- **Web Crawling:** Esplora siti seguendo i link automaticamente
- **Data Extraction:** Estrae dati strutturati dalle pagine
- **Personalizzazione:** Crea spider su misura per ogni target

---

## Come usarlo

### Installazione

```bash
pip3 install scrapy
```

### Creare un nuovo progetto

```bash
scrapy startproject myproject
```

### Spider base

```bash
scrapy crawl myspider -o results.json
```

### ReconSpider (HTB)

```bash
python3 ReconSpider.py http://target.com
```

> Fonte: https://github.com/scrapy/scrapy
