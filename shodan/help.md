# Shodan — Il motore di ricerca dei dispositivi

**Shodan** scansiona Internet e indicizza i banner dei servizi esposti: server, webcam, router, database e molto altro.

---

## A cosa serve?

- **Ricerca dispositivi:** Trova server, IoT, webcam esposti su Internet
- **Analisi host:** Mostra porte aperte, versioni software, certificati SSL
- **Ricerca per organizzazione:** Filtra per azienda, paese, tecnologia

---

## Installazione

```bash
pip install shodan
shodan init TUA_API_KEY
```

## Come usarlo

### Analizzare un host

```bash
shodan host 10.129.27.33
```

### Ricerca generica

```bash
shodan search "Apache 2.4.41"
shodan search "org:NomeAzienda"
```

### Contare i risultati

```bash
shodan count "org:NomeAzienda"
```

### Vedere il proprio IP pubblico

```bash
shodan myip
```

### Scansione automatica di una lista IP

```bash
for i in $(cat ip-addresses.txt); do shodan host $i; done
```

### Filtri utili

```bash
shodan search org:"Nome Azienda" --fields ip_str,port,org
```

> API Key gratuita: https://shodan.io
> Fonte: https://github.com/achillean/shodan-python
