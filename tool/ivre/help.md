# IVRE — Shodan self-hosted

**IVRE** è un framework open source di network recon: un'alternativa self-hosted e completamente sotto il tuo controllo a **Shodan, ZoomEye, Censys e GreyNoise**. Scansiona con Nmap, Masscan e ZGrab2, indicizza banner e servizi in un database e li espone in una **web UI con ricerca a filtri stile Shodan** — screenshot dei servizi web inclusi.

---

## A cosa serve?

- **Il tuo Shodan personale:** ricerca con filtri (`port:`, `product:`, `country:`, `host:`, `service:`…) sui risultati delle TUE scansioni
- **Screenshot:** anteprime dei servizi web direttamente nella UI (sezione images)
- **Host detail:** porte, banner, certificati TLS, script NSE, geolocalizzazione
- **Passive recon:** Zeek, p0f, Passive DNS, analisi dei flussi
- **Tre interfacce:** web UI, CLI (`ivre scancli`, `ivre ipinfo`), API Python

---

## Installazione

Richiede **Docker**: le immagini ufficiali `ivre/db`, `ivre/web` e `ivre/client` vengono scaricate automaticamente.

```bash
slconsole
> install ivre
```

Se Docker manca o non è avviato:

```bash
sudo apt install docker.io
sudo systemctl enable --now docker
```

## Come usarlo

### Prima configurazione (una tantum)

```bash
ivre init
```

Avvia i container, scarica i dati GeoIP (MaxMind) e inizializza il database.

### Scansionare un target (solo target autorizzati!)

```bash
ivre scan 10.10.11.23
ivre scan 192.168.1.0/24 LAB
```

Esegue `nmap -A` nel container client e importa i risultati nel database con categoria e sorgente.

### Aprire la web UI

```bash
ivre web        # oppure http://127.0.0.1:2728
```

Nella barra in alto si cercano i risultati con i filtri stile Shodan; la categoria **screenshots** mostra le anteprime dei servizi web trovati.

### Gestione dello stack

```bash
ivre up         # avvia i container (web UI su porta 2728)
ivre down       # ferma i container
ivre status     # stato dei container
ivre shell      # shell nel container client IVRE
```

### Workflow avanzato (da `ivre shell`)

```bash
ivre scancli --count                    # quanti host nel DB
ivre scancli --ports 22,80              # host con quelle porte aperte
ivre ipinfo 8.8.8.8                     # geoloc/ASN di un IP
nmap -A -oX /ivre-share/x.xml TARGET    # scan manuale (dir condivisa)
ivre scan2db -c LAB -s SEALION -r /ivre-share/x.xml
ivre db2view                            # aggiorna la vista della web UI
```

La directory `~/.sealionconsole/tools/ivre/ivre-share/` è montata come `/ivre-share` dentro i container: metti lì gli XML da importare.

---

## Note

- Porta web UI: **2728** (modificabile con la variabile `IVRE_PORT`)
- SLWeb mostra lo stato di IVRE nella home (sezione *Strumenti*): il link diventa verde/attivo quando la web UI risponde
- Scansiona solo reti e host per cui hai autorizzazione scritta
- Docs ufficiali: https://doc.ivre.rocks — Repo: https://github.com/ivre/ivre
