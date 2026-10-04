# RustNet — Network monitor TUI

**RustNet** è un monitor di rete scritto in Rust: mostra in tempo reale connessioni attive, porte in ascolto e processi associati, in un'interfaccia a terminale.

---

## A cosa serve?

- **Vista live:** connessioni TCP/UDP e processo proprietario, aggiornate in tempo reale
- **Post-exploitation:** su una target vedi chi parla con chi senza tcpdump
- **Binario statico:** nessuna dipendenza pesante, cross-platform

---

## Come usarlo

### Monitor live (TUI)

```bash
rustnet
```

### Con privilegi (più dettagli sui processi)

```bash
sudo rustnet
```

> In linseal è l'alternativa grafica a `ss -tlnp`; per una lista statica resta meglio `ss`.
> Fonte: https://github.com/domcyrus/rustnet
