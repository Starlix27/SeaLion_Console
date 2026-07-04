# hashID — Hash Identifier

**hashID** identifica il tipo di hash analizzando il formato della stringa. Supporta oltre 220 tipi di hash e può mostrare il formato corrispondente per John the Ripper e Hashcat.

---

## A cosa serve?

- **Identificazione hash:** Riconosce MD5, SHA, bcrypt, NTLM e molti altri
- **Integrazione JtR/Hashcat:** Mostra il formato corretto per il cracking

---

## Come usarlo

### Identificare un hash

```bash
hashid '5f4dcc3b5aa765d61d8327deb882cf99'
```

### Con formato John the Ripper

```bash
hashid -j '5f4dcc3b5aa765d61d8327deb882cf99'
```

### Con formato Hashcat

```bash
hashid -m '5f4dcc3b5aa765d61d8327deb882cf99'
```

> Fonte: https://github.com/psypanda/hashID
