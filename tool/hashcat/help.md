# Hashcat — Advanced Password Recovery

**Hashcat** è il tool di password cracking più veloce al mondo, con supporto GPU. Supporta centinaia di formati hash e modalità di attacco.

---

## A cosa serve?

- **Dictionary Attack (-a 0):** Wordlist + regole
- **Mask Attack (-a 3):** Brute force con pattern definiti
- **Combinator Attack (-a 1):** Combina parole da due dizionari
- **GPU Accelerated:** Sfrutta la potenza delle schede grafiche

---

## Come usarlo

### Dictionary attack

```bash
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

### Con regole

```bash
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### Mask attack (password 7 char: Maiuscola + 4 minuscole + numero + simbolo)

```bash
hashcat -a 3 -m 0 hash.txt '?u?l?l?l?l?d?s'
```

### Charset personalizzato

```bash
hashcat -a 3 -m 0 hash.txt -1 'aeiou123' '?1?1?1?1'
```

### IPMI hash cracking

```bash
hashcat -a 0 -m 7300 ipmi.txt /usr/share/wordlists/rockyou.txt
```

### Generare wordlist con mutazioni

```bash
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

### Charset Symbols

| Symbol | Charset |
|--------|---------|
| ?l | a-z |
| ?u | A-Z |
| ?d | 0-9 |
| ?s | Simboli speciali |
| ?a | Tutti i precedenti |

> Fonte: https://github.com/hashcat/hashcat
