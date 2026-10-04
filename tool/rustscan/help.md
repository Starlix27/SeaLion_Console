# RustScan — Port scanner veloce

**RustScan** è un port scanner scritto in Rust: scansiona tutte le 65535 porte TCP in pochi secondi, poi può passare le porte aperte a nmap per versioni e script.

---

## A cosa serve?

- **Discovery fulminea:** tutte le porte TCP in secondi, non minuti
- **Integrazione nmap:** dopo `--` i flag vengono passati a nmap (`-sV -sC`, NSE)
- **Output greppabile:** `-g` stampa solo `ip -> [porte]`, ideale negli script

---

## Come usarlo

### Scan completo + versioni/script (via nmap)

```bash
rustscan -a 10.129.14.128 -- -sV -sC
```

### Solo discovery, output greppabile

```bash
rustscan -g -a 10.129.14.128
```

### Top 1000 porte / range custom

```bash
rustscan -g --top -a 10.129.14.128
rustscan -g -r 1-10000 -a 10.129.14.128
```

### Tarare batch e timeout (rete lenta o fragile)

```bash
rustscan -a 10.129.14.128 -b 1500 -t 2000
```

> Solo TCP: per UDP serve nmap (`sudo nmap -sU --top-ports 50 <target>`).
> Fonte: https://github.com/RustScan/RustScan
