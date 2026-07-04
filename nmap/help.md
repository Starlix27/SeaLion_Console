# Nmap — Network Mapper

**Nmap** è il re degli scanner di rete. Serve a scoprire host attivi, porte aperte, servizi in esecuzione e versioni software su una rete.

---

## A cosa serve?

- **Scansione porte:** Scopre quali porte TCP/UDP sono aperte su un target
- **Rilevamento servizi:** Identifica il software in ascolto (Apache, OpenSSH, ecc.)
- **Rilevamento OS:** Indovina il sistema operativo del target
- **NSE Scripts:** Motore di scripting per vulnerability scanning, brute force, enumerazione

---

## Come usarlo

### Scansione base (Top 1000 porte)

```bash
nmap 10.129.14.128
```

### Scansione SYN stealth + versioni + script default

```bash
sudo nmap -sS -sV -sC 10.129.14.128
```

### Scansione aggressiva completa

```bash
sudo nmap -A -p- 10.129.14.128
```

### Scansione UDP

```bash
sudo nmap -sU --top-ports 100 10.129.14.128
```

### Scansione specifica con script NSE

```bash
sudo nmap --script smb-enum-shares -p445 10.129.14.128
sudo nmap --script ftp-anon -p21 10.129.14.128
```

### Salvare output in tutti i formati

```bash
sudo nmap -sV -sC -oA scan_results 10.129.14.128
```

> Fonte: https://github.com/nmap/nmap
