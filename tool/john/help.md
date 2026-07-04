# John the Ripper — Password Cracker

**John the Ripper** (JtR) è uno dei tool di password cracking più utilizzati. Supporta centinaia di formati hash e modalità di attacco: single, wordlist e incremental.

---

## A cosa serve?

- **Single Crack:** Genera password da username e info GECOS
- **Wordlist:** Usa dizionari con regole di mutazione
- **Incremental:** Brute force basato su modelli statistici (Markov)
- **File Cracking:** Cracka file protetti (ZIP, PDF, SSH keys, Office)

---

## Come usarlo

### Single crack mode (credenziali Linux)

```bash
john --single passwd
```

### Wordlist mode

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

### Con regole di mutazione

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --rules hashes.txt
```

### Incremental mode

```bash
john --incremental hashes.txt
```

### Specificare formato hash

```bash
john --format=raw-md5 hashes.txt
```

### Vedere password craccate

```bash
john hashes.txt --show
```

### Cracking file protetti (con tool *2john)

```bash
ssh2john.py id_rsa > ssh.hash
pdf2john.py file.pdf > pdf.hash
zip2john file.zip > zip.hash
office2john.py file.docx > office.hash
john --wordlist=rockyou.txt ssh.hash
```

> Fonte: https://github.com/openwall/john
