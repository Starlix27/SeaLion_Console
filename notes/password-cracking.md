# Password Cracking

## Autenticazione

- **Qualcosa che sai:** password o PIN
- **Qualcosa che hai:** telefono o smartcard
- **Qualcosa che sei:** caratteri biometrici
- **Dove sei:** geolocalizzazione o IP

**TTP** = Tactics, Techniques, and Procedures — concetto della Cyber Threat Intelligence per analizzare il comportamento degli attaccanti.

- **HaveIBeenPwned:** per controllare se una mail è stata in data breaches
- Le password vengono hashate quando storate (MD5 / SHA-256)
- **Rainbow tables** (crackstation.net): archivi di testo hashato
  - Salting: aggiungere bit casuali alle password per prevenire lookup in rainbow tables
- **SecLists** include rockyou.txt per bruteforcing: `cat /usr/share/wordlists/rockyou.txt`
  - Download: https://github.com/danielmiessler/SecLists

---

## Credenziali di Default

Prima di fare brute force, controlla sempre se il prodotto ha credenziali di default note.

```bash
# Installazione
pip3 install defaultcreds-cheat-sheet

# Cerca credenziali di default per un prodotto
creds search <product>
```

```bash
# Esempi
creds search tomcat
creds search jenkins
creds search mysql
creds search phpmyadmin
```

> Fonte: https://github.com/ihebski/DefaultCreds-cheat-sheet

---

## John The Ripper (JtR)

Usato per crack password con bruteforce e dizionario. La versione **Jumbo** aggiunge funzioni extra e performance migliorate.

### Single Crack Mode

Tecnica per credenziali Linux. Genera password in base a username, homedir, variabili GECOS.

```bash
# Crack con dati da passwd
john --single passwd

# Vedere la password decifrata
john --show passwd
```

### Wordlist Mode

```bash
# Crack con dizionario
john --wordlist=<wordlist_file> <hash_file>

# Con regole di mutazione
john --wordlist=/usr/share/wordlists/rockyou.txt --rules my_hashes.txt
```

### Incremental Mode

Crea password basate su modello statistico (Markov Chains). Esaustiva ma lenta.

```bash
john --incremental <hash_file>
```

### Identificazione Hash

```bash
# hashID per identificare il formato
pip install hashid
hashid -j 193069ceb0461e1d40d216e32c79c704
```

Per specificare il formato: `john --format=<format> <hash_file>`

### Cracking Files

```bash
# Trovare script di conversione
locate *2john*

# Esempi
ssh2john.py SSH.private > ssh.hash
john --wordlist=rockyou.txt ssh.hash
john ssh.hash --show

# Office
office2john.py Protected.docx > protected-docx.hash
john --wordlist=rockyou.txt protected-docx.hash

# PDF
pdf2john.py PDF.pdf > pdf.hash
john --wordlist=rockyou.txt pdf.hash
```

### Tools 2john

| Tool | Descrizione |
|------|-------------|
| `pdf2john` | PDF documents |
| `ssh2john` | SSH private keys |
| `keychain2john` | OS X keychain |
| `rar2john` | RAR archives |
| `keepass2john` | KeePass databases |
| `zip2john` | ZIP archives |
| `office2john` | MS Office documents |
| `putty2john` | PuTTY private keys |
| `hccap2john` | WPA/WPA2 captures |
| `bitlocker2john` | BitLocker volumes |

---

## Hashcat

Simile a JtR, ma con molte più modalità. Opera su Linux, MacOS e Windows.

```bash
# Sintassi base
hashcat -a <attack_mode> -m <hash_type> <hashes> [wordlist, rule, mask, ...]

# Vedere categorie hash
hashcat --help

# Identificare hash con hashid
hashid -m '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'
```

### Dictionary Attack (`-a 0`)

```bash
# Con regole
hashcat -a 0 -m 0 <hash> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# IPMI hash (mode 7300)
hashcat -a 0 -m 7300 ipmi.txt -r /usr/share/hashcat/rules/best64.rule /usr/share/wordlists/rockyou.txt
```

Rules disponibili: `ls -l /usr/share/hashcat/rules`

### Mask Attack (`-a 3`)

Bruteforce con maschera se conosci la struttura della password.

| Simbolo | Charset |
|---------|---------|
| `?l` | a-z |
| `?u` | A-Z |
| `?d` | 0-9 |
| `?h` | 0-9a-f |
| `?H` | 0-9A-F |
| `?s` | Caratteri speciali |
| `?a` | `?l?u?d?s` (tutti) |

```bash
# Esempio: Ullll9!
hashcat -a 3 -m 0 <hash> '?u?l?l?l?l?d?s'

# Charset personalizzato
hashcat -m 0 hash.txt -1 ciao12 ?1?1?1?1
```

---

## Wordlist Personalizzate

### Regole di mutazione Hashcat

| Funzione | Descrizione |
|----------|-------------|
| `:` | Nessuna modifica |
| `l` | Tutto minuscolo |
| `u` | Tutto maiuscolo |
| `c` | Prima lettera maiuscola |
| `sXY` | Sostituisci X con Y |
| `$!` | Aggiungi `!` alla fine |

```bash
# Generare mutazioni
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list

# Filtrare per lunghezza (>= 12 char)
cat mut_password.list | awk 'length($0) >= 12' > mut_password_12.list
```

### CeWL — Generazione wordlist da siti web

```bash
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
wc -l inlane.wordlist
```

---

## Crackare Archivi Protetti

### ZIP
```bash
zip2john ZIP.zip > zip.hash
john --wordlist=rockyou.txt zip.hash
```

### GZIP (OpenSSL encrypted)
```bash
file GZIP.gzip  # -> "openssl enc'd data with salted password"
for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
```

### BitLocker
```bash
# Estrarre hash
bitlocker2john -i Backup.vhd > backup.hashes
grep "bitlocker\$0" backup.hashes > backup.hash

# Crack con hashcat (mode 22100)
hashcat -a 0 -m 22100 '<hash>' /usr/share/wordlists/rockyou.txt

# Montare su Linux con dislocker
sudo apt-get install dislocker
sudo mkdir -p /media/bitlocker /media/bitlockermount
sudo losetup -f -P Backup.vhd
sudo dislocker /dev/loop0p2 -u<password> -- /media/bitlocker
sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount

# Smontare
sudo umount /media/bitlockermount
sudo umount /media/bitlocker
```

### File encriptati — Cercare estensioni
```bash
for ext in $(echo ".xls .xls* .xltx .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

### SSH Keys
```bash
# Cercare chiavi private
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null

# Verificare se è cifrata
ssh-keygen -yf ~/.ssh/id_ed25519

# Crackare passphrase
ssh2john.py SSH.private > ssh.hash
john --wordlist=rockyou.txt ssh.hash
```
