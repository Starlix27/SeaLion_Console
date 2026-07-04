# SSH — Secure Shell
**Porte:** 22 (TCP)  
**Categoria:** Accesso Remoto

Protocollo per connessioni remote cifrate. Standard per amministrazione Linux/Unix.
SSH-1 è insicuro (vulnerabile a MitM). SSH-2 è lo standard attuale.

6 metodi di autenticazione:
  1. Password  2. Public Key  3. Host-based  4. Keyboard  5. Challenge-Response  6. GSSAPI (Kerberos)

Chiavi SSH: la chiave privata (id_rsa) DEVE restare segreta.
Se trovi accesso a /home/user/.ssh/id_rsa puoi usarla per loggarti.
Alcune chiavi sono cifrate con passphrase → crackabili con ssh2john + JtR.

## Configurazione

- Config server: /etc/ssh/sshd_config
- Vedere config: cat /etc/ssh/sshd_config | grep -v '#' | sed -r '/^\s*$/d'

## Vulnerabilità comuni

- PermitRootLogin yes — accesso diretto come root da remoto
- PermitEmptyPasswords yes — login senza password (devastante)
- Protocol 1 — crittografia obsoleta, vulnerabile a MitM
- X11Forwarding yes — command injection in alcune versioni
- Password deboli — brute force con hydra/medusa
- Chiavi private esposte (id_rsa senza passphrase in share NFS/FTP/email)
- DebianBanner yes — mostra versione OS esatta (aiuta a scegliere exploit)

## Enumerazione & Comandi

### AUDIT CONFIGURAZIONE

```bash
./ssh-audit.py <IP>                                   # Audit completo (cifrari, KEX, chiavi host)
ssh -v user@<IP>                                      # Connessione verbose (vedi metodi auth)
ssh -v user@<IP> -o PreferredAuthentications=password  # Forza autenticazione password
sudo nmap -sV -p22 --script ssh* <IP>                 # Script NSE SSH
```

### BRUTE FORCE

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<IP>
```

### CHIAVI SSH

```bash
# Se trovi una chiave privata (id_rsa):
chmod 600 id_rsa                                      # Permessi restrittivi (obbligatorio)
ssh root@<IP> -i id_rsa                               # Login con chiave rubata
```

```bash
# Per cercare chiavi nel filesystem:
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null
```

```bash
# Se la chiave è cifrata con passphrase:
ssh-keygen -yf id_rsa                                 # Verifica se ha passphrase
ssh2john.py id_rsa > ssh.hash                         # Estrai hash per JtR
john --wordlist=rockyou.txt ssh.hash                  # Crack passphrase
john ssh.hash --show                                  # Mostra risultato
```

### PERSISTENZA

```bash
# Se hai accesso in scrittura a /home/user/.ssh/:
# Aggiungi la TUA chiave pubblica in authorized_keys → accesso permanente
```

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **nmap**
- **ssh-audit**
- **john**
- **hashcat**
- **seclists**
