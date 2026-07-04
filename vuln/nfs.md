# NFS — Network File System
**Porte:** 2049 (NFS), 111 (RPCBind/Portmapper)  
**Categoria:** Trasferimento File

Protocollo per accedere a filesystem remoti come se fossero locali.
Usato principalmente su Linux/Unix. Non può comunicare con SMB.

Non ha meccanismi di autenticazione propri — si fida del UID/GID del client.
NFSv4 usa porta unica 2049 TCP/UDP. Versioni precedenti necessitano anche di RPCBind (porta 111).

Versioni: NFSv2 (UDP) → NFSv3 (file variabili) → NFSv4 (Kerberos, ACL, stateful) → NFSv4.1 (pNFS parallelo).
Usa ONC-RPC e formato XDR per compatibilità tra SO diversi.

## Configurazione

- File export: /etc/exports (tabella filesystem condivisi)
- Vedere config: cat /etc/exports
- Riavviare dopo modifiche: exportfs -ra
- Opzioni chiave: rw/ro, sync/async, secure/insecure, root_squash/no_root_squash

## Vulnerabilità comuni

- no_root_squash — root remoto = root locale → privilege escalation immediata
- Nessuna autenticazione interna — si fida del UID/GID del client (falsificabile)
- Export aperti a 0.0.0.0/0 — chiunque può montare le share da qualsiasi IP
- Disallineamento UID — utente 1001 su client ≠ utente 1001 su server → accessi incrociati
- insecure — accetta connessioni da porte sopra 1024 (bypass restrizioni)
- root_squash attivo → non puoi modificare file anche se root (attenzione alla verifica)

## Enumerazione & Comandi

### RILEVAMENTO

```bash
showmount -e <IP>                                    # Lista export: chi può accedere e a cosa
sudo nmap -p111,2049 -sV -sC <IP>                   # Scan porte NFS/RPC
sudo nmap --script nfs* -sV -p111,2049 <IP>         # Script NSE: export, permessi, vuln note
```

### MONTARE UNA SHARE

```bash
sudo mkdir -p /mnt/target_nfs                        # Crea punto di mount locale
sudo mount -t nfs <IP>:/<share> /mnt/target_nfs -o nolock  # Monta la share (-o nolock se NLM non attivo)
```

### ESPLORAZIONE

```bash
ls -la /mnt/target_nfs                               # Esplora con username/groupname
ls -n /mnt/target_nfs                                # Mostra UID/GID numerici (verifica permessi)
tree /mnt/target_nfs                                 # Struttura completa ad albero
```

### SMONTARE

```bash
cd ~ && sudo umount /mnt/target_nfs                  # Smonta quando finito (esci prima dalla dir!)
```

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **nmap**
