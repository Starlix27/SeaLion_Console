# IMAP/POP3 — Protocolli di lettura email
**Porte:** 143 (IMAP), 110 (POP3), 993 (IMAPS), 995 (POP3S)  
**Categoria:** Email

IMAP: le email restano sul server e si sincronizzano su tutti i dispositivi in tempo reale.
POP3: scarica le email in locale e le cancella dal server. No sincronizzazione multi-device.

IMAP è il più flessibile (cartelle, stato messaggi). POP3 è più semplice.
Entrambi viaggiano in chiaro sulle porte standard (143/110).
Le porte cifrate sono 993 (IMAPS) e 995 (POP3S).

Per testing locale: pacchetti dovecot-imapd e dovecot-pop3d.

## Configurazione

- Server comune: Dovecot

## Vulnerabilità comuni

- auth_debug_passwords=yes — password scritte nei log in chiaro!
- auth_verbose_passwords=yes — password nei log (anche troncate)
- Autenticazione anonima (SASL ANONYMOUS) — accesso senza credenziali
- Connessione in chiaro (porte 143/110) — credenziali sniffabili
- Email con chiavi SSH o password nel body → leggi FETCH BODY[TEXT]!

## Enumerazione & Comandi

### SCAN

```bash
sudo nmap -sV -p110,143,993,995 -sC <IP>            # Scan tutte le porte email
```

### CONNESSIONE CON curl

```bash
curl -k 'imaps://<IP>' --user user:password           # Login IMAP con curl
curl -k 'imaps://<IP>' --user user:password -v        # Verbose (dettagli TLS, banner)
curl -k 'imaps://<IP>/INBOX;UID=1' --user user:pass   # Leggi email specifica per UID
```

### CONNESSIONE CIFRATA

```bash
openssl s_client -connect <IP>:imaps -crlf            # IMAP over SSL
openssl s_client -connect <IP>:pop3s                  # POP3 over SSL
```

### COMANDI IMAP (dopo connessione)

```bash
  1 LOGIN user password                              # Autenticazione
  1 LIST "" *                                         # Lista tutte le cartelle
  1 SELECT INBOX                                      # Seleziona inbox
  1 FETCH <ID> all                                   # Header + metadata email
  1 FETCH 1 (BODY[TEXT])                              # Corpo email → CERCA CHIAVI SSH!
  1 CLOSE                                             # Rimuovi email marcate come eliminate
  1 LOGOUT                                            # Disconnetti
```

### COMANDI POP3

```bash
  USER username > PASS password > STAT > LIST > RETR 1 > DELE 1 > QUIT
```

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **nmap**
