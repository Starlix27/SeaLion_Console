# SMTP — Simple Mail Transfer Protocol
**Porte:** 25 (standard), 587 (submission autenticata), 465 (SMTPS)  
**Categoria:** Email

Protocollo per l'invio di email. Spesso combinato con IMAP/POP3 per la lettura.
Trasmette dati in chiaro senza SSL/TLS. ESMTP è la versione moderna con STARTTLS.

Flusso email: MUA (client) → MSA (verifica auth) → MTA (postino, cerca DNS) → MDA (consegna) → Mailbox (POP3/IMAP)

Meccanismi di sicurezza:
  SMTP-Auth: obbliga username+password prima di inviare
  STARTTLS: attiva crittografia TLS dopo la connessione
  SPF: specifica quali server possono inviare per un dominio
  DKIM: firma digitale sul messaggio (integrità)
  DMARC: policy che combina SPF+DKIM

## Configurazione

- Server comune: Postfix — config in /etc/postfix/main.cf
- Vedere config: cat /etc/postfix/main.cf | grep -v '#' | sed -r '/^\s*$/d'

## Vulnerabilità comuni

- Open Relay (mynetworks=0.0.0.0/0) — chiunque nel mondo può inviare email dal server
- VRFY/EXPN abilitati — enumerazione utenti validi sul server
- Dati in chiaro — credenziali intercettabili senza STARTTLS
- Mancanza SPF/DKIM/DMARC — email spoofing facilissimo (phishing)
- Versioni obsolete di Postfix/Sendmail con exploit noti

## Enumerazione & Comandi

### SCAN

```bash
sudo nmap -sV -sC -p25 <IP>                         # Scan SMTP base
sudo nmap -p25 --script smtp-open-relay -v <IP>      # Verifica open relay
```

### CONNESSIONE MANUALE (telnet)

```bash
telnet <IP> 25                                       # Connessione diretta
  > EHLO mail1                                       # Inizia sessione (mostra funzionalità)
  > VRFY admin                                       # Verifica se utente esiste (code 252 = ambiguo)
  > EXPN admin                                       # Espandi mailing list
  > MAIL FROM: <test@test.com>                       # Imposta mittente
  > RCPT TO: <admin@target.com>                      # Imposta destinatario
  > DATA                                             # Inizia corpo email (termina con '.')
  > RSET                                             # Annulla trasmissione (mantieni connessione)
  > QUIT                                             # Chiudi sessione
```

### ENUMERAZIONE UTENTI (Metasploit)

```bash
msfconsole > search smtp_enum > use 0 > set RHOSTS <IP> > set USER_FILE wordlist.txt > run
```

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **nmap**
- **theHarvester**
