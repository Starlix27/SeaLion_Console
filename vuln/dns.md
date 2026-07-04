# DNS — Domain Name System
**Porte:** 53 (TCP/UDP)  
**Categoria:** DNS & Ricognizione

Sistema per la risoluzione dei nomi di dominio in indirizzi IP.
Distribuito globalmente, non ha un database centrale. Ogni server ha un ruolo:

  Root Server (13 nel mondo) → Authoritative NS → Caching/Forwarding → Resolver locale

Record DNS: A (IPv4), AAAA (IPv6), MX (mail), NS (nameserver), TXT (verifica/SPF/DKIM),
            CNAME (alias), PTR (reverse), SOA (info zona).

Zona DNS ≠ Record DNS: la zona è il 'contenitore' (es. hackthebox.com) con tutti i record.
Il record è la singola riga (es. A → 142.250.184.206). Le zone hanno un SOA, i record no.

DNS viaggia in chiaro per default. Soluzioni: DoT (DNS over TLS), DoH (DNS over HTTPS), DNSCrypt.
Il browser cerca prima in /etc/hosts, poi contatta i DNS server.

## Configurazione

- Server comune: BIND9 — config in named.conf (diviso in opzioni + zone)
- File locali: named.conf.local, named.conf.options, named.conf.log
- Vedere zone: cat /etc/bind/named.conf.local
- Zone file: cat /etc/bind/db.domain.com (descrive una zona completa, necessita SOA + NS)
- Reverse zone: cat /etc/bind/db.10.129.14 (record PTR per IP→dominio)
- Se zona mancante/corrotta il server risponde SERVFAIL

## Vulnerabilità comuni

- Zone Transfer (AXFR) aperto — scarichi l'intera zona DNS con tutti i sottodomini
- allow-recursion aperto a tutti — DNS amplification attack (DDoS reflection)
- allow-query senza restrizioni — informazioni esposte a chiunque
- DNS in chiaro — query intercettabili senza DoT/DoH (chiunque in rete vede i siti visitati)
- Subdomain takeover — sottodomini che puntano a risorse abbandonate (es. vecchio S3 bucket)
- DNS cache poisoning — reindirizzamento a siti malevoli

## Enumerazione & Comandi

### QUERY MANUALI CON dig

```bash
dig domain.com                                       # Record A (default)
dig domain.com A                                     # IPv4
dig domain.com AAAA                                  # IPv6
dig domain.com MX                                    # Mail servers
dig domain.com NS                                    # Name servers autoritativi
dig domain.com TXT                                   # Record TXT (SPF, DKIM, verifiche)
dig domain.com SOA                                   # Start of Authority (admin email, refresh)
dig domain.com ANY                                   # Tutti i record (spesso ignorato per RFC 8482)
dig @1.1.1.1 domain.com                              # Query a DNS specifico (Cloudflare)
dig +trace domain.com                                # Percorso risoluzione completo (root→TLD→auth)
dig -x 192.168.1.1                                   # Reverse lookup (IP→dominio)
dig +short domain.com                                # Solo la risposta, nient'altro
dig +noall +answer domain.com                        # Solo la sezione 'answer'
dig CH TXT version.bind @<DNS_SERVER>                # Versione server DNS
```

### ZONE TRANSFER

```bash
dig axfr @<DNS_SERVER> <dominio>                     # Full zone transfer (se permesso)
```

### BRUTE FORCE SOTTODOMINI

```bash
# Manuale con bash + SecLists:
for sub in $(cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.<dominio> @<IP> | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```

```bash
# Con dnsenum (automatico: AXFR + brute force + reverse + whois):
dnsenum --dnsserver <IP> --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt <dominio>
```

```bash
# Con gobuster (VHost fuzzing — trova virtual host nascosti):
gobuster vhost -u http://<dominio> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

### FONTI PASSIVE (OSINT)

```bash
curl -s 'https://crt.sh/?q=<dominio>&output=json' | jq -r '.[].name_value' | sort -u  # Certificati SSL
# subdomainfinder.c99.nl — trova sottodomini da fonti pubbliche
```

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **nmap**
- **dnsenum**
- **gobuster**
- **theHarvester**
- **recon-ng**
- **whois**
- **seclists**
