# SNMP — Simple Network Management Protocol
**Porte:** 161/UDP (query), 162/UDP (trap)  
**Categoria:** Monitoraggio Rete

Protocollo per monitorare e gestire dispositivi di rete (router, switch, server, stampanti).

Componenti: SNMP (trasporto) + MIB (dizionario dati del dispositivo) + OID (coordinate univoche per ogni dato).
Ogni OID è una catena di numeri (es. .1.3.6.1.2.1.1.1.0 = nome sistema).
Più la catena è lunga, più l'info è specifica.

Versioni:
  SNMPv1: nessuna crittografia né auth reale. Tutto intercettabile.
  SNMPv2c: introduce la Community String (password in chiaro). La più diffusa.
  SNMPv3: username + password + crittografia. Sicura ma complessa da configurare.

Trap (porta 162): notifiche automatiche dal dispositivo senza richiesta.

## Configurazione

- Config: /etc/snmp/snmpd.conf
- Vedere config: cat /etc/snmp/snmpd.conf | grep -v '#' | sed -r '/^\s*$/d'

## Vulnerabilità comuni

- Community string di default (public/private) — accesso totale ai dati del dispositivo
- rwuser noauth — lettura/scrittura su tutto l'albero OID senza autenticazione
- rwcommunity aperta — modifica OID tree (config dispositivo) senza limiti
- SNMPv1/v2c in chiaro — community string intercettabile con uno sniffer
- Esposizione info: processi in esecuzione, software installati, utenti, config di rete completa

## Enumerazione & Comandi

### BRUTE FORCE COMMUNITY STRING

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>
```

### ESTRAZIONE DATI (una volta trovata la community string)

```bash
snmpwalk -v2c -c public <IP>                          # Tutti gli OID (lento, uno per uno)
braa public@<IP>:.1.3.6.*                             # Scan parallelo (MOLTO più veloce)
braa <community>@<IP>:.1.3.6.*                        # Con community personalizzata
```

### NMAP

```bash
sudo nmap -sU -p161 --script snmp-info <IP>           # Info SNMP base
```

## Tool consigliati

*Installa con `use <tool>` + `install`*

- **nmap**
- **onesixtyone**
- **braa**
- **seclists**
