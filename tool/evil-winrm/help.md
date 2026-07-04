# Evil-WinRM — Shell WinRM per Pentesting

**Evil-WinRM** è una shell interattiva per connettersi a macchine Windows via WinRM (porte 5985/5986). Permette upload/download file, caricamento script PowerShell e moduli .NET.

---

## A cosa serve?

- **Shell remota:** Accesso interattivo a Windows via WinRM
- **Upload/Download:** Trasferimento file
- **PowerShell:** Caricamento ed esecuzione script .ps1
- **Pass-the-Hash:** Supporta autenticazione con hash NTLM

---

## Come usarlo

### Connessione con password

```bash
evil-winrm -i 10.129.201.248 -u 'Administrator' -p 'P455w0rD!'
```

### Connessione con hash NTLM

```bash
evil-winrm -i 10.129.201.248 -u 'Administrator' -H 'HASH_NTLM'
```

### Upload di un file

```bash
upload /path/locale/file.exe C:\Users\Admin\file.exe
```

### Comandi utili una volta dentro

```powershell
Get-LocalUser
Get-LocalGroup
Get-Process
```

> Fonte: https://github.com/Hackplayers/evil-winrm
