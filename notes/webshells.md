# WebShells

## Dove trovarle su Kali

Le webshell di default su Kali Linux sono in:

```bash
tree /usr/share/webshells/
```

```
/usr/share/webshells/
├── asp
│   ├── cmd-asp-5.1.asp
│   └── cmdasp.asp
├── aspx
│   └── cmdasp.aspx
├── cfm
│   └── cfexec.cfm
├── jsp
│   ├── cmdjsp.jsp
│   └── jsp-reverse.jsp
├── perl
│   ├── perlcmd.cgi
│   └── perl-reverse-shell.pl
└── php
    ├── findsock.c
    ├── php-findsock-shell.php
    ├── php-reverse-shell.php
    ├── qsd-php-backdoor.php
    └── simple-backdoor.php
```

> Altre webshell: laudanum in `/usr/share/laudanum/`, e con seclists
> installato (`install seclists`) anche in `/usr/share/seclists/Web-Shells/`.

## Uso rapido

| Target | WebShell | Note |
|--------|----------|------|
| Apache/Nginx + PHP | `simple-backdoor.php` | `?cmd=id` per RCE |
| Apache + PHP | `php-reverse-shell.php` | Reverse shell, editare `$ip`/`$port` |
| IIS (Windows) | `cmdasp.aspx` | ASP.NET, `cmd.exe` |
| IIS legacy | `cmdasp.asp` | Classic ASP |
| Tomcat (Java) | `cmdjsp.jsp` | JSP, spesso da uploadare come `.war` |
| CGI/Perl | `perlcmd.cgi` | Richiede exec su cgi-bin |

## Upload bypass — trucchi rapidi

- **Doppia estensione**: `shell.php.gif`, `shell.php.jpg`
- **Magic bytes**: prepend `GIF89a;` al payload per passare i check sul content-type
- **Case**: `shell.pHP`, `shell.PhP3`, `shell.phtml`
- **Null byte** (vecchi server): `shell.php%00.gif`
- **Content-Type**: cambia l'header in `image/gif` durante l'upload

Dalla console SeaLion: pagina **Delivery → WebShell to RCE** genera e scarica
webshell pronte (con magic bytes opzionali) con LHOST/LPORT già compilati.
