from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys


_SECLISTS_BASE = "/usr/share/seclists"

_SCOPE_MENU = [
    ("dir", "Directory / file"),
    ("sub", "Sottodomini"),
    ("vhost", "Virtual host (vhost)"),
    ("param", "Parametri (GET/POST)"),
    ("user", "Username"),
    ("pass", "Password"),
    ("api", "API endpoint"),
]

_TECH_MENU = [
    ("php", "PHP", [".php", ".phtml"]),
    ("asp", "ASP / ASPX", [".asp", ".aspx"]),
    ("java", "Java / JSP", [".jsp", ".do", ".action"]),
    ("python", "Python (Django/Flask)", [".py"]),
    ("node", "Node.js", [".js", ".json"]),
    ("wp", "WordPress", [".php"]),
    ("joomla", "Joomla", [".php"]),
    ("generic", "Non so / generico", []),
]

_INTENSITY_DIR = [
    ("fast", "Veloce", "~5k parole", "⚡ primo giro"),
    ("medium", "Media", "~20k parole", "⚖️  buon compromesso"),
    ("full", "Completa", "~220k parole", "🔍 esaustiva"),
]

_INTENSITY_SUB = [
    ("fast", "Veloce", "~5k sottodomini", "⚡"),
    ("medium", "Media", "~20k sottodomini", "⚖️"),
    ("full", "Completa", "~110k sottodomini", "🔍"),
]

_INTENSITY_GENERIC = [
    ("fast", "Veloce", "wordlist piccola", "⚡"),
    ("medium", "Media", "wordlist media", "⚖️"),
    ("full", "Completa", "wordlist grande", "🔍"),
]

_API_TYPE_MENU = [
    ("rest", "REST generico"),
    ("graphql", "GraphQL"),
    ("swagger", "Swagger / OpenAPI"),
    ("unknown", "Non so"),
]

_PASS_CONTEXT_MENU = [
    ("web", "Login web generico"),
    ("service", "SSH / FTP / servizio di rete"),
    ("offline", "Hash da crackare (offline)"),
]

_LANG_MENU = [
    ("en", "Inglese (default)"),
    ("it", "Italiano"),
    ("es", "Spagnolo"),
    ("de", "Tedesco"),
    ("fr", "Francese"),
    ("mixed", "Misto / non importa"),
]

# Wordlist database: (relative path from seclists, approx size label)
_WL = {
    # Directory / files
    "dir_fast":    ("Discovery/Web-Content/common.txt", "4.7k"),
    "dir_medium":  ("Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt", "220k"),
    "dir_full":    ("Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt", "1.3M"),
    "dir_small":   ("Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt", "87k"),
    "raft_dirs":   ("Discovery/Web-Content/raft-medium-directories.txt", "30k"),
    "raft_files":  ("Discovery/Web-Content/raft-medium-files.txt", "17k"),
    "raft_dirs_l": ("Discovery/Web-Content/raft-large-directories.txt", "62k"),
    "raft_files_l":("Discovery/Web-Content/raft-large-files.txt", "37k"),
    "dir_2_3_small": ("Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt", "87k"),
    # Tech-specific
    "php_fuzz":    ("Discovery/Web-Content/Programming-Language-Specific/PHP.fuzz.txt", "274"),
    "asp_fuzz":    ("Discovery/Web-Content/Programming-Language-Specific/ASP.NET/CommonBackdoors-ASP.fuzz.txt", "120"),
    "java_fuzz":   ("Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt", "200"),
    "wp_content":  ("Discovery/Web-Content/CMS/wordpress.fuzz.txt", "1.2k"),
    "wp_plugins":  ("Discovery/Web-Content/CMS/wp-plugins.fuzz.txt", "13k"),
    "wp_themes":   ("Discovery/Web-Content/CMS/wp-themes.fuzz.txt", "500"),
    "joomla_fuzz": ("Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt", "1k"),
    # Subdomains
    "sub_fast":    ("Discovery/DNS/subdomains-top1million-5000.txt", "5k"),
    "sub_medium":  ("Discovery/DNS/subdomains-top1million-20000.txt", "20k"),
    "sub_full":    ("Discovery/DNS/subdomains-top1million-110000.txt", "110k"),
    "sub_names":   ("Discovery/DNS/namelist.txt", "1.9k"),
    "sub_bitquark": ("Discovery/DNS/bitquark-subdomains-top100000.txt", "100k"),
    "sub_fierce":  ("Discovery/DNS/fierce-hostlist.txt", "2.5k"),
    # Parameters
    "param_burp":  ("Discovery/Web-Content/burp-parameter-names.txt", "6.5k"),
    "param_top":   ("Discovery/Web-Content/api/api-endpoints.txt", "800"),
    # Usernames
    "user_names":  ("Usernames/Names/names.txt", "10k"),
    "user_top":    ("Usernames/top-usernames-shortlist.txt", "17"),
    "user_xato":   ("Usernames/xato-net-10-million-usernames.txt", "8.3M"),
    "user_cirt":   ("Usernames/cirt-default-usernames.txt", "827"),
    "user_mssql_default": ("Usernames/mssql-betterdefaultpasslist.txt", "110"),
    "user_service_default": ("Usernames/CommonAdminBase64.txt", "57"),
    "user_unix":   ("Usernames/unix_users.txt", "167"),
    "user_satanlist": ("Usernames/satanlist.txt", "87"),
    # Passwords — common credentials
    "pass_top10k": ("Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt", "10k"),
    "pass_top1m":  ("Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt", "1M"),
    "pass_rockyou": ("/usr/share/wordlists/rockyou.txt", "14M"),
    "pass_500":    ("Passwords/Common-Credentials/500-worst-passwords.txt", "500"),
    "pass_common": ("Passwords/Common-Credentials/common-passwords-win.txt", "815"),
    "pass_default_web": ("Passwords/Default-Credentials/default-passwords.txt", "1.2k"),
    "pass_10k_most_common": ("Passwords/Common-Credentials/10k-most-common.txt", "10k"),
    "pass_100k":   ("Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt", "100k"),
    # Passwords — default credentials
    "pass_tomcat": ("Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt", "79"),
    "pass_ftp_default": ("Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt", "52"),
    "pass_mssql_default": ("Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt", "60"),
    "pass_mysql_default": ("Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt", "15"),
    "pass_postgres_default": ("Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt", "16"),
    "pass_ssh_default": ("Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt", "40"),
    # Passwords — leaked databases
    "pass_darkweb_top1k": ("Passwords/Leaked-Databases/alleged-gmail-passwords.txt", "18k"),
    "pass_openwall": ("Passwords/Leaked-Databases/openwall.net-all.txt", "3.7k"),
    "pass_hak5":     ("Passwords/Leaked-Databases/hak5.txt", "2.4k"),
    # Passwords — WiFi / WPA
    "pass_wifi_probable": ("Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt", "4.8k"),
    # Language-specific passwords
    "pass_it":     ("Passwords/Common-Credentials/Language-Specific/Italian_Pwdb_common-password-list-top-150.txt", "150"),
    "pass_es":     ("Passwords/Common-Credentials/Language-Specific/Spanish_common-usernames-and-passwords.txt", "1k"),
    "pass_de":     ("Passwords/Common-Credentials/Language-Specific/German_common-password-list-top-10000.txt", "10k"),
    "pass_fr":     ("Passwords/Common-Credentials/Language-Specific/French-common-password-list-top-20000.txt", "20k"),
    # API
    "api_endpoints": ("Discovery/Web-Content/api/api-endpoints-res.txt", "2.2k"),
    "api_objects":   ("Discovery/Web-Content/api/objects.txt", "2.9k"),
    "api_common":    ("Discovery/Web-Content/common-api-endpoints-mazen160.txt", "174"),
    "api_graphql":   ("Discovery/Web-Content/graphql.txt", "80"),
}

_SECLISTS_GITHUB = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"

def _wl_link(key: str) -> str:
    p = _WL[key][0]
    if p.startswith("/"):
        if "rockyou" in p:
            return "https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases"
        return ""
    return f"{_SECLISTS_GITHUB}/{p}"


def _wl_path(key: str) -> str:
    p = _WL[key][0]
    if p.startswith("/"):
        if os.path.isfile(p):
            return p
        local = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.path.basename(p))
        if os.path.isfile(local):
            return local
        return p
    full = f"{_SECLISTS_BASE}/{p}"
    if os.path.isfile(full):
        return full
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.path.basename(p))
    if os.path.isfile(local):
        return local
    return full


def _wl_label(key: str) -> str:
    path, size = _WL[key]
    name = path.rsplit("/", 1)[-1]
    if size:
        return f"{name}  ({size})"
    return name


def _wf_ask(prompt: str, options: list[tuple], default: int = 1) -> int:
    print(f"\n  \033[1m{prompt}\033[0m\n")
    for i, opt in enumerate(options, 1):
        label = opt[1] if len(opt) >= 2 else opt[0]
        extra = ""
        if len(opt) >= 4:
            extra = f"  {opt[2]:20s} {opt[3]}"
        elif len(opt) >= 3:
            extra = f"  \033[90m{opt[2]}\033[0m"
        print(f"    [{i}] {label}{extra}")
    print()
    while True:
        try:
            raw = input(f"  Scelta [{default}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return -1
        if not raw:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw)
        print(f"  Inserisci un numero da 1 a {len(options)}.")


def _wf_ask_text(prompt: str, default: str = "") -> str:
    try:
        raw = input(f"  {prompt}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return raw or default


def _parse_target(url: str) -> dict:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    port = parsed.port
    path = parsed.path or "/"
    domain = host
    base = f"{scheme}://{parsed.netloc or host}"
    if path and path != "/":
        base_with_path = f"{base}{path.rstrip('/')}"
    else:
        base_with_path = base
    return {
        "url": url, "scheme": scheme, "host": host, "port": port,
        "path": path, "domain": domain, "base": base,
        "base_path": base_with_path,
    }


def _build_dir_result(target: dict, tech_key: str, tech_exts: list[str], intensity: str) -> dict:
    wordlists = []
    extras = []

    if intensity == "fast":
        wordlists.append("dir_fast")
    elif intensity == "medium":
        wordlists.append("dir_medium")
        wordlists.append("dir_fast")
    else:
        wordlists.append("dir_full")
        wordlists.append("dir_medium")

    wordlists.append("raft_files")

    if tech_key == "php":
        extras.append("php_fuzz")
        tech_exts = [".php", ".phtml", ".txt", ".bak", ".php.bak"]
    elif tech_key == "asp":
        extras.append("asp_fuzz")
        tech_exts = [".asp", ".aspx", ".txt", ".bak", ".config"]
    elif tech_key == "java":
        extras.append("java_fuzz")
        tech_exts = [".jsp", ".do", ".action", ".xml", ".txt"]
    elif tech_key == "python":
        tech_exts = [".py", ".txt", ".json", ".yaml"]
    elif tech_key == "node":
        tech_exts = [".js", ".json", ".txt", ".map"]
    elif tech_key == "wp":
        extras.extend(["wp_content", "wp_plugins", "wp_themes"])
        tech_exts = [".php", ".txt", ".bak"]
    elif tech_key == "joomla":
        extras.append("joomla_fuzz")
        tech_exts = [".php", ".txt", ".bak"]
    else:
        tech_exts = [".txt", ".bak", ".html"]

    ext_str = ",".join(e.lstrip(".") for e in tech_exts)
    ext_dot = ",".join(tech_exts)
    main_wl = wordlists[0]
    url = target["base_path"]

    commands = []
    commands.append(("gobuster", f"gobuster dir -u {url} -w {_wl_path(main_wl)} -x {ext_str} -t 50 --no-error"))
    commands.append(("ffuf", f"ffuf -u {url}/FUZZ -w {_wl_path(main_wl)} -e {ext_dot} -t 50 -c -ac"))
    commands.append(("dirb", f"dirb {url} {_wl_path(main_wl)} -X {ext_dot}"))
    commands.append(("feroxbuster", f"feroxbuster -u {url} -w {_wl_path(main_wl)} -x {ext_str} -t 50 -C 404 --auto-tune"))
    commands.append(("wfuzz", f"wfuzz -u {url}/FUZZ -w {_wl_path(main_wl)} --hc 404 -t 50"))
    commands.append(("dirsearch", f"dirsearch -u {url} -w {_wl_path(main_wl)} -e {ext_str} -t 50 --exclude-status 404"))

    return {"wordlists": wordlists + extras, "extensions": ext_dot, "commands": commands}


def _build_sub_result(target: dict, intensity: str) -> dict:
    domain = target["domain"]
    wordlists = []

    if intensity == "fast":
        wordlists = ["sub_fast", "sub_names"]
    elif intensity == "medium":
        wordlists = ["sub_medium", "sub_names", "sub_bitquark"]
    else:
        wordlists = ["sub_full", "sub_bitquark", "sub_names"]

    main_wl = wordlists[0]
    commands = []
    commands.append(("gobuster", f"gobuster dns -d {domain} -w {_wl_path(main_wl)} -t 50"))
    commands.append(("ffuf", f"ffuf -u http://FUZZ.{domain} -w {_wl_path(main_wl)} -c -ac"))
    commands.append(("wfuzz", f"wfuzz -u http://FUZZ.{domain} -w {_wl_path(main_wl)} --hc 404 -t 50"))
    commands.append(("amass", f"amass enum -d {domain} -w {_wl_path(main_wl)}"))
    commands.append(("dnsenum", f"dnsenum --dnsserver 8.8.8.8 -f {_wl_path(main_wl)} {domain}"))

    return {"wordlists": wordlists, "commands": commands}


def _build_vhost_result(target: dict, intensity: str) -> dict:
    domain = target["domain"]
    base = target["base"]
    wordlists = []

    if intensity == "fast":
        wordlists = ["sub_fast", "sub_names"]
    elif intensity == "medium":
        wordlists = ["sub_medium", "sub_names"]
    else:
        wordlists = ["sub_full", "sub_bitquark"]

    main_wl = wordlists[0]
    commands = []
    commands.append(("gobuster", f"gobuster vhost -u {base} -w {_wl_path(main_wl)} --append-domain -t 50"))
    commands.append(("ffuf", f'ffuf -u {base} -H "Host: FUZZ.{domain}" -w {_wl_path(main_wl)} -c -ac'))
    commands.append(("wfuzz", f'wfuzz -u {base} -H "Host: FUZZ.{domain}" -w {_wl_path(main_wl)} --hc 404 -t 50'))

    return {"wordlists": wordlists, "commands": commands}


def _build_param_result(target: dict, intensity: str) -> dict:
    url = target["base_path"]
    wordlists = ["param_burp", "param_top"]

    main_wl = wordlists[0]
    commands = []
    commands.append(("ffuf GET", f'ffuf -u "{url}?FUZZ=test" -w {_wl_path(main_wl)} -c -ac'))
    commands.append(("ffuf POST", f'ffuf -u {url} -X POST -d "FUZZ=test" -w {_wl_path(main_wl)} -c -ac'))
    commands.append(("wfuzz GET", f'wfuzz -u "{url}?FUZZ=test" -w {_wl_path(main_wl)} --hc 404 -t 50'))
    commands.append(("arjun", f"arjun -u {url} -w {_wl_path(main_wl)}"))

    return {"wordlists": wordlists, "commands": commands}


def _build_user_result(target: dict, intensity: str) -> dict:
    wordlists = []
    if intensity == "fast":
        wordlists = ["user_top", "user_names"]
    elif intensity == "medium":
        wordlists = ["user_names", "user_top"]
    else:
        wordlists = ["user_xato", "user_names"]

    return {"wordlists": wordlists, "commands": []}


def _build_pass_result(target: dict, context: str, lang: str, username: str,
                       intensity: str, user_wl_key: str | None = None) -> dict:
    url = target["base_path"]
    wordlists = []

    if intensity == "fast":
        wordlists = ["pass_500", "pass_default_web"]
    elif intensity == "medium":
        wordlists = ["pass_top10k", "pass_common"]
    else:
        wordlists = ["pass_top1m", "pass_rockyou"]

    lang_wl = {"it": "pass_it", "es": "pass_es", "de": "pass_de", "fr": "pass_fr"}
    if lang in lang_wl:
        wordlists.append(lang_wl[lang])

    user = username or "admin"
    user_flag = f"-L {_wl_path(user_wl_key)}" if user_wl_key else f"-l {user}"
    user_flag_med = f"-U {_wl_path(user_wl_key)}" if user_wl_key else f"-u {user}"
    user_flag_cme = f"-u {_wl_path(user_wl_key)}" if user_wl_key else f"-u {user}"
    main_wl = wordlists[0]
    commands = []
    user_wls = [user_wl_key] if user_wl_key else []

    if context == "web":
        commands.append(("hydra", f'hydra {user_flag} -P {_wl_path(main_wl)} {target["host"]} http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"'))
        commands.append(("ffuf", f"ffuf -u {url} -X POST -d \"user={user}&pass=FUZZ\" -w {_wl_path(main_wl)} -fc 401,403 -c"))
        commands.append(("wfuzz", f"wfuzz -u {url} -d \"user={user}&pass=FUZZ\" -w {_wl_path(main_wl)} --hc 401,403 -t 50"))
        commands.append(("medusa", f"medusa -h {target['host']} {user_flag_med} -P {_wl_path(main_wl)} -M http -m DIR:{target['path']}"))
    elif context == "service":
        commands.append(("hydra SSH", f"hydra {user_flag} -P {_wl_path(main_wl)} {target['host']} ssh -t 4"))
        commands.append(("hydra FTP", f"hydra {user_flag} -P {_wl_path(main_wl)} {target['host']} ftp -t 4"))
        commands.append(("hydra RDP", f"hydra {user_flag} -P {_wl_path(main_wl)} {target['host']} rdp -t 4"))
        commands.append(("medusa SSH", f"medusa -h {target['host']} {user_flag_med} -P {_wl_path(main_wl)} -M ssh -t 4"))
        commands.append(("ncrack SSH", f"ncrack {'-U ' + _wl_path(user_wl_key) if user_wl_key else '-u ' + user} -P {_wl_path(main_wl)} {target['host']}:22"))
        commands.append(("crackmapexec SMB", f"crackmapexec smb {target['host']} {user_flag_cme} -p {_wl_path(main_wl)}"))
    else:
        commands.append(("john", f"john --wordlist={_wl_path(main_wl)} hash.txt"))
        commands.append(("hashcat", f"hashcat -m 0 hash.txt {_wl_path(main_wl)}"))
        if lang in lang_wl:
            commands.append(("john lang", f"john --wordlist={_wl_path(lang_wl[lang])} hash.txt"))
            commands.append(("hashcat lang", f"hashcat -m 0 hash.txt {_wl_path(lang_wl[lang])}"))

    result = {"wordlists": wordlists, "commands": commands}
    if user_wls:
        result["user_wordlists"] = user_wls
    return result


def _build_api_result(target: dict, api_type: str, intensity: str) -> dict:
    url = target["base_path"]
    wordlists = []

    if api_type == "graphql":
        wordlists = ["api_graphql", "api_common"]
    else:
        wordlists = ["api_endpoints", "api_objects", "api_common"]

    main_wl = wordlists[0]
    commands = []
    commands.append(("ffuf", f"ffuf -u {url}/FUZZ -w {_wl_path(main_wl)} -t 50 -c -ac"))
    commands.append(("gobuster", f"gobuster dir -u {url} -w {_wl_path(main_wl)} -t 50 --no-error"))
    commands.append(("wfuzz", f"wfuzz -u {url}/FUZZ -w {_wl_path(main_wl)} --hc 404 -t 50"))
    commands.append(("feroxbuster", f"feroxbuster -u {url} -w {_wl_path(main_wl)} -t 50 --no-recursion -C 404 --auto-tune"))

    if api_type == "graphql":
        commands.append(("graphql introspection", f'curl -s -X POST {url} -H "Content-Type: application/json" -d \'{{"query":"{{__schema{{types{{name}}}}}}"}}\' | python3 -m json.tool'))
    elif api_type == "swagger":
        swagger_paths = ["/swagger.json", "/openapi.json", "/api-docs", "/swagger/v1/swagger.json", "/v2/api-docs"]
        for sp in swagger_paths:
            commands.append(("curl swagger", f"curl -s {target['base']}{sp}"))

    return {"wordlists": wordlists, "commands": commands}


def _print_wordfind_result(result: dict) -> None:
    print(f"\n  \033[92m┌─ Risultato ────────────────────────────────┐\033[0m\n")

    if result.get("wordlists"):
        print("  \033[1mWordlist consigliate:\033[0m")
        for i, key in enumerate(result["wordlists"], 1):
            print(f"    [{i}] {_wl_label(key)}")
            link = _wl_link(key)
            if link:
                print(f"        \033[90m↳ {link}\033[0m")
        print()

    if result.get("extensions"):
        print(f"  \033[1mEstensioni:\033[0m {result['extensions']}")
        print()

    if result.get("commands"):
        print("  \033[1mComandi pronti (copia-incolla):\033[0m\n")
        for tool_name, cmd in result["commands"]:
            print(f"    \033[96m# {tool_name}\033[0m")
            if len(cmd) > 90:
                parts = cmd.split(" -", 1)
                if len(parts) == 2:
                    print(f"    {parts[0]} \\")
                    flags = (" -" + parts[1]).split(" -")
                    for j, flag in enumerate(flags):
                        flag = flag.strip()
                        if flag:
                            suffix = " \\" if j < len(flags) - 1 else ""
                            print(f"      -{flag}{suffix}")
                else:
                    print(f"    {cmd}")
            else:
                print(f"    {cmd}")
            print()

    print(f"  \033[92m└────────────────────────────────────────────┘\033[0m")


def _wf_ask_multi(prompt: str, options: list[tuple]) -> list[int]:
    print(f"\n  \033[1m{prompt}\033[0m\n")
    for i, opt in enumerate(options, 1):
        label = opt[1] if len(opt) >= 2 else opt[0]
        print(f"    [{i}] {label}")
    print(f"\n  Scrivi i numeri separati da spazi (es. 1 2 4), * per tutti, q per uscire\n")
    while True:
        try:
            raw = input("  Scelta: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return []
        if raw.lower() in {"q", "quit", "exit"}:
            return []
        if raw in {"*", "all", "tutto"}:
            return list(range(1, len(options) + 1))
        parts = raw.replace(",", " ").split()
        if all(p.isdigit() and 1 <= int(p) <= len(options) for p in parts) and parts:
            seen = set()
            result = []
            for p in parts:
                n = int(p)
                if n not in seen:
                    seen.add(n)
                    result.append(n)
            return result
        print(f"  Inserisci numeri da 1 a {len(options)} separati da spazi.")




def _print_cmd(cmd: str) -> None:
    if len(cmd) > 90:
        parts = cmd.split(" -", 1)
        if len(parts) == 2:
            print(f"    {parts[0]} \\")
            flags = (" -" + parts[1]).split(" -")
            for j, flag in enumerate(flags):
                flag = flag.strip()
                if flag:
                    suffix = " \\" if j < len(flags) - 1 else ""
                    print(f"      -{flag}{suffix}")
        else:
            print(f"    {cmd}")
    else:
        print(f"    {cmd}")


def _launch_commands(commands: list[tuple[str, str]]) -> None:
    in_tmux = bool(os.environ.get("TMUX"))
    if in_tmux:
        for i, (label, cmd) in enumerate(commands):
            titled_cmd = f"printf '\\033]0;{label}\\007'; {cmd}"
            if i == 0:
                subprocess.run(
                    ["tmux", "send-keys", titled_cmd, "Enter"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.run(
                    ["tmux", "split-window", "-v", "-l", "30%", titled_cmd],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            subprocess.run(
                ["tmux", "select-pane", "-T", label],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            print(f"    \033[92m✓\033[0m {label}")
        subprocess.run(
            ["tmux", "select-layout", "tiled"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        print(f"\n  Avviati \033[1m{len(commands)}\033[0m comandi in pane tmux")
    else:
        from shutil import which
        launched = False
        is_wsl = bool(os.environ.get("WSL_DISTRO_NAME") or os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"))
        wt_path = which("wt.exe") if is_wsl else None
        if wt_path:
            for label, cmd in commands:
                shell_cmd = "printf '\033]0;" + label + "\007'; " + cmd + '; echo; echo "\\033[92m[✓] Completato. INVIO per chiudere.\\033[0m"; read _'
                subprocess.Popen(
                    [wt_path, "new-tab", "--title", label, "wsl.exe", "-e", "sh", "-c", shell_cmd],
                    start_new_session=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                print(f"    \033[92m✓\033[0m {label}")
            launched = True
        if not launched:
            for term in ("x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "xterm"):
                term_path = which(term)
                if not term_path:
                    continue
                for label, cmd in commands:
                    shell_cmd = "printf '\033]0;" + label + "\007'; " + cmd + '; echo; echo "\\033[92m[✓] Completato. INVIO per chiudere.\\033[0m"; read _'
                    if term == "gnome-terminal":
                        subprocess.Popen(
                            [term_path, "--title", label, "--", "sh", "-c", shell_cmd],
                            start_new_session=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                    elif term == "konsole":
                        subprocess.Popen(
                            [term_path, "--title", label, "-e", "sh", "-c", shell_cmd],
                            start_new_session=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                    else:
                        subprocess.Popen(
                            [term_path, "-e", "sh", "-c", shell_cmd],
                            start_new_session=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                    print(f"    \033[92m✓\033[0m {label}")
                launched = True
                break
        if launched:
            print(f"\n  Avviati \033[1m{len(commands)}\033[0m comandi in finestre separate")
        else:
            print("\n  \033[91mNessun terminale trovato (tmux, wt.exe, gnome-terminal, ...).\033[0m")
            print("  Copia i comandi manualmente dall'elenco sopra.")


def cmd_wordfind_full(args: argparse.Namespace) -> int:
    url = getattr(args, "url", None) or ""
    if not url:
        try:
            url = input("\n  Target URL: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
    if not url:
        print("Specifica un URL target.", file=sys.stderr)
        return 1
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    target = _parse_target(url)

    print(f"\n  \033[92m┌─ wordfind --full ──────────────────────────┐\033[0m")
    print(f"\n  Target: \033[94m{url}\033[0m")

    choices = _wf_ask_multi("Quali scan vuoi includere?", _SCOPE_MENU)
    if not choices:
        return 0

    int_choice = _wf_ask("Intensità?", _INTENSITY_GENERIC, default=2)
    if int_choice == -1:
        return 0
    intensity = _INTENSITY_GENERIC[int_choice - 1][0]

    sections: list[tuple[str, dict]] = []
    for idx in choices:
        scope_key, scope_label = _SCOPE_MENU[idx - 1]
        if scope_key == "dir":
            result = _build_dir_result(target, "generic", [], intensity)
        elif scope_key == "sub":
            result = _build_sub_result(target, intensity)
        elif scope_key == "vhost":
            result = _build_vhost_result(target, intensity)
        elif scope_key == "param":
            result = _build_param_result(target, intensity)
        elif scope_key == "user":
            result = _build_user_result(target, intensity)
        elif scope_key == "pass":
            ctx_choice = _wf_ask("Contesto password?", _PASS_CONTEXT_MENU)
            if ctx_choice == -1:
                return 0
            context = _PASS_CONTEXT_MENU[ctx_choice - 1][0]
            result = _build_pass_result(target, context, "en", "admin", intensity)
        elif scope_key == "api":
            result = _build_api_result(target, "rest", intensity)
        else:
            continue
        sections.append((scope_label, result))

    to_launch: list[tuple[str, str]] = []

    for scope_label, result in sections:
        cmds = result.get("commands", [])
        if not cmds:
            continue

        print(f"\n  \033[93;1m══ {scope_label} ══\033[0m\n")
        for i, (tool_name, cmd) in enumerate(cmds, 1):
            print(f"    [{i}] \033[96m{tool_name}\033[0m")
            _print_cmd(cmd)
            print()

        print(f"    [0] Salta questa categoria\n")
        while True:
            try:
                raw = input(f"  Quale tool per {scope_label}? [1]: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return 0
            if not raw:
                raw = "1"
            if raw == "0":
                break
            if raw.isdigit() and 1 <= int(raw) <= len(cmds):
                pick = int(raw) - 1
                tool_name, cmd = cmds[pick]
                to_launch.append((f"{scope_label} · {tool_name}", cmd))
                print(f"  \033[92m✓\033[0m {tool_name}")
                break
            print(f"  Inserisci un numero da 0 a {len(cmds)}.")

    if not to_launch:
        print("\n  Nessun comando selezionato.")
        return 0

    print(f"\n  \033[1mRiepilogo — {len(to_launch)} comandi da lanciare:\033[0m\n")
    for i, (label, cmd) in enumerate(to_launch, 1):
        print(f"    \033[96m{i}. {label}\033[0m")
        _print_cmd(cmd)
        print()

    print(f"  \033[92m└────────────────────────────────────────────┘\033[0m\n")

    try:
        raw = input("  Avvia le shell? [S/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return 0
    if raw in {"n", "no"}:
        return 0

    print()
    _launch_commands(to_launch)
    return 0


def cmd_wordfind(args: argparse.Namespace, state=None) -> int:
    if getattr(args, "full", False):
        return cmd_wordfind_full(args)

    url = getattr(args, "url", None) or ""

    if url in {"help", "-h", "--help", "h"}:
        print("""
  \033[95mwordfind\033[0m — Wizard wordlist per fuzzing e bruteforce

    wordfind [url]           Wizard guidato: scegli scope, tecnologia,
                             intensità e ottieni comandi pronti

    wordfind --full [url]    Seleziona più scope insieme (es. 1 2 4 5),
                             scegli l'intensità una volta, vedi i comandi
                             e lancia quelli che vuoi in shell separate

  \033[1mScope disponibili:\033[0m

    [1] Directory / file     gobuster, ffuf, dirb, feroxbuster, wfuzz, dirsearch
    [2] Sottodomini          gobuster dns, ffuf vhost, amass, dnsenum
    [3] Virtual host         gobuster vhost, ffuf Host header, wfuzz
    [4] Parametri GET/POST   ffuf, wfuzz, arjun
    [5] Username             wordlist username (top, names, xato)
    [6] Password             hydra, ffuf, medusa, hashcat, john
    [7] API endpoint         ffuf, gobuster, wfuzz, feroxbuster

  \033[1mIntensità:\033[0m

    fast      ⚡  Wordlist piccole (~5k), scan veloce
    medium    ⚖️   Wordlist medie (~20k), buon compromesso
    full      🔍  Wordlist grandi (~220k), esaustivo

  \033[1mEsempi:\033[0m

    wordfind 10.10.11.42          Wizard singolo scope
    wordfind --full 10.10.11.42   Multi-scope (scrivi "1 2 3" o "*")
""")
        return 0

    if not url:
        try:
            url = input("\n  Target URL: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
    if not url:
        print("Specifica un URL target.", file=sys.stderr)
        return 1

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    target = _parse_target(url)

    print(f"\n  \033[92m┌─ wordfind ─────────────────────────────────┐\033[0m")
    print(f"\n  Target: \033[94m{url}\033[0m")

    # Step 1: Scope
    choice = _wf_ask("[1] Cosa stai cercando?", _SCOPE_MENU)
    if choice == -1:
        return 0
    scope_key = _SCOPE_MENU[choice - 1][0]

    if scope_key == "dir":
        # Step 2: Technology
        tech_choice = _wf_ask("[2] Tecnologia?", _TECH_MENU, default=8)
        if tech_choice == -1:
            return 0
        tech_key = _TECH_MENU[tech_choice - 1][0]
        tech_exts = _TECH_MENU[tech_choice - 1][2]

        # Step 3: Intensity
        int_choice = _wf_ask("[3] Intensità?", _INTENSITY_DIR, default=2)
        if int_choice == -1:
            return 0
        intensity = _INTENSITY_DIR[int_choice - 1][0]

        result = _build_dir_result(target, tech_key, tech_exts, intensity)

    elif scope_key == "sub":
        int_choice = _wf_ask("[2] Intensità?", _INTENSITY_SUB, default=2)
        if int_choice == -1:
            return 0
        intensity = _INTENSITY_SUB[int_choice - 1][0]

        result = _build_sub_result(target, intensity)

    elif scope_key == "vhost":
        int_choice = _wf_ask("[2] Intensità?", _INTENSITY_GENERIC, default=2)
        if int_choice == -1:
            return 0
        intensity = _INTENSITY_GENERIC[int_choice - 1][0]

        result = _build_vhost_result(target, intensity)

    elif scope_key == "param":
        int_choice = _wf_ask("[2] Intensità?", _INTENSITY_GENERIC, default=2)
        if int_choice == -1:
            return 0
        intensity = _INTENSITY_GENERIC[int_choice - 1][0]

        result = _build_param_result(target, intensity)

    elif scope_key == "user":
        int_choice = _wf_ask("[2] Intensità?", _INTENSITY_GENERIC, default=2)
        if int_choice == -1:
            return 0
        intensity = _INTENSITY_GENERIC[int_choice - 1][0]

        result = _build_user_result(target, intensity)

    elif scope_key == "pass":
        # Step 2: Context
        ctx_choice = _wf_ask("[2] Contesto?", _PASS_CONTEXT_MENU)
        if ctx_choice == -1:
            return 0
        context = _PASS_CONTEXT_MENU[ctx_choice - 1][0]

        # If service context, ask protocol + parse IP:PORT
        svc_proto = None
        svc_port = None
        if context == "service":
            svc_menu = [(s[0], f"{s[1]}  (porta {s[2]})") for s in _PF_SERVICE_MENU]
            svc_choice = _wf_ask("[2b] Protocollo?", svc_menu)
            if svc_choice == -1:
                return 0
            svc_entry = _PF_SERVICE_MENU[svc_choice - 1]
            svc_proto = svc_entry[0]
            svc_default_port = svc_entry[2]

            # Use port from URL if already parsed
            if target["port"]:
                svc_port = str(target["port"])
            else:
                print()
                port_input = _wf_ask_text(f"[2c] Porta? (invio = {svc_default_port})", default="")
                svc_port = port_input if port_input else svc_default_port

        # Step 3: Language
        lang_choice = _wf_ask("[3] Lingua / localizzazione?", _LANG_MENU)
        if lang_choice == -1:
            return 0
        lang = _LANG_MENU[lang_choice - 1][0]

        # Step 4: Username
        _USER_MODE_WF = [
            ("single", "Username singolo (lo scrivo io)"),
            ("wordlist", "Wordlist username (non conosco lo username)"),
        ]
        user_mode = _wf_ask("[4] Username?", _USER_MODE_WF, default=2)
        if user_mode == -1:
            return 0

        username = "admin"
        user_wl_key = None
        if user_mode == 1:
            print()
            username = _wf_ask_text("[4b] Username (vuoto = admin)", default="admin")
        else:
            _USER_WL_WF = [
                ("user_top", "top-usernames-shortlist.txt  (17 — i più comuni)"),
                ("user_cirt", "cirt-default-usernames.txt  (827 — credenziali default)"),
                ("user_names", "names.txt  (10k — nomi comuni)"),
                ("user_unix", "unix_users.txt  (167 — utenti UNIX tipici)"),
                ("user_xato", "xato-net-10-million-usernames.txt  (8.3M — esaustiva)"),
            ]
            uwl = _wf_ask("[4b] Quale wordlist username?", _USER_WL_WF)
            if uwl == -1:
                return 0
            user_wl_key = _USER_WL_WF[uwl - 1][0]

        if context == "service" and svc_proto:
            _PF_PASS_WL_WF = [
                ("pass_500", "500-worst-passwords.txt  (500 — velocissimo)", "⚡"),
                ("pass_default_web", "default-passwords.txt  (1.2k — credenziali default)", "⚡"),
                ("pass_top10k", "xato-net-10-million-passwords-10000.txt  (10k)", "⚖️"),
                ("pass_10k_most_common", "10k-most-common.txt  (10k — alternativa)", "⚖️"),
                ("pass_100k", "xato-net-10-million-passwords-100000.txt  (100k)", "⚖️"),
                ("pass_top1m", "xato-net-10-million-passwords-1000000.txt  (1M)", "🔍"),
                ("pass_rockyou", "rockyou.txt  (14M — esaustiva)", "🔍"),
            ]
            proto_defs = {
                "ftp": ("pass_ftp_default", "ftp-betterdefaultpasslist.txt  (52 — default FTP)", "⭐"),
                "ssh": ("pass_ssh_default", "ssh-betterdefaultpasslist.txt  (40 — default SSH)", "⭐"),
                "mysql": ("pass_mysql_default", "mysql-betterdefaultpasslist.txt  (15 — default MySQL)", "⭐"),
                "mssql": ("pass_mssql_default", "mssql-betterdefaultpasslist.txt  (60 — default MSSQL)", "⭐"),
                "postgres": ("pass_postgres_default", "postgres-betterdefaultpasslist.txt  (16 — default Postgres)", "⭐"),
            }
            if svc_proto in proto_defs:
                _PF_PASS_WL_WF.insert(0, proto_defs[svc_proto])

            lang_wl_map = {"it": "pass_it", "es": "pass_es", "de": "pass_de", "fr": "pass_fr"}
            if lang in lang_wl_map:
                lkey = lang_wl_map[lang]
                _PF_PASS_WL_WF.append((lkey, f"{_WL[lkey][0].rsplit('/', 1)[-1]}  ({_WL[lkey][1]})", "🌐"))

            pw_ch = _wf_ask("[5] Wordlist password?", _PF_PASS_WL_WF, default=1)
            if pw_ch == -1:
                return 0
            pw_key = _PF_PASS_WL_WF[pw_ch - 1][0]
            wl_path = _wl_path(pw_key)

            result = _build_service_result(svc_proto, svc_port, target["host"],
                                           username, "custom", user_wl_key=user_wl_key)
            for i, (name, cmd) in enumerate(result["commands"]):
                for old in ["/usr/share/wordlists/rockyou.txt",
                            "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt"]:
                    cmd = cmd.replace(old, wl_path)
                result["commands"][i] = (name, cmd)
            result["wordlists"] = [pw_key]
        else:
            int_choice = _wf_ask("[5] Intensità?", _INTENSITY_GENERIC, default=2)
            if int_choice == -1:
                return 0
            intensity = _INTENSITY_GENERIC[int_choice - 1][0]
            result = _build_pass_result(target, context, lang, username, intensity,
                                        user_wl_key=user_wl_key)

    elif scope_key == "api":
        # Step 2: API type
        api_choice = _wf_ask("[2] Tipo di API?", _API_TYPE_MENU)
        if api_choice == -1:
            return 0
        api_type = _API_TYPE_MENU[api_choice - 1][0]

        # Step 3: Intensity
        int_choice = _wf_ask("[3] Intensità?", _INTENSITY_GENERIC, default=2)
        if int_choice == -1:
            return 0
        intensity = _INTENSITY_GENERIC[int_choice - 1][0]

        result = _build_api_result(target, api_type, intensity)

    else:
        print("Scopo non supportato.")
        return 1

    _print_wordfind_result(result)
    return 0


# ──────────────────────────────────────────────────────────────
# passfind — Wizard per password cracking
# ──────────────────────────────────────────────────────────────

_PF_SCOPE_MENU = [
    ("hash", "Hash (MD5, SHA, NTLM, bcrypt, ...)"),
    ("file", "File protetto (SSH key, PDF, Office, ZIP, RAR, ...)"),
    ("archive", "Archivio / disco cifrato (BitLocker, TrueCrypt, LUKS, ...)"),
    ("service", "Servizio di rete (SSH, RDP, FTP, SMB, ...)"),
]

_PF_HASH_INPUT_MENU = [
    ("identify", "Ho l'hash — identificalo tu"),
    ("known", "Conosco già il formato"),
    ("auto", "Non conosco il formato — prova in auto"),
]

_PF_HASH_FORMAT_MENU = [
    ("raw-md5",       "MD5",                "0",     "raw-md5"),
    ("raw-sha1",      "SHA1",               "100",   "raw-sha1"),
    ("raw-sha256",    "SHA256",             "1400",  "raw-sha256"),
    ("raw-sha512",    "SHA512",             "1700",  "raw-sha512"),
    ("nt",            "NTLM",              "1000",  "nt"),
    ("bcrypt",        "bcrypt",            "3200",  "bcrypt"),
    ("md5crypt",      "md5crypt ($1$)",    "500",   "md5crypt"),
    ("sha512crypt",   "sha512crypt ($6$)", "1800",  "sha512crypt"),
    ("sha256crypt",   "sha256crypt ($5$)", "7400",  "sha256crypt"),
    ("netlmv2",       "NETNTLMv2",         "5600",  "netntlmv2"),
    ("netntlmv2",     "NETNTLMv2",         "5600",  "netntlmv2"),
    ("krb5tgs",       "Kerberoast (TGS)",  "13100", "krb5tgs"),
    ("krb5asrep",     "AS-REP Roast",      "18200", "krb5asrep"),
    ("mscash2",       "DCC2 / mscash2",    "2100",  "mscash2"),
    ("descrypt",      "DES crypt",         "1500",  "descrypt"),
    ("lm",            "LM",                "3000",  "LM"),
    ("phpass",        "phpass (WordPress)", "400",   "phpass-md5"),
    ("ipmi",          "IPMI 2.0 RAKP",     "7300",  ""),
    ("mysql",         "MySQL 4.1+",        "300",   "mysql-sha1"),
    ("mssql",         "MSSQL",             "131",   "mssql05"),
    ("oracle11",      "Oracle 11g+",       "112",   "oracle11"),
]

_PF_ATTACK_MENU = [
    ("wordlist_rules", "Wordlist + regole", "dizionario + mutazioni (consigliato)"),
    ("wordlist",       "Wordlist semplice", "solo dizionario, nessuna regola"),
    ("mask",           "Mask attack",       "conosco pattern o lunghezza"),
    ("incremental",    "Brute-force puro",  "tutte le combinazioni (lento)"),
]

_PF_INTENSITY_MENU = [
    ("fast",   "Veloce",   "top 10k password",            "⚡"),
    ("medium", "Media",    "rockyou.txt (~14M)",           "⚖️"),
    ("full",   "Completa", "rockyou + regole best64.rule", "🔍"),
]

_PF_FILE_MENU = [
    ("ssh",     "SSH private key",         "ssh2john",              "22921"),
    ("pdf",     "PDF",                     "pdf2john",              "10700"),
    ("office",  "Microsoft Office",        "office2john",           "9600"),
    ("zip",     "ZIP",                     "zip2john",              "17200"),
    ("rar",     "RAR",                     "rar2john",              "13000"),
    ("7z",      "7-Zip",                   "7z2john",               "11600"),
    ("keepass", "KeePass (.kdbx)",         "keepass2john",          "13400"),
    ("putty",   "PuTTY key (.ppk)",        "putty2john",           "15300"),
    ("gpg",     "GPG / PGP key",           "gpg2john",             "17010"),
    ("bitcoin", "Bitcoin wallet",          "bitcoin2john",         "11300"),
]

_PF_ARCHIVE_MENU = [
    ("bitlocker",  "BitLocker (.vhd)",     "bitlocker2john",  "22100"),
    ("truecrypt",  "TrueCrypt / VeraCrypt","truecrypt_volume2john", "6211"),
    ("luks",       "LUKS",                 "",                "14600"),
    ("openssl",    "OpenSSL enc (gzip/aes)", "",              ""),
]

_PF_SERVICE_MENU = [
    ("ssh",      "SSH",                    "22"),
    ("rdp",      "RDP",                    "3389"),
    ("ftp",      "FTP",                    "21"),
    ("smb",      "SMB",                    "445"),
    ("http",     "HTTP form login (POST)", "80"),
    ("http-get", "HTTP Basic/GET",         "80"),
    ("mysql",    "MySQL",                  "3306"),
    ("mssql",    "MSSQL",                  "1433"),
    ("postgres", "PostgreSQL",             "5432"),
    ("winrm",    "WinRM",                  "5985"),
    ("vnc",      "VNC",                    "5900"),
]

_PF_MASK_MENU = [
    ("lower8",  "8 caratteri minuscoli",          "?l?l?l?l?l?l?l?l"),
    ("mixed8",  "8 caratteri misti (a-z, A-Z, 0-9)", "?a?a?a?a?a?a?a?a"),
    ("cap_num", "Maiuscola + 5 minusc + 2 cifre", "?u?l?l?l?l?l?d?d"),
    ("custom",  "Scrivo io la maschera",          ""),
]


def _pf_hash_detect_hint(hash_str: str) -> list[str]:
    """Return hints about likely hash format from the hash string itself."""
    h = hash_str.strip()
    hints = []
    if h.startswith("$1$"):
        hints.append("md5crypt ($1$) — john: --format=md5crypt | hashcat: -m 500")
    elif h.startswith("$5$"):
        hints.append("sha256crypt ($5$) — john: --format=sha256crypt | hashcat: -m 7400")
    elif h.startswith("$6$"):
        hints.append("sha512crypt ($6$) — john: --format=sha512crypt | hashcat: -m 1800")
    elif h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"):
        hints.append("bcrypt — john: --format=bcrypt | hashcat: -m 3200")
    elif h.startswith("$krb5tgs$"):
        hints.append("Kerberoast TGS — john: --format=krb5tgs | hashcat: -m 13100")
    elif h.startswith("$krb5asrep$"):
        hints.append("AS-REP Roast — john: --format=krb5asrep | hashcat: -m 18200")
    elif len(h) == 32 and all(c in "0123456789abcdefABCDEF" for c in h):
        hints.append("Possibile MD5 o NTLM (32 hex)")
        hints.append("  MD5  — john: --format=raw-md5 | hashcat: -m 0")
        hints.append("  NTLM — john: --format=nt      | hashcat: -m 1000")
    elif len(h) == 40 and all(c in "0123456789abcdefABCDEF" for c in h):
        hints.append("Possibile SHA1 (40 hex)")
        hints.append("  john: --format=raw-sha1 | hashcat: -m 100")
    elif len(h) == 64 and all(c in "0123456789abcdefABCDEF" for c in h):
        hints.append("Possibile SHA256 (64 hex)")
        hints.append("  john: --format=raw-sha256 | hashcat: -m 1400")
    elif len(h) == 128 and all(c in "0123456789abcdefABCDEF" for c in h):
        hints.append("Possibile SHA512 (128 hex)")
        hints.append("  john: --format=raw-sha512 | hashcat: -m 1700")
    elif "::" in h and "$" not in h:
        hints.append("Possibile NETNTLMv2")
        hints.append("  john: --format=netntlmv2 | hashcat: -m 5600")
    if not hints:
        hints.append("Formato non riconosciuto — usa hashid o hashcat --identify")
    return hints


def _build_hash_result(john_fmt: str, hc_mode: str, attack: str,
                       intensity: str, mask: str) -> dict:
    wl_fast = "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt"
    wl_med = "/usr/share/wordlists/rockyou.txt"
    rules = "/usr/share/hashcat/rules/best64.rule"

    wordlists = []
    commands = []

    if attack == "mask":
        if john_fmt:
            commands.append(("hashcat (mask)", f"hashcat -a 3 -m {hc_mode} hash.txt '{mask}'"))
            commands.append(("john (mask)", f"john --format={john_fmt} --mask='{mask}' hash.txt"))
        else:
            commands.append(("john (mask, auto)", f"john --mask='{mask}' hash.txt"))
        return {"wordlists": wordlists, "commands": commands}

    if attack == "incremental":
        if john_fmt:
            commands.append(("john (incremental)", f"john --format={john_fmt} --incremental hash.txt"))
        else:
            commands.append(("john (incremental, auto)", "john --incremental hash.txt"))
        if hc_mode:
            commands.append(("hashcat (brute-force)", f"hashcat -a 3 -m {hc_mode} hash.txt ?a?a?a?a?a?a?a?a"))
        return {"wordlists": wordlists, "commands": commands}

    if intensity == "fast":
        wl = wl_fast
        wl_label = "xato-net-10-million-passwords-10000.txt"
        wordlists.append("pass_top10k")
    elif intensity == "medium":
        wl = wl_med
        wl_label = "rockyou.txt"
        wordlists.append("pass_rockyou")
    else:
        wl = wl_med
        wl_label = "rockyou.txt + best64.rule"
        wordlists.append("pass_rockyou")

    if john_fmt:
        if attack == "wordlist_rules":
            commands.append(("john (wordlist + rules)", f"john --format={john_fmt} --wordlist={wl} --rules hash.txt"))
        commands.append(("john (wordlist)", f"john --format={john_fmt} --wordlist={wl} hash.txt"))
        commands.append(("john (show)", f"john --format={john_fmt} hash.txt --show"))

    if hc_mode:
        if attack == "wordlist_rules" or intensity == "full":
            commands.append(("hashcat (wordlist + rules)", f"hashcat -a 0 -m {hc_mode} hash.txt {wl} -r {rules}"))
        commands.append(("hashcat (wordlist)", f"hashcat -a 0 -m {hc_mode} hash.txt {wl}"))

    if not john_fmt and not hc_mode:
        commands.append(("john (auto)", f"john --wordlist={wl} hash.txt"))
        if attack == "wordlist_rules":
            commands.append(("john (auto + rules)", f"john --wordlist={wl} --rules hash.txt"))
        commands.append(("john (show)", "john hash.txt --show"))

    return {"wordlists": wordlists, "commands": commands}


def _build_file_result(file_type: str, tool_2john: str, hc_mode: str,
                       intensity: str) -> dict:
    wl = "/usr/share/wordlists/rockyou.txt"
    if intensity == "fast":
        wl = "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt"

    rules = "/usr/share/hashcat/rules/best64.rule"
    ext_map = {
        "ssh": "id_rsa", "pdf": "document.pdf", "office": "file.docx",
        "zip": "archive.zip", "rar": "archive.rar", "7z": "archive.7z",
        "keepass": "database.kdbx", "putty": "key.ppk",
        "gpg": "key.gpg", "bitcoin": "wallet.dat",
    }
    sample = ext_map.get(file_type, "file")

    commands = []
    notes = []

    if tool_2john:
        commands.append(("1. Estrai hash", f"{tool_2john} {sample} > hash.txt"))
    else:
        notes.append(f"Nessun tool *2john specifico — prova: locate *2john*")

    commands.append(("2. john (crack)", f"john --wordlist={wl} hash.txt"))
    if intensity == "full":
        commands.append(("2b. john (+ rules)", f"john --wordlist={wl} --rules hash.txt"))
    commands.append(("3. john (show)", "john hash.txt --show"))

    if hc_mode:
        if intensity == "full":
            commands.append(("hashcat (+ rules)", f"hashcat -a 0 -m {hc_mode} hash.txt {wl} -r {rules}"))
        else:
            commands.append(("hashcat", f"hashcat -a 0 -m {hc_mode} hash.txt {wl}"))

    result = {"commands": commands}
    if notes:
        result["notes"] = notes
    return result


def _build_archive_result(archive_type: str, tool_2john: str, hc_mode: str,
                          intensity: str) -> dict:
    wl = "/usr/share/wordlists/rockyou.txt"
    if intensity == "fast":
        wl = "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt"
    rules = "/usr/share/hashcat/rules/best64.rule"

    commands = []

    if archive_type == "openssl":
        commands.append(("Brute-force OpenSSL", "for i in $(cat " + wl + ");do openssl enc -aes-256-cbc "
                         "-d -in encrypted.gz -k $i 2>/dev/null | tar xz && echo \"Password: $i\" && break; done"))
        return {"commands": commands}

    if tool_2john:
        sample = {"bitlocker": "disk.vhd", "truecrypt": "volume", "luks": "disk.img"}.get(archive_type, "file")
        commands.append(("1. Estrai hash", f"{tool_2john} -i {sample} > hash.txt"))
        if archive_type == "bitlocker":
            commands.append(("1b. Filtra hash", 'grep "bitlocker\\$0" hash.txt > crack.hash'))

    hash_file = "crack.hash" if archive_type == "bitlocker" else "hash.txt"
    commands.append(("2. john (crack)", f"john --wordlist={wl} {hash_file}"))
    commands.append(("3. john (show)", f"john {hash_file} --show"))

    if hc_mode:
        if intensity == "full":
            commands.append(("hashcat (+ rules)", f"hashcat -a 0 -m {hc_mode} {hash_file} {wl} -r {rules}"))
        else:
            commands.append(("hashcat", f"hashcat -a 0 -m {hc_mode} {hash_file} {wl}"))

    if archive_type == "bitlocker":
        commands.append(("Monta (Linux)", "sudo dislocker /dev/loop0p2 -uPASSWORD -- /media/bitlocker && "
                         "sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount"))

    return {"commands": commands}


def _build_service_result(proto: str, port: str, host: str, username: str,
                          intensity: str, user_wl_key: str | None = None) -> dict:
    wl = "/usr/share/wordlists/rockyou.txt"
    if intensity == "fast":
        wl = "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt"

    user_flag = f"-L {_wl_path(user_wl_key)}" if user_wl_key else f"-l {username}"
    user_flag_med = f"-U {_wl_path(user_wl_key)}" if user_wl_key else f"-u {username}"
    user_flag_cme = f"-u {_wl_path(user_wl_key)}" if user_wl_key else f"-u {username}"
    user_flag_ncr = f"-U {_wl_path(user_wl_key)}" if user_wl_key else f"-u {username}"

    s_flag = f"-s {port} " if port else ""
    host_port = f"{host}:{port}" if port else host

    commands = []
    user_wls = [user_wl_key] if user_wl_key else []

    if proto == "http":
        commands.append(("hydra (http-post-form)",
            f'hydra {user_flag} -P {wl} {s_flag}{host} http-post-form '
            f'"/login:user=^USER^&pass=^PASS^:F=incorrect" -f -t 16'))
        commands.append(("medusa (http)",
            f"medusa -h {host} {user_flag_med} -P {wl} -M http -m DIR:/login -t 4"
            + (f" -n {port}" if port else "")))
    elif proto == "http-get":
        commands.append(("hydra (http-get)",
            f"hydra {user_flag} -P {wl} {s_flag}{host} http-get / -f -t 16"))
        commands.append(("hydra (http-get path)",
            f"hydra {user_flag} -P {wl} {s_flag}{host} http-get /admin -f -t 16"))
        commands.append(("medusa (http)",
            f"medusa -h {host} {user_flag_med} -P {wl} -M http -m DIR:/ -t 4"
            + (f" -n {port}" if port else "")))
    elif proto == "winrm":
        commands.append(("crackmapexec",
            f"crackmapexec winrm {host_port} {user_flag_cme} -p {wl}"))
        commands.append(("evil-winrm (dopo crack)",
            f"evil-winrm -i {host} -u {username or 'USER'} -p 'PASSWORD'"
            + (f" -P {port}" if port and port != "5985" else "")))
    elif proto == "smb":
        commands.append(("hydra",
            f"hydra {user_flag} -P {wl} {s_flag}{host} smb -f -t 4"))
        commands.append(("crackmapexec",
            f"crackmapexec smb {host_port} {user_flag_cme} -p {wl}"))
        commands.append(("medusa",
            f"medusa -h {host} {user_flag_med} -P {wl} -M smbnt -t 4"
            + (f" -n {port}" if port else "")))
        commands.append(("ncrack",
            f"ncrack {user_flag_ncr} -P {wl} smb://{host_port}"))
    else:
        svc = proto
        commands.append(("hydra",
            f"hydra {user_flag} -P {wl} {s_flag}{host} {svc} -f -t 4"))
        commands.append(("medusa",
            f"medusa -h {host} {user_flag_med} -P {wl} -M {svc} -t 4"
            + (f" -n {port}" if port else "")))
        commands.append(("ncrack",
            f"ncrack {user_flag_ncr} -P {wl} {svc}://{host_port}"))

    result = {"commands": commands}
    if user_wls:
        result["user_wordlists"] = user_wls
    return result


def _print_passfind_result(result: dict) -> None:
    print(f"\n  \033[92m┌─ Risultato ────────────────────────────────┐\033[0m\n")

    if result.get("hints"):
        print("  \033[1mRilevamento hash:\033[0m")
        for h in result["hints"]:
            print(f"    {h}")
        print()

    if result.get("notes"):
        for n in result["notes"]:
            print(f"  \033[93m[!]\033[0m {n}")
        print()

    if result.get("wordlists"):
        print("  \033[1mWordlist consigliate:\033[0m")
        for i, key in enumerate(result["wordlists"], 1):
            print(f"    [{i}] {_wl_label(key)}")
            link = _wl_link(key)
            if link:
                print(f"        \033[90m↳ {link}\033[0m")
        print()

    if result.get("user_wordlists"):
        print("  \033[1mWordlist username consigliate:\033[0m")
        for i, key in enumerate(result["user_wordlists"], 1):
            print(f"    [{i}] {_wl_label(key)}")
            link = _wl_link(key)
            if link:
                print(f"        \033[90m↳ {link}\033[0m")
        print()

    if result.get("commands"):
        print("  \033[1mComandi pronti (copia-incolla):\033[0m\n")
        for tool_name, cmd in result["commands"]:
            print(f"    \033[96m# {tool_name}\033[0m")
            if len(cmd) > 90:
                parts = cmd.split(" -", 1)
                if len(parts) == 2:
                    print(f"    {parts[0]} \\")
                    flags = (" -" + parts[1]).split(" -")
                    for j, flag in enumerate(flags):
                        flag = flag.strip()
                        if flag:
                            suffix = " \\" if j < len(flags) - 1 else ""
                            print(f"      -{flag}{suffix}")
                else:
                    print(f"    {cmd}")
            else:
                print(f"    {cmd}")
            print()

    if result.get("extra_info"):
        print(f"  \033[1mInfo utili:\033[0m")
        for line in result["extra_info"]:
            print(f"    {line}")
        print()

    print(f"  \033[92m└────────────────────────────────────────────┘\033[0m")


def cmd_passfind(args: argparse.Namespace, state=None) -> int:
    print(f"\n  \033[92m┌─ passfind ─────────────────────────────────┐\033[0m")
    print(f"  \033[90m  Wizard password cracking\033[0m\n")

    # Step 1: scope
    choice = _wf_ask("[1] Cosa devi crackare?", _PF_SCOPE_MENU)
    if choice == -1:
        return 0
    scope = _PF_SCOPE_MENU[choice - 1][0]

    # ── Hash ──────────────────────────────────────────────────
    if scope == "hash":
        inp_choice = _wf_ask("[2] Hai l'hash o conosci il formato?", _PF_HASH_INPUT_MENU)
        if inp_choice == -1:
            return 0

        john_fmt = ""
        hc_mode = ""

        if inp_choice == 1:
            print()
            hash_str = _wf_ask_text("[hash] Incolla l'hash")
            if not hash_str:
                print("  Nessun hash inserito.")
                return 1
            hints = _pf_hash_detect_hint(hash_str)

            fmt_menu = [(f[0], f[1]) for f in _PF_HASH_FORMAT_MENU[:16]]
            fmt_choice = _wf_ask("[3] Seleziona il formato (o basati sui suggerimenti sopra)", fmt_menu)
            if fmt_choice == -1:
                return 0
            entry = _PF_HASH_FORMAT_MENU[fmt_choice - 1]
            john_fmt = entry[3]
            hc_mode = entry[2]
        elif inp_choice == 2:
            fmt_menu = [(f[0], f[1]) for f in _PF_HASH_FORMAT_MENU]
            fmt_choice = _wf_ask("[3] Formato hash?", fmt_menu)
            if fmt_choice == -1:
                return 0
            entry = _PF_HASH_FORMAT_MENU[fmt_choice - 1]
            john_fmt = entry[3]
            hc_mode = entry[2]
            hints = []
        else:
            hints = ["Auto-detect: john tenterà di identificare il formato automaticamente"]

        atk_choice = _wf_ask("[4] Metodo di attacco?", _PF_ATTACK_MENU)
        if atk_choice == -1:
            return 0
        attack = _PF_ATTACK_MENU[atk_choice - 1][0]

        mask = ""
        if attack == "mask":
            mask_choice = _wf_ask("[4b] Pattern maschera?", _PF_MASK_MENU)
            if mask_choice == -1:
                return 0
            mask = _PF_MASK_MENU[mask_choice - 1][2]
            if not mask:
                print()
                mask = _wf_ask_text("[mask] Inserisci la maschera (es. ?u?l?l?l?d?d)", default="?a?a?a?a?a?a?a?a")

        int_choice = _wf_ask("[5] Intensità wordlist?", _PF_INTENSITY_MENU, default=2)
        if int_choice == -1:
            return 0
        intensity = _PF_INTENSITY_MENU[int_choice - 1][0]

        result = _build_hash_result(john_fmt, hc_mode, attack, intensity, mask)
        if hints:
            result["hints"] = hints

        extra = []
        extra.append("Identifica hash:   hashid -m -j '<hash>'")
        extra.append("Formati john:      john --list=formats | grep -i <tipo>")
        extra.append("Formati hashcat:   hashcat --help | grep -i <tipo>")
        result["extra_info"] = extra

    # ── File protetto ─────────────────────────────────────────
    elif scope == "file":
        file_menu = [(f[0], f[1]) for f in _PF_FILE_MENU]
        file_choice = _wf_ask("[2] Tipo di file?", file_menu)
        if file_choice == -1:
            return 0
        entry = _PF_FILE_MENU[file_choice - 1]
        file_type = entry[0]
        tool_2john = entry[2]
        hc_mode = entry[3]

        int_choice = _wf_ask("[3] Intensità?", _PF_INTENSITY_MENU, default=2)
        if int_choice == -1:
            return 0
        intensity = _PF_INTENSITY_MENU[int_choice - 1][0]

        result = _build_file_result(file_type, tool_2john, hc_mode, intensity)
        result["extra_info"] = [
            f"Tool estrazione:   {tool_2john}",
            "Cerca tutti i *2john:  locate *2john*",
        ]

    # ── Archivio / disco cifrato ──────────────────────────────
    elif scope == "archive":
        arc_menu = [(a[0], a[1]) for a in _PF_ARCHIVE_MENU]
        arc_choice = _wf_ask("[2] Tipo di archivio?", arc_menu)
        if arc_choice == -1:
            return 0
        entry = _PF_ARCHIVE_MENU[arc_choice - 1]
        archive_type = entry[0]
        tool_2john = entry[2]
        hc_mode = entry[3]

        int_choice = _wf_ask("[3] Intensità?", _PF_INTENSITY_MENU, default=2)
        if int_choice == -1:
            return 0
        intensity = _PF_INTENSITY_MENU[int_choice - 1][0]

        result = _build_archive_result(archive_type, tool_2john, hc_mode, intensity)

        if archive_type == "bitlocker":
            result["extra_info"] = [
                "Su Windows: doppio click sul .vhd → inserisci password",
                "Su Linux: installa dislocker (sudo apt install dislocker)",
            ]

    # ── Servizio di rete ──────────────────────────────────────
    elif scope == "service":
        svc_menu = [(s[0], f"{s[1]}  (porta {s[2]})") for s in _PF_SERVICE_MENU]
        svc_choice = _wf_ask("[2] Protocollo?", svc_menu)
        if svc_choice == -1:
            return 0
        entry = _PF_SERVICE_MENU[svc_choice - 1]
        proto = entry[0]
        default_port = entry[2]

        print()
        host_raw = _wf_ask_text("[3] Target IP/hostname (oppure IP:PORTA)", default="10.10.11.42")
        if ":" in host_raw and not host_raw.startswith("["):
            parts = host_raw.rsplit(":", 1)
            if parts[1].isdigit():
                host = parts[0]
                port = parts[1]
            else:
                host = host_raw
                port = ""
        else:
            host = host_raw
            port = ""

        if not port:
            print()
            port_input = _wf_ask_text(f"[3b] Porta? (invio = {default_port})", default="")
            port = port_input if port_input else default_port

        print()
        _USER_MODE_MENU = [
            ("single", "Username singolo (lo scrivo io)"),
            ("wordlist", "Wordlist username (non conosco lo username)"),
        ]
        user_mode_choice = _wf_ask("[4] Username?", _USER_MODE_MENU, default=2)
        if user_mode_choice == -1:
            return 0

        username = "admin"
        user_wl_key = None
        if user_mode_choice == 1:
            print()
            username = _wf_ask_text("[4b] Username (vuoto = admin)", default="admin")
        else:
            _USER_WL_MENU = [
                ("user_top", f"top-usernames-shortlist.txt  (17 — i più comuni)"),
                ("user_cirt", f"cirt-default-usernames.txt  (827 — credenziali default)"),
                ("user_names", f"names.txt  (10k — nomi comuni)"),
                ("user_unix", f"unix_users.txt  (167 — utenti UNIX tipici)"),
                ("user_xato", f"xato-net-10-million-usernames.txt  (8.3M — esaustiva)"),
            ]
            uwl_choice = _wf_ask("[4b] Quale wordlist username?", _USER_WL_MENU)
            if uwl_choice == -1:
                return 0
            user_wl_key = _USER_WL_MENU[uwl_choice - 1][0]

        _PF_PASS_WL_MENU = [
            ("pass_500", "500-worst-passwords.txt  (500 — velocissimo)", "⚡"),
            ("pass_default_web", "default-passwords.txt  (1.2k — credenziali default)", "⚡"),
            ("pass_top10k", "xato-net-10-million-passwords-10000.txt  (10k)", "⚖️"),
            ("pass_10k_most_common", "10k-most-common.txt  (10k — alternativa)", "⚖️"),
            ("pass_100k", "xato-net-10-million-passwords-100000.txt  (100k)", "⚖️"),
            ("pass_top1m", "xato-net-10-million-passwords-1000000.txt  (1M)", "🔍"),
            ("pass_rockyou", "rockyou.txt  (14M — esaustiva)", "🔍"),
        ]
        # Add protocol-specific defaults
        proto_defaults = {
            "ftp": ("pass_ftp_default", "ftp-betterdefaultpasslist.txt  (52 — default FTP)", "⭐"),
            "ssh": ("pass_ssh_default", "ssh-betterdefaultpasslist.txt  (40 — default SSH)", "⭐"),
            "mysql": ("pass_mysql_default", "mysql-betterdefaultpasslist.txt  (15 — default MySQL)", "⭐"),
            "mssql": ("pass_mssql_default", "mssql-betterdefaultpasslist.txt  (60 — default MSSQL)", "⭐"),
            "postgres": ("pass_postgres_default", "postgres-betterdefaultpasslist.txt  (16 — default Postgres)", "⭐"),
        }
        if proto in proto_defaults:
            _PF_PASS_WL_MENU.insert(0, proto_defaults[proto])

        pw_choice = _wf_ask("[5] Wordlist password?", _PF_PASS_WL_MENU, default=1)
        if pw_choice == -1:
            return 0
        pw_key = _PF_PASS_WL_MENU[pw_choice - 1][0]
        wl_path = _wl_path(pw_key)

        result = _build_service_result(proto, port, host, username, "custom",
                                       user_wl_key=user_wl_key)
        # Override password wordlist in generated commands
        for i, (name, cmd) in enumerate(result["commands"]):
            old_wls = [
                "/usr/share/wordlists/rockyou.txt",
                "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt",
            ]
            for old in old_wls:
                cmd = cmd.replace(old, wl_path)
            result["commands"][i] = (name, cmd)

        result["wordlists"] = [pw_key]

    else:
        print("  Scopo non supportato.")
        return 1

    _print_passfind_result(result)
    return 0


# ──────────────────────────────────────────────────────────────
# wordgen — Wizard creazione wordlist personalizzate
# ──────────────────────────────────────────────────────────────

_WG_METHOD_MENU = [
    ("cewl",       "CeWL",            "crawla un sito → wordlist dalle parole trovate"),
    ("crunch",     "Crunch",          "genera combinazioni da charset e lunghezza"),
    ("cupp",       "CUPP",            "profila una persona → password probabili"),
    ("john_rules", "John rules",      "muta una wordlist esistente con regole"),
    ("hc_rules",   "Hashcat rules",   "muta una wordlist con regole hashcat"),
    ("mask",       "Maskprocessor",   "genera da maschera (?u?l?l?d?d)"),
    ("prince",     "Princeprocessor", "combina parole di un dizionario tra loro"),
    ("kwproc",     "Kwprocessor",     "genera keyboard walks (qwerty, asdfgh...)"),
    ("user_anarchy","Username Anarchy","da nome e cognome → varianti username"),
    ("rsmangler",  "rsmangler",       "permutazioni: capitalize, reverse, append numeri"),
    ("pydictor",   "Pydictor",        "generator Python: social eng, leet, combo"),
    ("ttpassgen",  "TTPassGen",       "pattern: date, nomi, combinazioni custom"),
    ("lyricpass",  "Lyricpass",       "wordlist da testi di canzoni (Genius API)"),
    ("bewgor",     "BEWGor",          "come CUPP ma con più varianti (date IT, suffissi)"),
    ("bash",       "Bash/Python",     "script custom con for/sed/awk/python"),
    ("combo",      "Combinazione",    "unisci più wordlist + dedup + regole"),
]

_WG_INSTALL = {
    "cewl":        "sudo apt install cewl",
    "crunch":      "sudo apt install crunch",
    "cupp":        "git clone https://github.com/Mebus/cupp.git && cd cupp && python3 cupp.py -i",
    "john_rules":  "sudo apt install john",
    "hc_rules":    "sudo apt install hashcat",
    "mask":        "sudo apt install maskprocessor   # oppure: https://github.com/hashcat/maskprocessor",
    "prince":      "https://github.com/hashcat/princeprocessor → make",
    "kwproc":      "https://github.com/hashcat/kwprocessor → make",
    "user_anarchy":"git clone https://github.com/urbanadventurer/username-anarchy.git",
    "rsmangler":   "git clone https://github.com/digininja/RSMangler.git",
    "pydictor":    "git clone https://github.com/LandGrey/pydictor.git",
    "ttpassgen":   "pip3 install ttpassgen",
    "lyricpass":   "git clone https://github.com/initstring/lyricpass.git",
    "bewgor":      "git clone https://github.com/berzerk0/BEWGor.git",
    "bash":        "(nessuna installazione — bash + coreutils)",
    "combo":       "(nessuna installazione — bash + sort/uniq)",
}


def _wg_build(method: str) -> dict:
    commands = []
    notes = []
    install = _WG_INSTALL.get(method, "")

    if method == "cewl":
        url = _wf_ask_text("[URL] Sito da crawlare", default="http://target.com")
        depth = _wf_ask_text("[Depth] Profondità (default 2)", default="2")
        minlen = _wf_ask_text("[Min] Lunghezza minima parole (default 5)", default="5")
        outfile = _wf_ask_text("[Output] File di output", default="cewl_wordlist.txt")
        commands.append(("CeWL base", f"cewl -d {depth} -m {minlen} -w {outfile} {url}"))
        commands.append(("CeWL + email", f"cewl -d {depth} -m {minlen} -w {outfile} -e --email_file emails.txt {url}"))
        commands.append(("CeWL + lowercase", f"cewl -d {depth} -m {minlen} --lowercase -w {outfile} {url}"))
        notes.append("--with-numbers include anche parole con numeri")
        notes.append("-c mostra il conteggio di ogni parola")

    elif method == "crunch":
        minl = _wf_ask_text("[Min] Lunghezza minima", default="6")
        maxl = _wf_ask_text("[Max] Lunghezza massima", default="8")
        _CHARSET_MENU = [
            ("lower", "Solo minuscole (abcdefghijklmnopqrstuvwxyz)"),
            ("upper", "Solo maiuscole"),
            ("digits", "Solo numeri (0-9)"),
            ("lower_digits", "Minuscole + numeri"),
            ("mixed", "Tutto (a-z, A-Z, 0-9, simboli)"),
            ("custom", "Scrivo io il charset"),
        ]
        cs_choice = _wf_ask("Charset?", _CHARSET_MENU)
        if cs_choice == -1:
            return {"commands": [], "notes": []}
        charset_map = {
            "lower": "abcdefghijklmnopqrstuvwxyz",
            "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "digits": "0123456789",
            "lower_digits": "abcdefghijklmnopqrstuvwxyz0123456789",
            "mixed": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%",
        }
        cs_key = _CHARSET_MENU[cs_choice - 1][0]
        if cs_key == "custom":
            charset = _wf_ask_text("[Charset] Inserisci i caratteri", default="abc123")
        else:
            charset = charset_map[cs_key]
        outfile = _wf_ask_text("[Output] File di output", default="crunch_wordlist.txt")
        commands.append(("Crunch", f"crunch {minl} {maxl} '{charset}' -o {outfile}"))
        commands.append(("Crunch con pattern", f"crunch {minl} {maxl} -t ,@@%%^^ -o {outfile}"))
        notes.append("Pattern: @ = minuscola, , = maiuscola, % = numero, ^ = simbolo")
        notes.append(f"Attenzione: crunch {minl}-{maxl} con charset ampio genera file enormi")

    elif method == "cupp":
        commands.append(("CUPP interattivo", "python3 cupp.py -i"))
        commands.append(("CUPP da file config", "python3 cupp.py -w"))
        commands.append(("CUPP download default", "python3 cupp.py -l"))
        notes.append("Ti chiederà nome, cognome, data di nascita, nick, partner, pet, ecc.")
        notes.append("Più info inserisci, migliore è la wordlist generata")

    elif method == "john_rules":
        wl = _wf_ask_text("[Wordlist] Wordlist base da mutare", default="/usr/share/wordlists/rockyou.txt")
        outfile = _wf_ask_text("[Output] File di output", default="mutated.txt")
        commands.append(("John + best64", f"john --wordlist={wl} --rules=best64 --stdout > {outfile}"))
        commands.append(("John + jumbo", f"john --wordlist={wl} --rules=jumbo --stdout > {outfile}"))
        commands.append(("John + korelogic", f"john --wordlist={wl} --rules=KoreLogic --stdout > {outfile}"))
        commands.append(("Lista regole", "john --list=rules"))
        notes.append("best64 = 64 regole più efficaci (veloce)")
        notes.append("jumbo = migliaia di regole (lento, esaustivo)")

    elif method == "hc_rules":
        wl = _wf_ask_text("[Wordlist] Wordlist base da mutare", default="/usr/share/wordlists/rockyou.txt")
        outfile = _wf_ask_text("[Output] File di output", default="mutated.txt")
        rules_dir = "/usr/share/hashcat/rules"
        commands.append(("best64.rule", f"hashcat --stdout -r {rules_dir}/best64.rule {wl} > {outfile}"))
        commands.append(("dive.rule", f"hashcat --stdout -r {rules_dir}/dive.rule {wl} > {outfile}"))
        commands.append(("toggles.rule", f"hashcat --stdout -r {rules_dir}/toggles1.rule {wl} > {outfile}"))
        commands.append(("combina 2 regole", f"hashcat --stdout -r {rules_dir}/best64.rule -r {rules_dir}/toggles1.rule {wl} > {outfile}"))
        notes.append("dive.rule = ~100k regole (molto lento, molto esaustivo)")
        notes.append(f"Lista regole: ls {rules_dir}/")

    elif method == "mask":
        mask = _wf_ask_text("[Mask] Maschera (es. ?u?l?l?l?d?d)", default="?u?l?l?l?l?l?d?d")
        outfile = _wf_ask_text("[Output] File di output", default="mask_wordlist.txt")
        commands.append(("Maskprocessor", f"mp64 '{mask}' -o {outfile}"))
        commands.append(("Hashcat mask", f"hashcat -a 3 --stdout '{mask}' > {outfile}"))
        notes.append("?l = minuscola, ?u = maiuscola, ?d = cifra, ?s = simbolo, ?a = tutto")
        notes.append("?1 = charset custom: hashcat -a 3 -1 ?l?d --stdout '?1?1?1?1?1?1'")

    elif method == "prince":
        wl = _wf_ask_text("[Wordlist] Dizionario base", default="words.txt")
        outfile = _wf_ask_text("[Output] File di output", default="prince_wordlist.txt")
        commands.append(("Prince base", f"pp64 < {wl} > {outfile}"))
        commands.append(("Prince max 3 parole", f"pp64 --elem-cnt-max=3 < {wl} > {outfile}"))
        commands.append(("Prince con lunghezza", f"pp64 --pw-min=8 --pw-max=16 < {wl} > {outfile}"))
        notes.append("Combina 2-3 parole del dizionario: 'password' + 'admin' → 'passwordadmin'")
        notes.append("Molto efficace con wordlist piccole e mirate (nomi, parole target)")

    elif method == "kwproc":
        outfile = _wf_ask_text("[Output] File di output", default="keyboard_wordlist.txt")
        commands.append(("QWERTY walks", f"kwp basechars/full.base keymaps/en-us.keymap routes/2-to-16-max-3-direction-changes.route > {outfile}"))
        commands.append(("Solo 8 char", f"kwp basechars/full.base keymaps/en-us.keymap routes/2-to-10-max-2-direction-changes.route | awk 'length==8' > {outfile}"))
        notes.append("Genera pattern da tastiera: qwerty, asdfgh, zxcvbn, 1qaz2wsx...")
        notes.append("Scarica: https://github.com/hashcat/kwprocessor")

    elif method == "user_anarchy":
        nome = _wf_ask_text("[Nome] Nome e cognome", default="Mario Rossi")
        outfile = _wf_ask_text("[Output] File di output", default="usernames.txt")
        commands.append(("Username Anarchy", f"./username-anarchy '{nome}' > {outfile}"))
        commands.append(("Con formato email", f"./username-anarchy --select-format first.last '{nome}' > {outfile}"))
        commands.append(("Da file di nomi", f"./username-anarchy --input-file names.txt > {outfile}"))
        notes.append("Genera: mrossi, m.rossi, rossim, mario.rossi, mario_rossi, ecc.")

    elif method == "rsmangler":
        wl = _wf_ask_text("[Wordlist] Parole base (una per riga)", default="base_words.txt")
        outfile = _wf_ask_text("[Output] File di output", default="mangled.txt")
        commands.append(("rsmangler", f"rsmangler -f {wl} > {outfile}"))
        commands.append(("Solo capitalize + numeri", f"rsmangler -f {wl} --capitalize --numbers > {outfile}"))
        notes.append("Permutazioni: capitalize, reverse, append 0-99, double, leet speak")
        notes.append("Crea un file base_words.txt con poche parole chiave (nome, azienda, anno...)")

    elif method == "pydictor":
        commands.append(("Base numerica", "pydictor -base d --len 6 8 -o num_wordlist.txt"))
        commands.append(("Leet speak", "pydictor -base dLc --len 6 12 --leet 0 1 2 -o leet_wordlist.txt"))
        commands.append(("Social engineering", "pydictor --sedb"))
        commands.append(("Combo da file", "pydictor -tool combiner file1.txt file2.txt -o combined.txt"))
        notes.append("--sedb = modalità interattiva social engineering (come CUPP ma più opzioni)")
        notes.append("Supporta plugin custom in Python")

    elif method == "ttpassgen":
        commands.append(("Da pattern", "ttpassgen --rule '[?l]{6,8}[?d]{2,4}' -o tt_wordlist.txt"))
        commands.append(("Nome + anno", "ttpassgen --rule 'mario[?d]{4}' -o tt_wordlist.txt"))
        commands.append(("Append special", "ttpassgen --rule '[?l]{4,6}[!@#$]{1,2}[?d]{2}' -o tt_wordlist.txt"))
        notes.append("Sintassi regole: ?l=lower, ?u=upper, ?d=digit, ?s=special")
        notes.append("pip3 install ttpassgen")

    elif method == "lyricpass":
        artista = _wf_ask_text("[Artista] Nome artista/band", default="Eminem")
        outfile = _wf_ask_text("[Output] File di output", default="lyrics_wordlist.txt")
        commands.append(("Lyricpass", f"python3 lyricpass.py -a '{artista}' -o {outfile}"))
        notes.append("Richiede Genius API token (gratuito): export GENIUS_CLIENT_ACCESS_TOKEN=...")
        notes.append("Utile quando sai che il target è fan di un artista specifico")

    elif method == "bewgor":
        commands.append(("BEWGor interattivo", "python3 bewgor.py"))
        notes.append("Come CUPP ma con varianti extra: date italiane, suffissi comuni IT (123, !!, ecc.)")
        notes.append("git clone https://github.com/berzerk0/BEWGor.git")

    elif method == "bash":
        outfile = _wf_ask_text("[Output] File di output", default="custom_wordlist.txt")
        commands.append(("Combina parole", f"for a in mario admin root; do for b in 2024 2025 123 !; do echo \"$a$b\"; done; done > {outfile}"))
        commands.append(("Date italiane", f"for y in $(seq 1980 2005); do for m in $(seq -w 1 12); do for d in $(seq -w 1 31); do echo \"$d$m$y\"; echo \"$d/$m/$y\"; done; done; done > {outfile}"))
        commands.append(("Leet speak", f"sed 'y/aeiost/431057/' base.txt >> {outfile}"))
        commands.append(("Append numeri 0-999", f"while read w; do for i in $(seq 0 999); do echo \"$w$i\"; done; done < base.txt > {outfile}"))
        notes.append("Combinare con sort -u per rimuovere duplicati")

    elif method == "combo":
        outfile = _wf_ask_text("[Output] File di output", default="combined_wordlist.txt")
        commands.append(("Unisci + dedup", f"cat wordlist1.txt wordlist2.txt wordlist3.txt | sort -u > {outfile}"))
        commands.append(("Filtra per lunghezza", f"awk 'length >= 6 && length <= 16' {outfile} > filtered.txt"))
        commands.append(("Poi muta con regole", f"john --wordlist={outfile} --rules=best64 --stdout | sort -u > final.txt"))
        commands.append(("Conta righe", f"wc -l {outfile}"))
        notes.append("Workflow tipico: CeWL + CUPP + base → unisci → dedup → muta con rules → dedup finale")

    return {"commands": commands, "notes": notes, "install": install}


def cmd_wordgen(args: argparse.Namespace, state=None) -> int:
    print(f"\n  \033[92m┌─ wordgen ──────────────────────────────────┐\033[0m")
    print(f"  \033[90m  Wizard creazione wordlist personalizzate\033[0m\n")

    choice = _wf_ask("[1] Metodo di generazione?", _WG_METHOD_MENU)
    if choice == -1:
        return 0
    method = _WG_METHOD_MENU[choice - 1][0]

    print()
    result = _wg_build(method)

    print(f"\n  \033[92m┌─ Risultato ────────────────────────────────┐\033[0m\n")

    if result.get("install"):
        print(f"  \033[1mInstallazione:\033[0m")
        print(f"    {result['install']}")
        print()

    if result.get("notes"):
        for n in result["notes"]:
            print(f"  \033[93m[i]\033[0m {n}")
        print()

    if result.get("commands"):
        print("  \033[1mComandi pronti (copia-incolla):\033[0m\n")
        for tool_name, cmd in result["commands"]:
            print(f"    \033[96m# {tool_name}\033[0m")
            if len(cmd) > 90:
                parts = cmd.split(" -", 1)
                if len(parts) == 2:
                    print(f"    {parts[0]} \\")
                    flags = (" -" + parts[1]).split(" -")
                    for j, flag in enumerate(flags):
                        flag = flag.strip()
                        if flag:
                            suffix = " \\" if j < len(flags) - 1 else ""
                            print(f"      -{flag}{suffix}")
                else:
                    print(f"    {cmd}")
            else:
                print(f"    {cmd}")
            print()

    print(f"  \033[92m└────────────────────────────────────────────┘\033[0m")
    return 0

