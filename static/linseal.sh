#!/bin/sh
# LinSeal — Lightweight Linux Enumeration (SeaLion)
# POSIX-compatible, no dependencies, no broken pipes

set -e

# Colors
R='\033[1;31m'    # red — critical
Y='\033[1;33m'    # yellow — interesting
G='\033[1;32m'    # green — info
C='\033[1;36m'    # cyan — section
B='\033[1;34m'    # blue — header
W='\033[1;37m'    # white bold
N='\033[0m'       # reset

banner() {
  printf "\n${B}╔══════════════════════════════════════════════╗${N}\n"
  printf "${B}║${W}    LinSeal — Lightweight Linux Enumeration   ${B}║${N}\n"
  printf "${B}║${G}              SeaLion Toolkit                 ${B}║${N}\n"
  printf "${B}╚══════════════════════════════════════════════╝${N}\n\n"
}

section() {
  printf "\n${C}═══════════════════════════════════════════════${N}\n"
  printf "${C}  %s${N}\n" "$1"
  printf "${C}═══════════════════════════════════════════════${N}\n\n"
}

hi() { printf "${R}[!] %s${N}\n" "$1"; }
warn() { printf "${Y}[*] %s${N}\n" "$1"; }
info() { printf "${G}[+] %s${N}\n" "$1"; }

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
  SUDO_OUT=$(sudo -l 2>/dev/null)
  if [ -n "$SUDO_OUT" ]; then
    printf "%s\n" "$SUDO_OUT"
    if echo "$SUDO_OUT" | grep -qi "NOPASSWD"; then
      hi "NOPASSWD entries found — check for privesc"
    fi
    if echo "$SUDO_OUT" | grep -qi "(ALL)"; then
      hi "Can run commands as ALL users"
    fi
    for cmd in env find vim nmap python perl ruby bash sh less more awk node php; do
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
  [ -r "$f" ] 2>/dev/null && printf "${W}--- %s ---${N}\n" "$f" && cat "$f" 2>/dev/null
done

printf "\n${W}--- User crontab ---${N}\n"
crontab -l 2>/dev/null || info "No user crontab"

# Check writable scripts in cron
grep -rhE '^[^#].*/' /etc/crontab /etc/cron.d/ 2>/dev/null | grep -oE '/[^ ]+' | sort -u | while read -r s; do
  if [ -f "$s" ] && [ -w "$s" ]; then
    hi "WRITABLE cron script: $s"
  fi
done

# ── Timers ───────────────────────────────────────────────────
section "SYSTEMD TIMERS"

if command -v systemctl >/dev/null 2>&1; then
  systemctl list-timers --no-pager 2>/dev/null || true
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

printf "\n${W}--- All processes ---${N}\n"
ps aux 2>/dev/null

# ── Network ──────────────────────────────────────────────────
section "NETWORK — LISTENING PORTS"

if command -v ss >/dev/null 2>&1; then
  ss -tlnp 2>/dev/null
elif command -v netstat >/dev/null 2>&1; then
  netstat -tlnp 2>/dev/null
fi

printf "\n${W}--- All connections ---${N}\n"
if command -v ss >/dev/null 2>&1; then
  ss -tanp 2>/dev/null
elif command -v netstat >/dev/null 2>&1; then
  netstat -tanp 2>/dev/null
fi

section "NETWORK — INTERFACES"
ip addr 2>/dev/null || ifconfig 2>/dev/null

section "NETWORK — ROUTES"
ip route 2>/dev/null || route -n 2>/dev/null

section "NETWORK — ARP"
ip neigh 2>/dev/null || arp -a 2>/dev/null

# ── Interesting files ────────────────────────────────────────
section "INTERESTING FILES"

info "Looking for passwords/keys in common locations..."

for f in /etc/shadow /etc/master.passwd; do
  if [ -r "$f" ]; then
    hi "READABLE: $f"
    cat "$f"
  fi
done

printf "\n${W}--- SSH keys ---${N}\n"
find / -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "*.pem" -o -name "authorized_keys" 2>/dev/null | while read -r f; do
  if [ -r "$f" ]; then
    hi "FOUND: $f"
    ls -la "$f"
  fi
done

printf "\n${W}--- Config files with passwords ---${N}\n"
for f in /var/www /opt /home /srv /etc; do
  find "$f" -maxdepth 4 -type f \( -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.env" -o -name ".env" -o -name "wp-config.php" -o -name "config.php" -o -name "database.yml" -o -name "settings.py" -o -name "*.properties" \) -readable 2>/dev/null | while read -r c; do
    if grep -qiE 'passw|secret|key.*=|token|credentials|mysql|postgres' "$c" 2>/dev/null; then
      hi "PASSWORDS in: $c"
      grep -inE 'passw|secret|key.*=|token|credentials' "$c" 2>/dev/null | head -5
      printf "\n"
    fi
  done
done

printf "\n${W}--- History files ---${N}\n"
for f in /home/*/.bash_history /home/*/.zsh_history /root/.bash_history /home/*/.mysql_history /home/*/.psql_history; do
  if [ -r "$f" ] 2>/dev/null; then
    hi "READABLE: $f"
    wc -l "$f" 2>/dev/null
    grep -iE 'passw|secret|token|key|mysql.*-p|sudo|su |ssh ' "$f" 2>/dev/null | head -10
  fi
done

printf "\n${W}--- Backup files ---${N}\n"
find / -maxdepth 4 -type f \( -name "*.bak" -o -name "*.old" -o -name "*.save" -o -name "*.orig" -o -name "*backup*" -o -name "*.sql" -o -name "*.db" -o -name "*.sqlite" \) -readable 2>/dev/null | head -20 | while read -r f; do
  warn "BACKUP: $f"
done

# ── /etc/passwd ──────────────────────────────────────────────
section "USERS"

info "Users with shell:"
grep -E '/bin/(ba)?sh$|/bin/zsh$|/bin/fish$' /etc/passwd 2>/dev/null

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

ls -la /home/ 2>/dev/null
for d in /home/*; do
  [ -d "$d" ] || continue
  if [ -r "$d" ]; then
    printf "\n${W}--- %s ---${N}\n" "$d"
    ls -la "$d" 2>/dev/null
  fi
done

# ── Docker / LXD ─────────────────────────────────────────────
section "CONTAINERS"

if command -v docker >/dev/null 2>&1; then
  warn "Docker installed"
  docker ps -a 2>/dev/null && docker images 2>/dev/null
  if [ -w /var/run/docker.sock ]; then
    hi "docker.sock is WRITABLE — container escape possible"
  fi
fi

if command -v lxc >/dev/null 2>&1; then
  warn "LXC/LXD installed"
  lxc list 2>/dev/null
fi

# ── Mounted filesystems ─────────────────────────────────────
section "MOUNTS"

mount 2>/dev/null | while read -r line; do
  if echo "$line" | grep -qE 'nosuid|noexec'; then
    info "$line"
  else
    printf "%s\n" "$line"
  fi
done

printf "\n${W}--- /etc/fstab ---${N}\n"
cat /etc/fstab 2>/dev/null

# ── Disk ─────────────────────────────────────────────────────
section "DISK USAGE"
df -h 2>/dev/null

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

# ── Done ─────────────────────────────────────────────────────
printf "\n${B}╔══════════════════════════════════════════════╗${N}\n"
printf "${B}║${G}          LinSeal scan complete                ${B}║${N}\n"
printf "${B}╚══════════════════════════════════════════════╝${N}\n\n"
printf "${Y}[!] = Critical   ${G}[+] = Info   ${Y}[*] = Interesting${N}\n\n"
