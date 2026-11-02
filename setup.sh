#!/usr/bin/env bash
#
# setup.sh - install and verify everything nscan.sh needs
#
#   * checks bash, naabu, nmap, flock, timeout, libpcap
#   * installs what is missing via the system package manager
#   * installs naabu from source (go install) or a prebuilt release binary
#   * optionally grants cap_net_raw so SYN scans work without root (--setcap)
#   * optionally installs extra vuln NSE scripts (--extra-scripts)
#   * finishes with a dependency report and a real nscan.sh dry run
#
set -uo pipefail

SETUP_VERSION="1.0.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NSCAN="$SCRIPT_DIR/nscan.sh"

MIN_BASH_MAJOR=5
NAABU_FALLBACK_VERSION="2.3.1"   # used if the GitHub API is unreachable
NMAP_SCRIPT_DIRS=(/usr/share/nmap/scripts /usr/local/share/nmap/scripts)

ASSUME_YES=0
CHECK_ONLY=0
DRY_RUN=0
DO_SETCAP=0
DO_EXTRA_SCRIPTS=0
FORCE_SOURCE=0

# ------------------------------------------------------------------ output ---
if [[ -t 1 ]]; then
  B=$'\e[1m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
else
  B=""; R=""; G=""; Y=""; C=""; N=""
fi
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s==>%s %s%s%s\n' "$C" "$N" "$B" "$*" "$N"; }
ok()   { printf '  %s[ ok ]%s %s\n' "$G" "$N" "$*"; }
miss() { printf '  %s[miss]%s %s\n' "$Y" "$N" "$*"; }
bad()  { printf '  %s[fail]%s %s\n' "$R" "$N" "$*"; }
info() { printf '  %s..%s   %s\n' "$C" "$N" "$*"; }
die()  { printf '\n%sERROR%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

usage() {
  cat <<EOF
${B}setup.sh v$SETUP_VERSION${N} - dependency installer for nscan.sh

Usage: $0 [options]

  -c, --check           only report what is present/missing, change nothing
  -n, --dry-run         print the install commands without running them
  -y, --yes             assume yes, never prompt (for CI / provisioning)
      --setcap          grant cap_net_raw+eip to naabu & nmap so SYN scans
                        work without sudo (Linux only)
      --extra-scripts   also install the nmap-vulners and vulscan NSE scripts
      --from-source     build naabu with "go install" even if a release
                        binary could be downloaded
  -h, --help            this help

Examples:
  sudo ./setup.sh                      # install everything, prompt once
  sudo ./setup.sh -y --setcap          # unattended, rootless SYN afterwards
  ./setup.sh --check                   # audit only
  ./setup.sh -n                        # see the exact commands first
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--check)       CHECK_ONLY=1; shift ;;
    -n|--dry-run)     DRY_RUN=1; shift ;;
    -y|--yes)         ASSUME_YES=1; shift ;;
    --setcap)         DO_SETCAP=1; shift ;;
    --extra-scripts)  DO_EXTRA_SCRIPTS=1; shift ;;
    --from-source)    FORCE_SOURCE=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    *)                printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }

# Privilege helper: run as root, via sudo, or explain why we cannot.
if [[ $(id -u) -eq 0 ]]; then
  SUDO=""
elif have sudo; then
  SUDO="sudo"
else
  SUDO=""
fi

# run <cmd...> : honour --dry-run, echo what happens
run() {
  if (( DRY_RUN )); then
    printf '  %s[dry]%s %s\n' "$Y" "$N" "$*"
    return 0
  fi
  info "$*"
  "$@"
}

# run_root <cmd...> : same, but needs privileges
run_root() {
  if [[ $(id -u) -ne 0 && -z "$SUDO" ]]; then
    bad "need root (or sudo) for: $*"
    return 1
  fi
  if [[ -n "$SUDO" ]]; then run $SUDO "$@"; else run "$@"; fi
}

confirm() {
  (( ASSUME_YES )) && return 0
  (( DRY_RUN )) && return 0
  local reply
  printf '%s%s%s [Y/n] ' "$B" "$1" "$N"
  read -r reply || true
  [[ -z "$reply" || "$reply" =~ ^[Yy] ]]
}

# ------------------------------------------------------- package managers ---
PM=""; PM_INSTALL=""; PM_UPDATE=""
detect_pm() {
  if   have apt-get; then PM="apt";    PM_UPDATE="apt-get update -qq";  PM_INSTALL="apt-get install -y"
  elif have dnf;     then PM="dnf";    PM_UPDATE="";                    PM_INSTALL="dnf install -y"
  elif have yum;     then PM="yum";    PM_UPDATE="";                    PM_INSTALL="yum install -y"
  elif have pacman;  then PM="pacman"; PM_UPDATE="pacman -Sy --noconfirm"; PM_INSTALL="pacman -S --needed --noconfirm"
  elif have zypper;  then PM="zypper"; PM_UPDATE="";                    PM_INSTALL="zypper install -y"
  elif have apk;     then PM="apk";    PM_UPDATE="apk update";          PM_INSTALL="apk add"
  elif have brew;    then PM="brew";   PM_UPDATE="";                    PM_INSTALL="brew install"
  fi
}

# pkg_name <logical-name> : map a dependency to this distro's package name
pkg_name() {
  case "$1:$PM" in
    nmap:*)                  echo "nmap" ;;
    libpcap:apt)             echo "libpcap-dev" ;;
    libpcap:dnf|libpcap:yum) echo "libpcap-devel" ;;
    libpcap:pacman)          echo "libpcap" ;;
    libpcap:zypper)          echo "libpcap-devel" ;;
    libpcap:apk)             echo "libpcap-dev" ;;
    libpcap:brew)            echo "libpcap" ;;
    flock:apt|flock:dnf|flock:yum|flock:zypper) echo "util-linux" ;;
    flock:pacman)            echo "util-linux" ;;
    flock:apk)               echo "flock" ;;
    flock:brew)              echo "flock" ;;
    timeout:apk)             echo "coreutils" ;;
    timeout:*)               echo "coreutils" ;;
    curl:*)                  echo "curl" ;;
    unzip:*)                 echo "unzip" ;;
    go:apt)                  echo "golang-go" ;;
    go:*)                    echo "go" ;;
    *)                       echo "$1" ;;
  esac
}

PM_PENDING=()
queue_pkg() { PM_PENDING+=("$(pkg_name "$1")"); }

install_queued() {
  (( ${#PM_PENDING[@]} )) || return 0
  local uniq; mapfile -t uniq < <(printf '%s\n' "${PM_PENDING[@]}" | awk '!s[$0]++')
  step "Installing packages: ${uniq[*]}"
  [[ -n "$PM_UPDATE" ]] && run_root $PM_UPDATE
  # shellcheck disable=SC2086
  run_root $PM_INSTALL "${uniq[@]}" || die "package install failed: ${uniq[*]}"
  PM_PENDING=()
}

# ----------------------------------------------------------------- checks ---
MISSING=()
NEED_NAABU=0

check_bash() {
  local maj="${BASH_VERSINFO[0]}"
  if (( maj >= MIN_BASH_MAJOR )); then
    ok "bash $BASH_VERSION"
  else
    bad "bash $BASH_VERSION - nscan.sh needs bash >= $MIN_BASH_MAJOR.0"
    MISSING+=("bash")
  fi
}

check_cmd() {   # check_cmd <command> <logical-pkg> [version-cmd]
  local cmd="$1" pkg="$2" vcmd="${3:-}" ver=""
  if have "$cmd"; then
    [[ -n "$vcmd" ]] && ver="$(eval "$vcmd" 2>/dev/null | head -1)"
    ok "$cmd${ver:+ - $ver}"
    return 0
  fi
  miss "$cmd (package: $(pkg_name "$pkg"))"
  MISSING+=("$cmd")
  queue_pkg "$pkg"
  return 1
}

check_libpcap() {
  local found=""
  # Note: assign first - "ldconfig | grep -q" can race into SIGPIPE under pipefail.
  found="$(ldconfig -p 2>/dev/null | grep -m1 'libpcap\.so' || true)"
  if [[ -n "$found" ]]; then
    ok "libpcap"
  elif [[ "$(uname -s)" == "Darwin" ]]; then
    ok "libpcap (macOS system library)"
  else
    miss "libpcap (package: $(pkg_name libpcap)) - needed for naabu SYN scans"
    MISSING+=("libpcap")
    queue_pkg libpcap
  fi
}

# --------------------------------------------------------- naabu install ---
goroot_bin() {
  local gb
  gb="$(go env GOBIN 2>/dev/null)"
  [[ -z "$gb" ]] && gb="$(go env GOPATH 2>/dev/null)/bin"
  printf '%s' "$gb"
}

install_naabu_source() {
  step "Installing naabu from source (go install)"
  have go || { queue_pkg go; install_queued; }
  have go || return 1
  run go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || return 1
  local gb; gb="$(goroot_bin)"
  if [[ -x "$gb/naabu" ]] && ! have naabu; then
    info "linking $gb/naabu into /usr/local/bin"
    run_root ln -sf "$gb/naabu" /usr/local/bin/naabu || \
      say "  add $gb to your PATH to use naabu"
  fi
  (( DRY_RUN )) || have naabu
}

latest_naabu_version() {
  local v=""
  if have curl; then
    v="$(curl -fsSL --max-time 15 \
        https://api.github.com/repos/projectdiscovery/naabu/releases/latest 2>/dev/null \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)"
  fi
  [[ -z "$v" ]] && v="$NAABU_FALLBACK_VERSION"
  printf '%s' "$v"
}

install_naabu_release() {
  local os arch ver url tmp
  case "$(uname -s)" in
    Linux)  os="linux" ;;
    Darwin) os="macOS" ;;
    *)      return 1 ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) return 1 ;;
  esac
  have curl || { queue_pkg curl; install_queued; }
  have unzip || { queue_pkg unzip; install_queued; }
  have curl && have unzip || return 1

  ver="$(latest_naabu_version)"
  url="https://github.com/projectdiscovery/naabu/releases/download/v${ver}/naabu_${ver}_${os}_${arch}.zip"
  step "Installing naabu v$ver prebuilt binary"
  info "$url"
  if (( DRY_RUN )); then
    printf '  %s[dry]%s curl -fsSL %s | unzip -> /usr/local/bin/naabu\n' "$Y" "$N" "$url"
    return 0
  fi
  tmp="$(mktemp -d)" || return 1
  if ! curl -fsSL --max-time 180 -o "$tmp/naabu.zip" "$url"; then
    rm -rf "$tmp"; return 1
  fi
  unzip -q -o "$tmp/naabu.zip" -d "$tmp" || { rm -rf "$tmp"; return 1; }
  [[ -f "$tmp/naabu" ]] || { rm -rf "$tmp"; return 1; }
  chmod +x "$tmp/naabu"
  run_root install -m 0755 "$tmp/naabu" /usr/local/bin/naabu || { rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
  have naabu
}

install_naabu() {
  if (( FORCE_SOURCE )); then
    install_naabu_source && return 0
    say "  source build failed, trying a prebuilt release"
    install_naabu_release && return 0
    return 1
  fi
  if have go; then
    install_naabu_source && return 0
    say "  go install failed, trying a prebuilt release"
  fi
  install_naabu_release
}

# ------------------------------------------------------------ extra steps ---
grant_caps() {
  step "Granting cap_net_raw (rootless SYN scanning)"
  [[ "$(uname -s)" == "Linux" ]] || { miss "setcap is Linux-only, skipping"; return 0; }
  have setcap || { queue_pkg libcap2-bin; install_queued; }
  have setcap || { bad "setcap not available"; return 1; }
  local p
  for p in naabu nmap; do
    if have "$p"; then
      local real; real="$(readlink -f "$(command -v "$p")")"
      run_root setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$real" \
        && ok "$p -> $real" || bad "setcap failed for $real"
    fi
  done
}

install_extra_scripts() {
  step "Installing extra vuln NSE scripts"
  have git || { queue_pkg git; install_queued; }
  have git || { bad "git not available"; return 1; }
  local dir=""
  for d in "${NMAP_SCRIPT_DIRS[@]}"; do [[ -d "$d" ]] && { dir="$d"; break; }; done
  [[ -n "$dir" ]] || { bad "nmap scripts directory not found"; return 1; }

  if [[ -d "$dir/nmap-vulners" ]]; then
    ok "nmap-vulners already present"
  else
    run_root git clone --depth 1 -q \
      https://github.com/vulnersCom/nmap-vulners "$dir/nmap-vulners" \
      && ok "nmap-vulners -> $dir/nmap-vulners" || bad "nmap-vulners clone failed"
  fi
  if [[ -d "$dir/vulscan" ]]; then
    ok "vulscan already present"
  else
    run_root git clone --depth 1 -q \
      https://github.com/scipag/vulscan "$dir/vulscan" \
      && ok "vulscan -> $dir/vulscan" || bad "vulscan clone failed"
  fi
  if (( DRY_RUN )); then
    printf '  %s[dry]%s nmap --script-updatedb\n' "$Y" "$N"
  else
    run_root nmap --script-updatedb >/dev/null 2>&1 && ok "nmap script database updated"
  fi
  say ""
  say "  use them with:  ./nscan.sh -l ips.txt --scripts 'default,vuln,vulners'"
}

# ----------------------------------------------------------------- main ---
say "${B}nscan setup v$SETUP_VERSION${N}"
detect_pm
if [[ -n "$PM" ]]; then
  say "package manager: $PM   os: $(uname -s) $(uname -m)"
else
  say "package manager: ${Y}none detected${N} - missing deps must be installed by hand"
fi
(( CHECK_ONLY )) && say "mode: check only (no changes)"
(( DRY_RUN ))    && say "mode: dry run (commands printed, nothing executed)"

step "Checking dependencies"
check_bash
check_cmd nmap    nmap    'nmap --version | head -1'
check_cmd flock   flock
check_cmd timeout timeout
check_libpcap
if have naabu; then
  ok "naabu - $(naabu -version 2>&1 | sed -n 's/.*Current Version:[[:space:]]*//p' | head -1)"
else
  miss "naabu (installed from source or a release binary)"
  MISSING+=("naabu")
  NEED_NAABU=1
fi

if [[ ! -f "$NSCAN" ]]; then
  bad "nscan.sh not found next to setup.sh ($NSCAN)"
else
  if [[ -x "$NSCAN" ]]; then
    ok "nscan.sh is executable"
  elif (( CHECK_ONLY || DRY_RUN )); then
    miss "nscan.sh is not executable (setup would chmod +x it)"
  else
    run chmod +x "$NSCAN" && ok "nscan.sh made executable"
  fi
fi

# ------------------------------------------------------------- act on it ---
if (( ${#MISSING[@]} == 0 )); then
  step "All dependencies satisfied"
  if (( CHECK_ONLY )); then
    say "  nothing to do"
    exit 0
  fi
else
  if (( CHECK_ONLY )); then
    step "Missing: ${MISSING[*]}"
    say "  re-run without --check to install them"
    exit 1
  fi
  if [[ -z "$PM" ]] && (( ${#PM_PENDING[@]} )); then
    die "no supported package manager; install manually: ${PM_PENDING[*]}"
  fi
  confirm "Install missing dependencies (${MISSING[*]})?" || die "aborted by user"
  install_queued
  if (( NEED_NAABU )); then
    install_naabu || die "naabu install failed - see https://github.com/projectdiscovery/naabu"
    (( DRY_RUN )) || ok "naabu installed"
  fi
fi

(( DO_SETCAP ))        && grant_caps
(( DO_EXTRA_SCRIPTS )) && install_extra_scripts

# -------------------------------------------------------------- verify ---
if (( DRY_RUN )); then
  step "Dry run complete - nothing was changed"
  exit 0
fi

step "Verifying"
FAIL=0
for c in naabu nmap flock timeout; do
  if have "$c"; then ok "$c"; else bad "$c still missing"; FAIL=1; fi
done

if [[ -x "$NSCAN" ]]; then
  SAMPLE="$(mktemp)"; printf '127.0.0.1\n' > "$SAMPLE"
  if "$NSCAN" -n -l "$SAMPLE" >/dev/null 2>&1; then
    ok "nscan.sh dry run succeeded"
  else
    bad "nscan.sh dry run failed - run: $NSCAN -n -l $SAMPLE"
    FAIL=1
  fi
  rm -f "$SAMPLE"
fi

if [[ ! -f "$SCRIPT_DIR/ips.txt" ]]; then
  step "Creating a starter target list"
  cat > "$SCRIPT_DIR/ips.txt" <<'EOT'
# nscan target list - one IP, CIDR or hostname per line.
# Lines starting with # and blank lines are ignored; duplicates are collapsed.
# Scan only hosts you own or are explicitly authorised to test.
127.0.0.1
EOT
  ok "wrote $SCRIPT_DIR/ips.txt (edit it before scanning)"
fi

if (( FAIL )); then
  step "${R}Setup incomplete${N}"
  exit 1
fi

step "Setup complete"
cat <<EOT
  Next steps:
    1. edit the target list:   $SCRIPT_DIR/ips.txt
    2. preview the commands:   ./nscan.sh -n -l ips.txt
    3. run it:                 sudo ./nscan.sh -l ips.txt

  Useful flags:  --no-vuln (fast sweep)   -nj/-mj (parallelism)   -h (full help)
EOT
if [[ $(id -u) -ne 0 ]] && (( ! DO_SETCAP )); then
  say ""
  say "  Tip: SYN scanning needs root. Either use sudo, or re-run:"
  say "       sudo ./setup.sh --setcap    (grants cap_net_raw to naabu & nmap)"
fi
