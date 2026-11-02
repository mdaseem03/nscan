#!/usr/bin/env bash
#
# nscan.sh - pipelined naabu -> nmap scanner
#
#   Stage 1 (producer): naabu port-scans each IP from the list, one naabu job
#                       per host, up to --naabu-jobs hosts at a time. As soon
#                       as a host finishes, its open ports are appended to
#                       output-naabu.txt and the host is pushed onto a queue.
#   Stage 2 (consumer): picks hosts off that queue the moment they land and
#                       runs nmap (-sV + default/vuln NSE) against exactly
#                       that host's open ports, up to --nmap-jobs at a time.
#
# The two stages run concurrently: nmap on host A overlaps naabu on host B.
# Results are appended to output-nmap.txt under a lock, so parallel jobs never
# interleave their output.
#
set -uo pipefail

VERSION="1.0.0"

# ---------------------------------------------------------------- defaults ---
IP_LIST="ips.txt"
NAABU_OUT="output-naabu.txt"
NMAP_OUT="output-nmap.txt"
LOG_DIR="nscan-logs"

PORTS=""                 # -p : explicit naabu port spec (overrides TOP_PORTS)
TOP_PORTS="1000"         # naabu -top-ports (100 | 1000 | full)
NAABU_JOBS=5             # concurrent naabu host scans
NMAP_JOBS=3              # concurrent nmap host scans
NAABU_RATE=1000          # naabu packets/sec
NAABU_TIMEOUT=0          # per-host naabu wall-clock limit in s (0 = unlimited)
NMAP_TIMEOUT=0           # per-host nmap wall-clock limit in s  (0 = unlimited)
NMAP_SCRIPTS="default,vuln"
NMAP_SCRIPT_TIMEOUT="60s"  # nmap --script-timeout (caps slow NSE scripts)
NMAP_HOST_TIMEOUT="30m"    # nmap --host-timeout
NMAP_EXTRA=""            # extra raw nmap flags
SCAN_TYPE=""             # naabu -s : s (SYN) or c (CONNECT); auto by default
VULN_SCAN=1              # 0 = service/version detection only, no vuln scripts
QUIET=0
DRY_RUN=0

usage() {
  cat <<EOF
nscan.sh v$VERSION - naabu -> nmap pipeline (parallel, per-host streaming)

Usage: $0 [options] [ip-list]

Input / output:
  -l, --list FILE        file with one IP/CIDR/host per line (default: $IP_LIST)
      --naabu-out FILE   naabu results file   (default: $NAABU_OUT)
      --nmap-out FILE    nmap results file    (default: $NMAP_OUT)
      --log-dir DIR      per-host raw logs    (default: $LOG_DIR)

Ports:
  -p,  --ports SPEC      naabu port spec, e.g. 80,443,8000-9000 (overrides -tp)
  -tp, --top-ports N     naabu top ports: 100 | 1000 | full (default: $TOP_PORTS)

Parallelism / rate:
  -nj, --naabu-jobs N    concurrent naabu host scans (default: $NAABU_JOBS)
  -mj, --nmap-jobs N     concurrent nmap host scans  (default: $NMAP_JOBS)
       --rate N          naabu packets per second    (default: $NAABU_RATE)
  -s,  --scan-type s|c   naabu SYN (s, needs root) or CONNECT (c); auto-detected
       --naabu-timeout S kill a host's naabu after S seconds (0 = off)
       --nmap-timeout S  kill a host's nmap after S seconds  (0 = off)

nmap behaviour:
       --scripts LIST    nmap --script value (default: $NMAP_SCRIPTS)
       --no-vuln         skip vuln scripts, run -sV with default scripts only
       --script-timeout T nmap --script-timeout (default: $NMAP_SCRIPT_TIMEOUT)
       --host-timeout T  nmap --host-timeout  (default: $NMAP_HOST_TIMEOUT)
       --nmap-extra ".." extra flags passed straight to nmap (e.g. "-O -T3")

Note: the "vuln" NSE category is thorough but slow - budget minutes per open
port. Use --no-vuln for a quick service sweep, or cap it with --nmap-timeout.

Misc:
  -q, --quiet            only warnings/errors on stderr
  -n, --dry-run          print what would run, scan nothing
  -h, --help             this help

Examples:
  $0 -l targets.txt
  $0 -l targets.txt -p 1-65535 -nj 10 -mj 5
  $0 -l targets.txt --no-vuln --nmap-extra "-T4 --version-intensity 5"
EOF
}

# ------------------------------------------------------------------- args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -l|--list)          IP_LIST="${2:?}"; shift 2 ;;
    --naabu-out)        NAABU_OUT="${2:?}"; shift 2 ;;
    --nmap-out)         NMAP_OUT="${2:?}"; shift 2 ;;
    --log-dir)          LOG_DIR="${2:?}"; shift 2 ;;
    -p|--ports)         PORTS="${2:?}"; shift 2 ;;
    -tp|--top-ports)    TOP_PORTS="${2:?}"; shift 2 ;;
    -nj|--naabu-jobs)   NAABU_JOBS="${2:?}"; shift 2 ;;
    -mj|--nmap-jobs)    NMAP_JOBS="${2:?}"; shift 2 ;;
    --rate)             NAABU_RATE="${2:?}"; shift 2 ;;
    -s|--scan-type)     SCAN_TYPE="${2:?}"; shift 2 ;;
    --naabu-timeout)    NAABU_TIMEOUT="${2:?}"; shift 2 ;;
    --nmap-timeout)     NMAP_TIMEOUT="${2:?}"; shift 2 ;;
    --scripts)          NMAP_SCRIPTS="${2:?}"; shift 2 ;;
    --script-timeout)   NMAP_SCRIPT_TIMEOUT="${2:?}"; shift 2 ;;
    --host-timeout)     NMAP_HOST_TIMEOUT="${2:?}"; shift 2 ;;
    --no-vuln)          VULN_SCAN=0; shift ;;
    --nmap-extra)       NMAP_EXTRA="${2:?}"; shift 2 ;;
    -q|--quiet)         QUIET=1; shift ;;
    -n|--dry-run)       DRY_RUN=1; shift ;;
    -h|--help)          usage; exit 0 ;;
    -*)                 echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *)                  IP_LIST="$1"; shift ;;
  esac
done

# ------------------------------------------------------------------- utils ---
ts()   { date '+%Y-%m-%d %H:%M:%S'; }
log()  { (( QUIET )) || printf '[%s] %s\n' "$(ts)" "$*" >&2; }
warn() { printf '[%s] WARN  %s\n' "$(ts)" "$*" >&2; }
die()  { printf '[%s] ERROR %s\n' "$(ts)" "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found in PATH"; }
slug() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }

# pool_wait <max> <pid-array-name>
# Blocks until fewer than <max> of the tracked background jobs are alive,
# pruning reaped pids from the array. Used to cap each stage's concurrency.
pool_wait() {
  local _max="$1" _fin _p _tmp
  local -n _pids="$2"
  while (( ${#_pids[@]} >= _max )); do
    _fin=""
    wait -n -p _fin "${_pids[@]}" 2>/dev/null
    if [[ -n "$_fin" ]]; then
      _tmp=()
      for _p in "${_pids[@]}"; do [[ "$_p" == "$_fin" ]] || _tmp+=("$_p"); done
      _pids=("${_tmp[@]}")
    else
      _pids=()            # nothing left alive to wait for
    fi
  done
}

# --------------------------------------------------------------- preflight ---
need naabu
need nmap
[[ -r "$IP_LIST" ]] || die "cannot read IP list: $IP_LIST"

for v in NAABU_JOBS NMAP_JOBS NAABU_RATE NAABU_TIMEOUT NMAP_TIMEOUT; do
  [[ ${!v} =~ ^[0-9]+$ ]] || die "$v must be an integer (got '${!v}')"
done
(( NAABU_JOBS > 0 )) || die "--naabu-jobs must be >= 1"
(( NMAP_JOBS  > 0 )) || die "--nmap-jobs must be >= 1"

# SYN scanning needs raw sockets; fall back to connect scan when unprivileged.
if [[ -z "$SCAN_TYPE" ]]; then
  if [[ $(id -u) -eq 0 ]]; then SCAN_TYPE="s"; else SCAN_TYPE="c"; fi
fi
if [[ $(id -u) -ne 0 ]]; then
  [[ "$SCAN_TYPE" == "s" ]] && \
    warn "SYN scan needs root; naabu will likely fail (use '-s c' or run via sudo)"
  warn "not running as root: nmap -sV / NSE results will be less complete"
fi

(( VULN_SCAN )) || NMAP_SCRIPTS="default"

# Normalise the target list: drop comments, blanks and stray whitespace; dedupe.
mapfile -t TARGETS < <(
  sed -e 's/#.*//' -e 's/[[:space:]]//g' "$IP_LIST" | grep -v '^$' | awk '!seen[$0]++'
)
(( ${#TARGETS[@]} > 0 )) || die "no targets found in $IP_LIST"

# naabu port selection
if [[ -n "$PORTS" ]]; then
  NAABU_PORT_ARGS=(-p "$PORTS")
else
  NAABU_PORT_ARGS=(-top-ports "$TOP_PORTS")
fi

# ----------------------------------------------------------------- dry run ---
if (( DRY_RUN )); then
  echo "targets (${#TARGETS[@]}): ${TARGETS[*]}"
  echo "naabu : naabu -host <IP> ${NAABU_PORT_ARGS[*]} -s $SCAN_TYPE -Pn -rate $NAABU_RATE -silent -duc -no-stdin -o <per-host-log>"
  echo "nmap  : nmap -Pn -sV --script $NMAP_SCRIPTS --script-timeout $NMAP_SCRIPT_TIMEOUT --host-timeout $NMAP_HOST_TIMEOUT -p <open-ports> ${NMAP_EXTRA:+$NMAP_EXTRA }-oN <per-host-log> -v0 <IP>"
  echo "jobs  : naabu=$NAABU_JOBS  nmap=$NMAP_JOBS"
  echo "out   : $NAABU_OUT, $NMAP_OUT, per-host logs in $LOG_DIR/"
  exit 0
fi

mkdir -p "$LOG_DIR" || die "cannot create log dir: $LOG_DIR"
: >> "$NAABU_OUT" || die "cannot write $NAABU_OUT"
: >> "$NMAP_OUT"  || die "cannot write $NMAP_OUT"

RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nscan.XXXXXX")" || die "mktemp failed"
QUEUE="$RUN_DIR/queue.fifo"        # naabu -> nmap handoff
NAABU_LOCK="$RUN_DIR/naabu.lock"   # serialises appends to $NAABU_OUT
NMAP_LOCK="$RUN_DIR/nmap.lock"     # serialises appends to $NMAP_OUT
mkfifo "$QUEUE" || die "mkfifo failed"
: > "$NAABU_LOCK"; : > "$NMAP_LOCK"

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  pkill -P $$ >/dev/null 2>&1          # stop any scan still running
  [[ -n "${RUN_DIR:-}" && -d "$RUN_DIR" ]] && rm -rf "$RUN_DIR"
  exit $rc
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- stage 1 ---
# naabu for one host -> append to $NAABU_OUT -> push "ip<TAB>ports" to the queue
scan_host_naabu() {
  local ip="$1" safe raw rc ports=""
  safe="$(slug "$ip")"
  raw="$LOG_DIR/naabu-$safe.txt"
  local cmd=(naabu -host "$ip" "${NAABU_PORT_ARGS[@]}"
             -s "$SCAN_TYPE" -Pn -rate "$NAABU_RATE"
             -silent -duc -no-stdin -o "$raw")

  log "naabu  START  $ip"
  if (( NAABU_TIMEOUT > 0 )); then
    timeout --kill-after=15s "${NAABU_TIMEOUT}s" "${cmd[@]}" \
      >"$LOG_DIR/naabu-$safe.log" 2>&1
  else
    "${cmd[@]}" >"$LOG_DIR/naabu-$safe.log" 2>&1
  fi
  rc=$?
  if (( rc == 124 || rc == 137 )); then
    warn "naabu timed out on $ip after ${NAABU_TIMEOUT}s"
  elif (( rc != 0 )); then
    warn "naabu exited $rc on $ip (see $LOG_DIR/naabu-$safe.log)"
  fi

  # naabu -silent writes one "host:port" per line.
  if [[ -s "$raw" ]]; then
    ports="$(awk -F: 'NF>1 && $NF ~ /^[0-9]+$/ {print $NF}' "$raw" \
             | sort -n -u | paste -sd, -)"
  fi

  if [[ -z "$ports" ]]; then
    log "naabu  DONE   $ip - no open ports"
    ( flock 9; printf '# %s  %s  no open ports\n' "$(ts)" "$ip" >> "$NAABU_OUT"
    ) 9>>"$NAABU_LOCK"
    return 0
  fi

  # Append this host's block; the lock keeps parallel jobs from interleaving.
  ( flock 9
    { printf '# %s  %s  open: %s\n' "$(ts)" "$ip" "$ports"; cat "$raw"; } \
      >> "$NAABU_OUT"
    printf '%s\n' "$ip" >> "$RUN_DIR/hosts-open"
  ) 9>>"$NAABU_LOCK"

  log "naabu  DONE   $ip -> $ports  (queued for nmap)"
  # Hand off right now; one short write, atomic on a pipe.
  printf '%s\t%s\n' "$ip" "$ports" >&3
}

# ---------------------------------------------------------------- stage 2 ---
scan_host_nmap() {
  local ip="$1" ports="$2" safe raw rc
  safe="$(slug "$ip")"
  raw="$LOG_DIR/nmap-$safe.txt"
  local cmd=(nmap -Pn -sV --script "$NMAP_SCRIPTS"
             --script-timeout "$NMAP_SCRIPT_TIMEOUT"
             --host-timeout "$NMAP_HOST_TIMEOUT"
             -p "$ports")
  # word-split on purpose: user-supplied extra nmap flags
  # shellcheck disable=SC2206
  [[ -n "$NMAP_EXTRA" ]] && cmd+=($NMAP_EXTRA)
  cmd+=(-oN "$raw" -v0 "$ip")

  log "nmap   START  $ip  ports=$ports"
  if (( NMAP_TIMEOUT > 0 )); then
    timeout --kill-after=30s "${NMAP_TIMEOUT}s" "${cmd[@]}" \
      >"$LOG_DIR/nmap-$safe.log" 2>&1
  else
    "${cmd[@]}" >"$LOG_DIR/nmap-$safe.log" 2>&1
  fi
  rc=$?
  if (( rc == 124 || rc == 137 )); then
    warn "nmap timed out on $ip after ${NMAP_TIMEOUT}s"
  elif (( rc != 0 )); then
    warn "nmap exited $rc on $ip (see $LOG_DIR/nmap-$safe.log)"
  fi

  ( flock 9
    {
      printf '\n%s\n' "======================================================================"
      printf '== %s  host: %s  ports: %s\n' "$(ts)" "$ip" "$ports"
      printf '%s\n' "======================================================================"
      if [[ -s "$raw" ]]; then cat "$raw"; else echo "(no nmap output produced)"; fi
    } >> "$NMAP_OUT"
    printf '%s\n' "$ip" >> "$RUN_DIR/hosts-nmap"
  ) 9>>"$NMAP_LOCK"

  log "nmap   DONE   $ip"
}

# ------------------------------------------------------------------ run it ---
START_EPOCH=$(date +%s)
log "nscan v$VERSION: ${#TARGETS[@]} target(s), naabu-jobs=$NAABU_JOBS, nmap-jobs=$NMAP_JOBS, scan-type=$SCAN_TYPE, ports=${PORTS:-top-$TOP_PORTS}"

HEADER="$(printf '\n### nscan run %s | targets=%d | ports=%s | scan-type=%s' \
  "$(ts)" "${#TARGETS[@]}" "${PORTS:-top-$TOP_PORTS}" "$SCAN_TYPE")"
printf '%s\n' "$HEADER" >> "$NAABU_OUT"
printf '%s\n' "$HEADER" >> "$NMAP_OUT"

# Hold the queue open read-write in this shell, so the consumer sees EOF only
# once the naabu stage is really finished - not merely idle between hosts.
exec 3<>"$QUEUE"

# --- stage 2: nmap consumer, started first so it is already on the queue
(
  exec 3>&-                           # must not hold the queue's write end
  exec 6<"$QUEUE"                     # read-only end for this subshell
  NMAP_PIDS=()
  while IFS=$'\t' read -r ip ports <&6; do
    [[ -n "$ip" && -n "$ports" ]] || continue
    pool_wait "$NMAP_JOBS" NMAP_PIDS
    scan_host_nmap "$ip" "$ports" &
    NMAP_PIDS+=("$!")
  done
  (( ${#NMAP_PIDS[@]} )) && wait "${NMAP_PIDS[@]}"   # finish in-flight nmap jobs
  exit 0
) &
CONSUMER_PID=$!

# --- stage 1: naabu producer
NAABU_PIDS=()
for ip in "${TARGETS[@]}"; do
  pool_wait "$NAABU_JOBS" NAABU_PIDS
  scan_host_naabu "$ip" &
  NAABU_PIDS+=("$!")
done
(( ${#NAABU_PIDS[@]} )) && wait "${NAABU_PIDS[@]}" 2>/dev/null
log "naabu stage complete; waiting for remaining nmap jobs"

exec 3>&-                             # last write end gone -> consumer hits EOF
wait "$CONSUMER_PID" 2>/dev/null || true

ELAPSED=$(( $(date +%s) - START_EPOCH ))
N_OPEN=$(wc -l < "$RUN_DIR/hosts-open" 2>/dev/null | tr -d ' '); N_OPEN=${N_OPEN:-0}
N_NMAP=$(wc -l < "$RUN_DIR/hosts-nmap" 2>/dev/null | tr -d ' '); N_NMAP=${N_NMAP:-0}
log "done in ${ELAPSED}s - ${#TARGETS[@]} target(s) scanned, $N_OPEN with open ports, $N_NMAP nmap'd"
log "naabu results : $NAABU_OUT"
log "nmap results  : $NMAP_OUT"
log "per-host logs : $LOG_DIR/"
