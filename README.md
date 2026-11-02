<h1 align="center">nscan</h1>

<p align="center">
  <b>Pipelined <a href="https://github.com/projectdiscovery/naabu">naabu</a> → <a href="https://nmap.org">nmap</a> scanning.</b><br>
  Fast port discovery across a host list, with service &amp; vulnerability scans<br>
  kicked off <i>per host, the moment that host's ports are known</i> — not after the whole sweep.
</p>

<p align="center">
  <img alt="shell" src="https://img.shields.io/badge/shell-bash%205.0%2B-4EAA25?logo=gnubash&logoColor=white">
  <img alt="requires" src="https://img.shields.io/badge/requires-naabu%20%7C%20nmap-0A7BBB">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-blue">
</p>

---

## Why

The usual way to chain these tools is sequential: run naabu over every target, wait, then feed the
results to nmap. On a list of any size, nmap sits idle for the entire discovery phase.

`nscan.sh` runs both stages **at the same time**. Each host is handed to nmap as soon as its own
naabu scan finishes, so deep service and vulnerability scanning on host A overlaps port discovery
on hosts B, C, D…

```
  ips.txt
     │
     ├─ naabu 127.0.0.1 ──┐                          append  ┌──────────────────┐
     ├─ naabu 10.0.0.7  ──┼──▶ output-naabu.txt ◀────────────┤ naabu job pool   │
     ├─ naabu 10.0.0.8  ──┘                                  │  (-nj, default 5)│
     │        │                                              └──────────────────┘
     │        │ host done → ip + open ports
     │        ▼
     │   ┌─────────────┐   pops immediately    ┌──────────────────┐
     │   │  FIFO queue │ ────────────────────▶ │ nmap job pool    │
     │   └─────────────┘                       │  (-mj, default 3)│
     │                                         └─────────┬────────┘
     └─ still scanning the rest, in parallel              │ append
                                                          ▼
                                                   output-nmap.txt
```

## Features

- **True two-stage parallelism** — naabu and nmap pools run concurrently, each with its own
  independent concurrency cap.
- **Streaming handoff** — a host reaches nmap the second its ports are known, via a FIFO queue.
- **Targeted nmap** — scans only the ports naabu actually found open on *that* host.
- **Clean concurrent output** — every append to the result files is `flock`-serialised, so parallel
  jobs never interleave their output mid-line.
- **Per-host raw logs** — each naabu/nmap run also keeps its own file under `nscan-logs/`.
- **Deterministic job pools** — pid-tracked (`wait -n -p`), not job-count guesswork.
- **Safety rails** — optional per-host wall-clock timeouts for both stages, plus nmap
  `--script-timeout` / `--host-timeout` caps.
- **Privilege aware** — SYN scan when root, automatic fallback to connect scan otherwise, with a
  warning instead of a silent empty result.
- **Tidy input handling** — comments, blank lines, stray whitespace and duplicates in the target
  list are all handled.
- **`--dry-run`** — print the exact commands that would run, scan nothing.

## Requirements

| Tool | Notes |
|---|---|
| `bash` ≥ 5.0 | uses `wait -n -p`, namerefs, `mapfile` |
| `naabu` | port discovery stage |
| `nmap` | service / NSE stage |
| `flock`, `timeout` | from `util-linux` / `coreutils` |
| root *(recommended)* | SYN scanning and complete `-sV` / NSE results |

## Install

`setup.sh` checks every dependency, installs what is missing, and verifies the result:

```bash
git clone <your-repo> nscan && cd nscan
chmod +x setup.sh
sudo ./setup.sh
```

```
==> Checking dependencies
  [ ok ] bash 5.2.37(1)-release
  [ ok ] nmap - Nmap version 7.95 ( https://nmap.org )
  [ ok ] flock
  [ ok ] timeout
  [ ok ] libpcap
  [miss] naabu (installed from source or a release binary)
==> Installing naabu from source (go install)
==> Verifying
  [ ok ] nscan.sh dry run succeeded
==> Setup complete
```

It detects `apt`, `dnf`, `yum`, `pacman`, `zypper`, `apk` or `brew`, installs naabu with
`go install` (falling back to the matching prebuilt release binary if Go is absent), `chmod +x`es
`nscan.sh`, writes a starter `ips.txt`, and finishes with a real `nscan.sh` dry run.

| Option | Description |
|---|---|
| `-c`, `--check` | audit only — report what is present/missing, change nothing |
| `-n`, `--dry-run` | print the exact install commands, execute nothing |
| `-y`, `--yes` | never prompt (CI / provisioning) |
| `--setcap` | grant `cap_net_raw` to naabu & nmap so SYN scans work without `sudo` |
| `--extra-scripts` | also install the `nmap-vulners` and `vulscan` NSE scripts |
| `--from-source` | build naabu with `go install` even if a release binary would do |
| `-h`, `--help` | help |

```bash
./setup.sh --check              # audit an existing box
./setup.sh -n                   # see the commands first
sudo ./setup.sh -y --setcap     # unattended, rootless SYN afterwards
sudo ./setup.sh --extra-scripts # add nmap-vulners + vulscan
```

<details>
<summary>Manual install instead</summary>

```bash
# Debian / Ubuntu / Kali
sudo apt install -y nmap util-linux coreutils libpcap-dev
# naabu
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
chmod +x nscan.sh
```
</details>

## Quick start

```bash
sudo ./setup.sh            # one-time: install & verify dependencies

# one target per line
cat > ips.txt <<'EOF'
192.168.1.10
192.168.1.0/24      # CIDR works too
scanme.example.com  # so do hostnames
EOF

sudo ./nscan.sh -l ips.txt
```

```
[2026-11-02 23:12:45] nscan v1.0.0: 4 target(s), naabu-jobs=2, nmap-jobs=2, scan-type=s
[2026-11-02 23:12:45] naabu  START  127.0.0.1
[2026-11-02 23:12:45] naabu  START  127.0.0.2
[2026-11-02 23:12:47] naabu  DONE   127.0.0.1 -> 8081  (queued for nmap)
[2026-11-02 23:12:47] nmap   START  127.0.0.1  ports=8081      ← nmap running while…
[2026-11-02 23:12:47] naabu  START  127.0.0.3                  ← …naabu scans the rest
[2026-11-02 23:12:54] nmap   DONE   127.0.0.1
[2026-11-02 23:12:54] nmap   START  127.0.0.3  ports=8083      ← waited for a free slot
[2026-11-02 23:13:01] done in 16s - 4 target(s) scanned, 3 with open ports, 3 nmap'd
```

## Usage

```
./nscan.sh [options] [ip-list]
```

### Input / output

| Option | Default | Description |
|---|---|---|
| `-l`, `--list FILE` | `ips.txt` | file with one IP / CIDR / hostname per line |
| `--naabu-out FILE` | `output-naabu.txt` | naabu results (appended) |
| `--nmap-out FILE` | `output-nmap.txt` | nmap results (appended) |
| `--log-dir DIR` | `nscan-logs` | per-host raw naabu & nmap logs |

### Ports

| Option | Default | Description |
|---|---|---|
| `-p`, `--ports SPEC` | — | explicit naabu port spec, e.g. `80,443,8000-9000` (overrides `-tp`) |
| `-tp`, `--top-ports N` | `1000` | naabu top ports: `100`, `1000` or `full` |

### Parallelism & rate

| Option | Default | Description |
|---|---|---|
| `-nj`, `--naabu-jobs N` | `5` | concurrent naabu host scans |
| `-mj`, `--nmap-jobs N` | `3` | concurrent nmap host scans |
| `--rate N` | `1000` | naabu packets per second |
| `-s`, `--scan-type s\|c` | auto | naabu SYN (`s`, needs root) or CONNECT (`c`) |
| `--naabu-timeout S` | `0` (off) | kill a host's naabu after S seconds |
| `--nmap-timeout S` | `0` (off) | kill a host's nmap after S seconds |

### nmap behaviour

| Option | Default | Description |
|---|---|---|
| `--scripts LIST` | `default,vuln` | value passed to nmap `--script` |
| `--no-vuln` | — | drop vuln scripts; `-sV` + default scripts only |
| `--script-timeout T` | `60s` | nmap `--script-timeout` |
| `--host-timeout T` | `30m` | nmap `--host-timeout` |
| `--nmap-extra "…"` | — | extra raw nmap flags, e.g. `"-O -T4"` |

### Misc

| Option | Description |
|---|---|
| `-q`, `--quiet` | warnings and errors only |
| `-n`, `--dry-run` | print the commands that would run, scan nothing |
| `-h`, `--help` | help |

## Examples

```bash
# full TCP range, wide open throttles
sudo ./nscan.sh -l targets.txt -p 1-65535 -nj 10 -mj 5

# fast service sweep, no vuln scripts
sudo ./nscan.sh -l targets.txt --no-vuln

# quiet, bounded run suitable for cron
sudo ./nscan.sh -l targets.txt -q --naabu-timeout 120 --nmap-timeout 600

# web ports only, extra nmap flags, custom script set
sudo ./nscan.sh -l targets.txt -p 80,443,8080,8443 \
  --scripts "default,vuln,http-enum" --nmap-extra "-T4 --version-intensity 5"

# unprivileged connect scan
./nscan.sh -l targets.txt -s c -tp 100

# see what would happen first
./nscan.sh -n -l targets.txt
```

## Output format

**`output-naabu.txt`** — a run header, then one commented block per host followed by its raw
`host:port` lines:

```
### nscan run 2026-11-02 23:12:45 | targets=4 | ports=22,80,8081-8083 | scan-type=s
# 2026-11-02 23:12:47  127.0.0.1  open: 8081
127.0.0.1:8081
# 2026-11-02 23:12:50  192.0.2.1  no open ports
# 2026-11-02 23:12:50  127.0.0.3  open: 8083
127.0.0.3:8083
```

The `host:port` lines are left machine-readable on purpose:

```bash
grep -v '^[#]' output-naabu.txt | grep ':' | sort -u   # just the open ports
```

**`output-nmap.txt`** — one banner-delimited block per host, holding that host's full nmap report:

```
======================================================================
== 2026-11-02 23:12:54  host: 127.0.0.1  ports: 8081
======================================================================
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00010s latency).

PORT     STATE SERVICE VERSION
8081/tcp open  http    SimpleHTTPServer 0.6 (Python 3.13.9)
|_http-title: Directory listing for /
|_http-server-header: SimpleHTTP/0.6 Python/3.13.9
```

Both files are **appended** to, so repeated runs accumulate under their own run headers.

## How it works

1. The target list is normalised: comments stripped, blanks dropped, duplicates removed.
2. A FIFO queue is created, plus two lock files — one per output file.
3. The **nmap consumer** starts first and blocks on the queue, so it is ready before the first
   host lands.
4. The **naabu producer** walks the target list, launching one `naabu -host <ip>` per target and
   capping itself at `-nj` live jobs. Each job: writes its own log, derives the sorted unique port
   list, appends its block to `output-naabu.txt` under `flock`, then pushes `ip<TAB>ports` onto the
   queue in a single atomic write.
5. The consumer pops each host immediately and runs nmap against exactly those ports, capped at
   `-mj` live jobs, appending each report under the second lock.
6. The main shell holds the queue's write end open for the whole producer stage, so the consumer
   reaches EOF only when discovery is genuinely finished — never while merely idle between hosts.
7. On exit (including `Ctrl-C`), a trap kills in-flight children and removes the scratch directory.

## Notes & caveats

- **`vuln` is slow.** The NSE `vuln` category is thorough but expensive — budget minutes per open
  port (in testing, one HTTP port took ~76s even with `--script-timeout 45s`). Use `--no-vuln` for
  a quick sweep, or bound it with `--nmap-timeout`.
- **SYN needs root.** Without root, `nscan` falls back to a connect scan and warns that `-sV` and
  NSE results will be less complete.
- **Mind the rate.** `--rate` and `-nj` multiply. Dial both down on fragile networks, or you will
  trip IDS/rate limits and get false negatives.
- **Tune the pools to the work.** `-nj` is network-bound and cheap; `-mj` is CPU/NSE-bound. Raising
  `-mj` far past your core count mostly adds contention.
- `--nmap-extra` is intentionally word-split so you can pass multiple flags; quote it as one
  argument.

## Legal

For use **only** against systems you own or have explicit written authorisation to test.
Unauthorised port and vulnerability scanning is illegal in most jurisdictions. You are responsible
for how you use this.

## License

MIT
