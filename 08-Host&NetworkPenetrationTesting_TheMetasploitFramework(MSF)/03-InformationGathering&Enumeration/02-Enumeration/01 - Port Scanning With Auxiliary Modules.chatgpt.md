# Port Scanning With Auxiliary Modules (eJPT)

Note: The transcript is not provided. The following is a conservative, experience-based summary for a typical eJPT “Enumeration” lesson titled “Port Scanning With Auxiliary Modules,” focusing on Metasploit auxiliary port-scanner modules. Commands and module names reflect common, current Metasploit usage; always run show options to verify on your version.

## What the video covers (Introduction / big picture)
- Why and when to use Metasploit’s auxiliary port-scanning modules during enumeration.
- Differences between TCP connect vs SYN vs ACK vs XMAS scans and when each is useful.
- How to run scans against single hosts or subnets, tune performance, and run as root when needed.
- How results are stored in Metasploit’s database and how to query/export them for follow-up.
- Quick comparison with db_nmap integration.

## Flow (ordered)
1. Start Metasploit with database enabled and set a workspace.
2. Discover available port-scanning auxiliary modules.
3. Run a fast TCP connect scan for initial coverage.
4. Run a SYN scan for faster/stealthier results (requires root/capabilities).
5. Use ACK and XMAS scans to probe firewall filtering behavior.
6. Narrow targets and ports as needed; tune THREADS and timeouts conservatively.
7. Review results via services/hosts; pivot RHOSTS to interesting services.
8. Export results or cross-check with db_nmap if desired.

## Tools highlighted
- Metasploit Framework (msfconsole)
  - auxiliary/scanner/portscan/tcp
  - auxiliary/scanner/portscan/syn
  - auxiliary/scanner/portscan/ack
  - auxiliary/scanner/portscan/xmas
- Metasploit database commands: workspace, services, hosts, notes, db_export
- Optional: db_nmap integration for Nmap scans stored directly in the MSF DB

## Typical command walkthrough (detailed, copy-paste friendly)
Tip: Run Metasploit with sudo for SYN scans (raw sockets). Replace target ranges/ports with your lab values.

```bash
# 0) Launch Metasploit (quiet) with root privileges for SYN scans
sudo msfconsole -q
```

```bash
# 1) Use a dedicated workspace
workspace -a enum_lab
workspace enum_lab

# Optional: log everything
spool msf-enum.log
```

```bash
# 2) Set common globals (edit to your lab)
setg RHOSTS 10.10.10.0/24
setg THREADS 50
setg VERBOSE true
```

```bash
# 3) Discover available portscan modules
search type:auxiliary portscan

# Example output (module names you’ll use):
# auxiliary/scanner/portscan/tcp
# auxiliary/scanner/portscan/syn
# auxiliary/scanner/portscan/ack
# auxiliary/scanner/portscan/xmas
```

```bash
# 4) TCP connect scan (reliable; does not require root)
use auxiliary/scanner/portscan/tcp
show options
set PORTS 1-1000
# Optional speed/precision tuning (validate on show options)
# set TIMEOUT 1000   # ms per connection (only if option exists on your version)
# set DELAY 0        # ms between connections per thread (if available)
run

# View discovered services
services
```

```bash
# 5) SYN scan (faster/stealthier; requires root or CAP_NET_RAW)
use auxiliary/scanner/portscan/syn
show options
set PORTS 1-1000
run

# Quick check for web ports and prep RHOSTS for follow-up modules
services -p 80,443
services -p 80,443 -R   # sets RHOSTS to hosts with HTTP/HTTPS discovered
```

```bash
# 6) ACK scan (probe firewall state; identifies unfiltered vs filtered)
use auxiliary/scanner/portscan/ack
show options
set PORTS 1-1000
run
```

```bash
# 7) XMAS scan (fingerprints filtering; noisy on IDS—use only where allowed)
use auxiliary/scanner/portscan/xmas
show options
set PORTS 1-1000
run
```

```bash
# 8) Narrow scans to high-value ports for speed
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.10.5
set PORTS 21,22,80,139,445,3306,3389
run
```

```bash
# 9) Manage targets via files (supported on most MSF builds)
# RHOSTS can ingest a file list:
set RHOSTS file:/tmp/targets.txt
run
```

```bash
# 10) Review and export results
hosts
services

# Export CSV for notes/reporting
services -o services.csv
hosts -o hosts.csv

# Optional: export entire DB in a format your MSF supports
# db_export -f xml -a msf-db.xml
# db_export -f json -a msf-db.json
```

```bash
# 11) Optional cross-check with Nmap via Metasploit DB (stores results automatically)
# Use -sT if not root; -sS for SYN if root
db_nmap -Pn -n -sT -p- 10.10.10.0/24

# Re-check results in the DB
services
```

```bash
# 12) Cleanup
spool off
exit
```

## Practical tips
- TCP vs SYN:
  - TCP (portscan/tcp) is reliable and unprivileged; slightly slower and noisier.
  - SYN (portscan/syn) is faster/stealthier but requires root/capabilities.
- ACK/XMAS scans:
  - Use to understand firewall behavior (filtered vs unfiltered) rather than to confirm “open” in the classic sense.
- Performance tuning:
  - THREADS 50 is a safe starting point on lab ranges; increase cautiously to avoid drops.
  - Restrict PORTS to likely services after your first pass to speed up subsequent scans.
- Data handling:
  - Leverage services -p <port> -R to set RHOSTS for follow-on modules.
  - Keep results in a dedicated workspace; export CSV for quick triage.
- Permissions:
  - For SYN scans, run msfconsole with sudo or ensure the Ruby process has CAP_NET_RAW.
- Validation:
  - Always run show options to confirm available parameters on your MSF version.
- Scope:
  - Only scan in authorized lab ranges; ACK/XMAS can trigger detection in monitored networks.

## Minimal cheat sheet (one-screen flow)
```bash
# Start and set workspace
sudo msfconsole -q
workspace -a enum_lab
setg RHOSTS 10.10.10.0/24
setg THREADS 50

# TCP scan (no root needed)
use auxiliary/scanner/portscan/tcp
set PORTS 1-1000
run

# SYN scan (root needed)
use auxiliary/scanner/portscan/syn
set PORTS 1-1000
run

# ACK/XMAS (firewall probing)
use auxiliary/scanner/portscan/ack
set PORTS 1-1000
run
use auxiliary/scanner/portscan/xmas
set PORTS 1-1000
run

# Review/export
services
services -p 80,443 -R
services -o services.csv
hosts -o hosts.csv

# Optional Nmap via MSF DB
db_nmap -Pn -n -sT -p- 10.10.10.0/24
```

## Summary
This lesson demonstrates using Metasploit’s auxiliary port-scanning modules to enumerate hosts and services directly within the framework. You learn when to choose TCP vs SYN vs ACK/XMAS scans, how to tune and scope scans, and how to capture and reuse results via the Metasploit database. The workflow pairs well with db_nmap for verification and gives you a fast, DB-driven path from discovery to targeted service testing in eJPT labs.