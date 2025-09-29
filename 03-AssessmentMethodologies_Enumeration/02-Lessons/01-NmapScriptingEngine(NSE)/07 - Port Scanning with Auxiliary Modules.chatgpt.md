# 07 - Port Scanning with Auxiliary Modules

Note: No transcript was provided. Based on the filename and common eJPT workflows, this summary infers that the video demonstrates doing port scans using Metasploit Framework auxiliary modules (tcp/syn/ack), likely contrasting them with Nmap’s scans and how to capture results in the MSF database. Where exact flags/options are uncertain from the title alone, I’ve kept recommendations conservative and standard.

## What the video covers (Introduction / big picture)
- How to perform port scanning using Metasploit Framework auxiliary scanner modules.
- When to choose TCP connect vs SYN vs ACK scans.
- Tuning scan scope, speed, and permissions (root vs non-root).
- Capturing and reviewing results using Metasploit’s database (hosts/services).
- Quick comparison/hand-off to Nmap where useful (e.g., UDP or verification).
- Practical, eJPT-friendly workflow you can copy/paste.

## Flow (ordered)
1. Start Metasploit and (optionally) set up a workspace.
2. Choose a port scan technique (tcp/syn/ack) based on access and stealth needs.
3. Set RHOSTS, PORTS, and THREADS (and any other relevant options).
4. Run the scan and monitor output.
5. Review results with services/hosts and refine next steps.
6. Optionally verify or complement with Nmap scans.
7. Save/export findings and proceed to service-specific enumeration.

## Tools highlighted
- Metasploit Framework (msfconsole)
  - auxiliary/scanner/portscan/tcp (full connect scan; works without root)
  - auxiliary/scanner/portscan/syn (SYN scan; requires root/cap_net_raw)
  - auxiliary/scanner/portscan/ack (firewall mapping; open vs filtered inference)
  - Database helpers: workspace, hosts, services
- Nmap (for comparison/verification)
  - -sS, -sT, -sA, -sU, -p- / -p, -T, -Pn, -n
  - Optional NSE basics for discovery/enumeration

## Typical command walkthrough (detailed, copy-paste friendly)

Initial setup
```
msfconsole -q
workspace -a eJPT-scan
workspace eJPT-scan
db_status
```

TCP connect port scan (no root needed; reliable, a bit noisier)
```
use auxiliary/scanner/portscan/tcp
show options
set RHOSTS 10.10.10.0/24
set PORTS 1-1000,1433,3306,3389,8080,8443
set THREADS 100
run
```

SYN port scan (faster/stealthier; requires root or CAP_NET_RAW)
```
use auxiliary/scanner/portscan/syn
show options
set RHOSTS 10.10.10.0/24
set PORTS 1-1000,1433,3306,3389,8080,8443
set THREADS 100
run
```

ACK scan (firewall rule mapping; does not tell “open”, tells “unfiltered/filtered”)
```
use auxiliary/scanner/portscan/ack
show options
set RHOSTS 10.10.10.0/24
set PORTS 1-1000,1433,3306,3389,8080,8443
set THREADS 100
run
```

Review and filter results in the MSF database
```
hosts
services
services -p 80
services -p 3389
```

Set globals to reuse target scope across modules
```
setg RHOSTS 10.10.10.0/24
```

Optionally: verify/augment with Nmap (examples)
```
# Quick TCP top ports with service detection (single host)
sudo nmap -sS -sV -Pn -n --top-ports 1000 -T4 10.10.10.10

# Full TCP sweep (can be slow)
sudo nmap -sS -p- -T4 -Pn -n --min-rate 2000 10.10.10.10

# UDP top ports (slow; good for checking common UDP services)
sudo nmap -sU --top-ports 50 -T4 -Pn -n 10.10.10.10
```

Tips for narrowing scope dynamically (example workflow)
```
# After discovering RDP on multiple hosts, focus enumeration:
services -p 3389
# Then pivot into a service scanner or exploit modules as appropriate.
```

Exporting results (simple)
```
services > services.txt
hosts > hosts.txt
```

Stop a running scan
```
# Press Ctrl+C, then confirm
```

## Practical tips
- Choose the scan type based on constraints:
  - tcp: reliable, no special privileges; more detectable.
  - syn: faster, stealthier; requires root/cap_net_raw.
  - ack: map filtering; use to understand firewall behavior.
- Always set a sane PORTS list to speed up scans (mix of ranges and high-value ports).
- Use THREADS conservatively over WAN/VPN (e.g., 10–50) and higher on LAN (e.g., 100–200).
- Keep scans targeted; scan a subnet only after confirming host discovery if needed.
- Review services often; don’t wait for full scans to complete to begin enumeration.
- If SYN scan complains about permissions, rerun msfconsole with sudo.
- Save results to the MSF DB (default) and export text for reporting.
- Use Nmap to complement MSF for UDP and deep service detection.
- On noisy networks or IPS, prefer smaller port sets and lower THREADS.

## Minimal cheat sheet (one-screen flow)
```
# Start & prepare
msfconsole -q
workspace -a eJPT-scan && workspace eJPT-scan
db_status

# TCP connect scan (no root)
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.10.0/24
set PORTS 1-1000,1433,3306,3389,8080,8443
set THREADS 100
run

# SYN scan (root required)
use auxiliary/scanner/portscan/syn
set RHOSTS 10.10.10.0/24
set PORTS 1-1000,1433,3306,3389,8080,8443
set THREADS 100
run

# ACK scan (firewall mapping)
use auxiliary/scanner/portscan/ack
set RHOSTS 10.10.10.0/24
set PORTS 1-1000,1433,3306,3389,8080,8443
set THREADS 100
run

# Review findings
hosts
services
services -p 80
services -p 3389

# Optional: verify with Nmap (TCP/UDP)
sudo nmap -sS -sV -Pn -n --top-ports 1000 -T4 10.10.10.10
sudo nmap -sU --top-ports 50 -T4 -Pn -n 10.10.10.10
```

## Summary
- Metasploit’s auxiliary portscan modules provide fast, flexible TCP scanning directly within your exploitation workflow, storing results in its database for easy follow-up.
- Use tcp when you lack privileges, syn for speed/stealth (with root), and ack to understand firewall filtering.
- Keep scans targeted with curated port lists and tuned THREADS. Review services and pivot quickly into enumeration or exploitation.
- Complement with Nmap, especially for UDP or where deeper service fingerprints are needed.