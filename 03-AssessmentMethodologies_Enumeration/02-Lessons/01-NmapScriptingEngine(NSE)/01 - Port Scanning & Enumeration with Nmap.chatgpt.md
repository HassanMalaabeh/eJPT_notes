# 01 – Port Scanning & Enumeration with Nmap (inferred)

Note: No transcript was provided. The following is a conservative, exam-oriented summary inferred from the filename and the folder “01-NmapScriptingEngine(NSE)”. Commands and flags reflect common eJPT workflows for Nmap port scanning, service/OS detection, and NSE-driven enumeration.

## What the video covers (Introduction / big picture)
- How to systematically discover live hosts and open ports with Nmap
- Choosing scan types (SYN, TCP connect, UDP), scope handling, and speed/performance
- Enumerating discovered services with -sV, -sC, and targeted NSE scripts
- Understanding NSE categories (safe, default, vuln, etc.) and using script arguments
- Producing clean artifacts (-oA) and a repeatable, minimally noisy workflow for eJPT-style engagements

## Flow (ordered)
1. Define scope and prepare output directories
2. Host discovery (ping/ARP sweep) to identify live targets
3. Quick TCP scan to get initial port picture
4. Full TCP scan (-p-) for completeness
5. Service/OS detection (-sV, -O) and default scripts (-sC)
6. Targeted UDP scan for common UDP services
7. NSE-driven, service-specific enumeration (HTTP, SMB, FTP, RDP, DNS, SNMP, etc.)
8. Optional: vulnerability-oriented NSE scans (careful with “intrusive”/“vuln”)
9. Save outputs in multiple formats (-oA), parse results, iterate

## Tools highlighted
- Nmap (core scanning, service/OS detection, NSE)
- Nmap Scripting Engine (NSE): /usr/share/nmap/scripts, --script, --script-args, --script-help
- Optional Nmap companions:
  - nping for reachability/latency checks
  - ncat for banner grabbing/manual interaction

## Typical command walkthrough (detailed, copy-paste friendly)

Preparation
```
# Set variables (adjust to your scope/target)
export SCOPE="10.10.10.0/24"
export TARGET="10.10.10.10"
export OUT="scans_$(date +%F_%H%M)"
mkdir -p "$OUT"
sudo -v  # cache sudo credentials
```

1) Host discovery (ping/ARP sweep)
```
# Local network ARP + ICMP + common TCP/UDP probes (fast, thorough)
sudo nmap -sn -n -PE -PS80,443,22,3389 -PA80,443,3389 -PU53 -PR "$SCOPE" -oA "$OUT/01_discovery"

# If ICMP is blocked but you know hosts are up, skip host discovery:
# sudo nmap -Pn -sn "$SCOPE" -oA "$OUT/01_discovery_pn"
```

2) Quick TCP scan (top ports, get fast signal)
```
# Top 100 TCP ports, show open only
sudo nmap -Pn -n --top-ports 100 -sS --open -T4 "$TARGET" -oA "$OUT/02_quick_top100_tcp"
```

3) Full TCP scan (completeness)
```
# Full TCP scan (SYN), all ports; use T3/T4 based on distance and stability
sudo nmap -Pn -n -sS -p- -T4 --max-retries 2 --min-rate 300 "$TARGET" -oA "$OUT/03_full_tcp_allports"
```

4) Service detection + default scripts + OS detection (targeted to open ports)
```
# Extract open TCP ports and run detailed enumeration
OPEN_TCP=$(grep -oP '^\d+/tcp\s+open' "$OUT/03_full_tcp_allports.nmap" | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')

# If no ports found, set manually, e.g., OPEN_TCP="22,80"
sudo nmap -Pn -n -sV -sC -O -p "$OPEN_TCP" --version-intensity 7 --reason "$TARGET" -oA "$OUT/04_tcp_svc_os_default"
```

5) UDP scan (focused, because UDP is slow)
```
# Common UDP ports (DNS, SNMP, NTP, etc.)
# Use top 25–50 for speed during exams; add -sV on specific ports later
sudo nmap -Pn -n -sU --top-ports 25 --max-retries 1 --host-timeout 30m "$TARGET" -oA "$OUT/05_udp_top"

# If DNS/SNMP are suspected:
sudo nmap -Pn -n -sU -p 53,69,123,137,161,500 "$TARGET" -oA "$OUT/05_udp_targeted"
```

6) HTTP/HTTPS enumeration with NSE
```
# Titles, headers, methods, robots, common paths
sudo nmap -Pn -n -p 80,443,8080,8443 --script "http-title,http-headers,http-methods,http-robots.txt,http-server-header,http-enum" "$TARGET" -oA "$OUT/06_http_enum"

# TLS details
sudo nmap -Pn -n -p 443,8443 --script "ssl-cert,ssl-enum-ciphers" "$TARGET" -oA "$OUT/06_tls_enum"
```

7) SMB enumeration with NSE
```
# Basic SMB discovery and shares
sudo nmap -Pn -n -p 139,445 --script "smb-os-discovery,smb-protocols,smb2-security-mode,smb2-time,smb-enum-shares,smb-enum-users" "$TARGET" -oA "$OUT/07_smb_enum"

# If you have creds:
# sudo nmap -Pn -n -p445 --script "smb-enum-shares,smb-enum-users" --script-args "smbusername=USER,smbpassword=PASS" "$TARGET" -oA "$OUT/07_smb_enum_auth"
```

8) FTP, SSH, SMTP, RDP, DNS, SNMP enumeration with NSE
```
# FTP (check anonymous)
sudo nmap -Pn -n -p21 --script "ftp-anon,ftp-syst" "$TARGET" -oA "$OUT/08_ftp_enum"

# SSH (keys and auth methods)
sudo nmap -Pn -n -p22 --script "ssh-hostkey,ssh2-enum-algos,ssh-auth-methods" "$TARGET" -oA "$OUT/08_ssh_enum"

# SMTP (VRFY/EXPN, if enabled)
sudo nmap -Pn -n -p25,465,587 --script "smtp-commands,smtp-enum-users" "$TARGET" -oA "$OUT/08_smtp_enum"

# RDP encryption and security
sudo nmap -Pn -n -p3389 --script "rdp-enum-encryption,rdp-ntlm-info" "$TARGET" -oA "$OUT/08_rdp_enum"

# DNS (TCP/UDP as applicable)
sudo nmap -Pn -n -sU -p53 --script "dns-recursion,dns-service-discovery" "$TARGET" -oA "$OUT/08_dns_udp"
sudo nmap -Pn -n -sT -p53 --script "dns-recursion,dns-service-discovery" "$TARGET" -oA "$OUT/08_dns_tcp"

# SNMP info (requires UDP 161 open; try common community strings only if authorized)
sudo nmap -Pn -n -sU -p161 --script "snmp-info" "$TARGET" -oA "$OUT/08_snmp_info"
# Brute (noisy; only with permission):
# sudo nmap -Pn -n -sU -p161 --script "snmp-brute" --script-args snmpbrute.communitiesdb=/usr/share/seclists/Discovery/SNMP/snmp.txt "$TARGET" -oA "$OUT/08_snmp_brute"
```

9) Vulnerability-oriented NSE (cautious, may be intrusive/noisy)
```
# Safe-first approach: restrict to safe/default categories on discovered ports
sudo nmap -Pn -n -p "$OPEN_TCP" --script "default,safe and not intrusive" "$TARGET" -oA "$OUT/09_safe_scripts"

# If permitted, vuln category (expect false positives, read script output carefully)
sudo nmap -Pn -n -p "$OPEN_TCP" --script "vuln" "$TARGET" -oA "$OUT/09_vuln_category"
```

10) Output management and quick parsing
```
# Save all in one go (-oA creates .nmap, .gnmap, .xml)
# Already used above; to quickly grep open ports:
grep -i "open" "$OUT"/**/*.nmap | sort -u

# Greppable output parsing
grep -E "Ports: .*open" "$OUT"/**/*.gnmap | sed 's/  */ /g'

# Convert XML to HTML (requires xsltproc)
xsltproc "$OUT/04_tcp_svc_os_default.xml" -o "$OUT/04_tcp_svc_os_default.html"
```

11) NSE discovery, help, and updates
```
# Where scripts live
ls -1 /usr/share/nmap/scripts | head

# Find scripts by keyword or category
nmap --script-help='http-*'
nmap --script-help='category:vuln'

# After adding custom scripts, refresh DB
sudo nmap --script-updatedb
```

Common scan options and meanings
- -sS: TCP SYN (half-open), requires sudo
- -sT: TCP connect(), slower but works without sudo
- -sU: UDP scan, slow; focus ports
- -sV: Service/version detection
- -sC: Default scripts (equivalent to --script=default)
- -O: OS detection (sudo recommended)
- -A: Aggressive (combines -sC -sV -O --traceroute)
- -p-: All 65535 TCP ports
- --top-ports N: Top N ports by frequency
- -Pn: Treat targets as online (skip host discovery)
- -n: No DNS resolution (faster, less noisy)
- -T3/T4: Timing templates (T4 on LAN, T3 on WAN)
- -oA basename: Output all formats (.nmap, .gnmap, .xml)
- --reason: Show why Nmap believes a port is in a given state

NSE categories (use with --script)
- default, safe, version, auth, broadcast, brute, discovery, vuln, intrusive, external, fuzzer, malware, dos (avoid intrusive/dos unless explicitly allowed)

Port states quick reference
- open: service accepts connections
- closed: reachable but no service
- filtered: packet blocked by a device (firewall)
- unfiltered: reachable but state unknown
- open|filtered: cannot distinguish between open and filtered

## Practical tips
- Start wide, go deep: discovery → quick scan → full TCP → focused enumeration.
- Use -oA for every run; you’ll reuse the XML/grepable output later.
- Prefer -sS over -sT if you have sudo; it’s faster and less noisy.
- For UDP, target only relevant ports first; verify with -sV on a per-port basis.
- If nothing shows up, try -Pn (ICMP/ping often blocked).
- Keep timing sane: T4 on local/internal, T3 for remote; too aggressive can drop accuracy.
- Use --reason and -vv to understand why ports are marked open/filtered.
- Leverage NSE categories safely: start with default,safe; escalate only when authorized.
- Script arguments matter (e.g., smbusername=, smbpassword=, http.useragent, dns, snmp community); check nmap --script-help.
- Exclude out-of-scope IPs with --exclude or --excludefile.
- Legal: Only scan targets you’re authorized to test.

## Minimal cheat sheet (one-screen flow)
```
# Vars
TARGET=10.10.10.10; SCOPE=10.10.10.0/24; OUT=scans_$(date +%F_%H%M); mkdir -p "$OUT"

# 1) Discover hosts
sudo nmap -sn -n -PE -PS80,443,22 -PA3389 -PU53 -PR "$SCOPE" -oA "$OUT/01_discovery"

# 2) Quick TCP
sudo nmap -Pn -n --top-ports 100 -sS --open -T4 "$TARGET" -oA "$OUT/02_quick"

# 3) Full TCP
sudo nmap -Pn -n -sS -p- -T4 --max-retries 2 --min-rate 300 "$TARGET" -oA "$OUT/03_full_tcp"

# 4) Service/OS + default scripts
OPEN_TCP=$(grep -oP '^\d+/tcp\s+open' "$OUT/03_full_tcp.nmap" | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
sudo nmap -Pn -n -sV -sC -O -p "$OPEN_TCP" --reason "$TARGET" -oA "$OUT/04_enum"

# 5) UDP (top 25)
sudo nmap -Pn -n -sU --top-ports 25 --max-retries 1 "$TARGET" -oA "$OUT/05_udp"

# 6) HTTP/HTTPS NSE
sudo nmap -Pn -n -p 80,443,8080,8443 --script "http-title,http-headers,http-methods,http-robots.txt,http-enum,ssl-cert,ssl-enum-ciphers" "$TARGET" -oA "$OUT/06_web"

# 7) SMB NSE
sudo nmap -Pn -n -p 139,445 --script "smb-os-discovery,smb2-security-mode,smb-enum-shares,smb-enum-users" "$TARGET" -oA "$OUT/07_smb"

# 8) Other common services
sudo nmap -Pn -n -p21 --script "ftp-anon,ftp-syst" "$TARGET" -oA "$OUT/08_ftp"
sudo nmap -Pn -n -p22 --script "ssh-hostkey,ssh2-enum-algos,ssh-auth-methods" "$TARGET" -oA "$OUT/08_ssh"
sudo nmap -Pn -n -p3389 --script "rdp-enum-encryption,rdp-ntlm-info" "$TARGET" -oA "$OUT/08_rdp"
```

## Summary
This session walks through a reliable Nmap workflow for eJPT-style assessments: host discovery; quick and full TCP coverage; targeted UDP checks; and focused service enumeration with -sV, -sC, and NSE. You learn to select appropriate scan types and timing, leverage NSE categories and script arguments, and save/parse results cleanly. Start safe (default,safe), escalate only as permitted, and iterate based on findings.