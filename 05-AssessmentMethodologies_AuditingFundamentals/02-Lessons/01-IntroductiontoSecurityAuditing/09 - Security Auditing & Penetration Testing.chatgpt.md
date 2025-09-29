# 09 - Security Auditing & Penetration Testing — eJPT Study Notes

Note: No transcript was provided; this summary is inferred conservatively from the filename and typical eJPT “Introduction to Security Auditing” content. Commands are generic and intended for authorized lab environments only.

## What the video covers (Introduction / big picture)
- Distinguishing security auditing vs penetration testing:
  - Security auditing: systematic review of policies, configurations, and controls against standards/baselines; evidence-driven; broad coverage; low risk.
  - Penetration testing: authorized adversarial testing to validate exploitable risk; focused; time-boxed; higher operational risk; proof-of-exploit.
- Methodologies and frameworks:
  - Pentest: PTES, NIST SP 800-115, OSSTMM; OWASP (web).
  - Audit: ISO 27001/2, CIS Benchmarks, NIST CSF, SOC 2 controls, PCI DSS.
- Engagement fundamentals:
  - Scope, objectives, rules of engagement (ROE), legal authorization, success criteria, time/budget, communications, data handling, safe testing constraints.
- High-level workflow:
  - Pre-engagement and scoping → Recon (passive/active) → Scanning → Enumeration → Vulnerability analysis → Validation (safe PoC) → Post-exploitation (if in scope) → Cleanup → Reporting.
- Deliverables:
  - Executive summary, technical findings with evidence and impact, CVSS/risk ratings, reproducible steps, remediation guidance, and a safe validation plan.

## Flow (ordered)
1. Pre-engagement: confirm scope, constraints, approvals, and ROE.
2. Asset discovery: identify live hosts and in-scope ranges.
3. Port scanning: map services and versions.
4. Service enumeration: collect banners, shares, directories, users, configs.
5. Vulnerability analysis: correlate versions/configs to known issues.
6. Validation (non-destructive): verify exposure safely; avoid impacting availability.
7. Post-exploitation (if authorized): enumerate privileges, data exposure; no persistence unless approved.
8. Cleanup: revert changes, remove accounts/artifacts, deconflict with blue team.
9. Reporting: document findings, evidence, risk, and remediation steps.

## Tools highlighted
- Discovery/Scanning: nmap (NSE), rustscan, masscan (use carefully).
- Enumeration:
  - Web: curl, whatweb, nikto, gobuster/feroxbuster, wafw00f.
  - SMB/Windows: smbclient, enum4linux-ng, rpcclient, nbtscan.
  - FTP/SSH: ftp, ssh/ssh-keyscan.
  - DNS/SNMP: dig, nslookup, snmpwalk.
- Analysis/Lookup: searchsploit, CVE/CVSS references.
- Credentials (authorized testing only): hydra/medusa, john (hash cracking).
- Traffic capture: tcpdump, Wireshark.
- Notes/Reporting: Markdown/Obsidian/CherryTree, screenshots, nmap -oA.

## Typical command walkthrough (detailed, copy-paste friendly)
Set a workspace and environment variables to keep outputs organized.

```bash
# 0) Workspace
mkdir -p ~/engagements/target/{notes,scans,loot,screens}
cd ~/engagements/target
export TARGET=10.10.10.10
export URL=http://$TARGET
date | tee notes/start.txt
```

1) Discovery (adjust CIDR to scope)

```bash
# Ping sweep (ARP/ICMP). Use sudo for ARP on local net.
sudo nmap -sn 10.10.10.0/24 -oA scans/ping-sweep
```

2) Full port scan then detailed scripts/versioning

```bash
# All TCP ports, reduced noise
sudo nmap -Pn -n -p- --min-rate 2000 --defeat-rst-ratelimit -oA scans/alltcp $TARGET

# Extract open ports into a comma list
ports=$(grep -oP '\d+(?=/open/tcp)' scans/alltcp.gnmap | sort -nu | tr '\n' ',' | sed 's/,$//'); echo "$ports"

# Service/version and safe default scripts
sudo nmap -Pn -n -sC -sV -O -p $ports -oA scans/servdet $TARGET
```

3) Web enumeration (if 80/443 open)

```bash
# Fingerprinting and headers
whatweb -v $URL | tee scans/whatweb-$TARGET.txt
curl -I $URL | tee scans/headers-$TARGET.txt

# Content discovery (adjust wordlist and extensions as needed)
gobuster dir -u $URL -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,js -t 50 -o scans/gobuster-$TARGET.txt

# Basic web vuln scan (non-invasive checks)
nikto -h $URL -o scans/nikto-$TARGET.txt
```

4) SMB/Windows enumeration (if 139/445 open)

```bash
# NSE enumeration bundle
sudo nmap -Pn -p139,445 --script "smb-* and not brute" -oA scans/nmap-smb $TARGET

# List shares (guest/anonymous)
smbclient -L \\\\$TARGET\\ -N | tee scans/smb-shares-$TARGET.txt

# Enumerate users/shares/etc.
enum4linux-ng -A $TARGET | tee scans/enum4linux-$TARGET.txt

# Access a share (if guest allowed)
smbclient \\\\$TARGET\\share -N -c 'recurse; prompt off; ls; mget *' -W WORKGROUP
```

5) FTP/SSH enumeration (if 21/22 open)

```bash
# FTP anonymous/system info
sudo nmap -Pn -p21 --script ftp-anon,ftp-syst -oA scans/nmap-ftp $TARGET
ftp -inv $TARGET << 'EOF'
user anonymous anonymous@
ls
bye
EOF

# SSH fingerprint and banner
ssh-keyscan -T 5 -p 22 $TARGET | tee scans/ssh_known_hosts.txt
```

6) DNS/SNMP checks (only if in scope)

```bash
# DNS
dig @${TARGET} any example.local +noall +answer
dig @${TARGET} axfr example.local   # Zone transfer test (authorized domains only)

# SNMP
sudo nmap -sU -Pn -p161 --script snmp-info,snmp-processes -oA scans/nmap-snmp $TARGET
snmpwalk -v2c -c public $TARGET 1.3.6.1.2.1.1 | tee scans/snmp-system.txt
```

7) Vulnerability cues and lookup

```bash
# NSE vuln checks (non-destructive scripts)
sudo nmap -Pn -sV --script vuln -p $ports -oA scans/nmap-vuln $TARGET

# Map versions to known CVEs locally
searchsploit -w -t "$(grep 'Service Info\|open' scans/servdet.nmap | sed -n 's/.*\s\([a-zA-Z0-9._-]\+\)\s\([0-9][^ ]*\).*/\1 \2/p')" | tee scans/searchsploit.txt
```

8) Credentials testing (authorized, low/slow, stop-on-success)

```bash
# SSH example (authorized testing only)
hydra -L users.txt -P passwords.txt ssh://$TARGET -s 22 -t 4 -W 3 -f -o scans/hydra-ssh.txt

# HTTP basic auth example (adjust path/realm)
# hydra -L users.txt -P passwords.txt $TARGET http-get /protected/ -f -o scans/hydra-http.txt
```

9) Capture evidence and wrap-up

```bash
# Packet capture (if needed and allowed; e.g., over VPN interface)
# sudo tcpdump -i tun0 host $TARGET -w scans/$TARGET.pcap

# Finish timestamp
date | tee -a notes/end.txt
```

## Practical tips
- Always align with ROE: approved time windows, throttle (-T2/-T3), avoid destructive scripts, and stop on instability.
- Log everything: use -oA for nmap, tee outputs, and keep timestamps. Take screenshots for key findings.
- Reduce noise: target specific ports first, then deepen enumeration; prefer -n (no DNS) and -Pn only when justified.
- Use /etc/hosts for vhosts to improve web enumeration; try multiple wordlists and file extensions.
- Correlate findings: version + config + exposure. Validate risk with safe checks before deeper testing.
- Prioritize: high-impact internet-facing services, weak auth, exposed shares, sensitive endpoints.
- Reporting-first mindset: capture commands, parameters, and evidence so findings are reproducible.

## Minimal cheat sheet (one-screen flow)
```bash
# Vars
export TARGET=10.10.10.10; export URL=http://$TARGET
mkdir -p scans

# Discovery
sudo nmap -sn 10.10.10.0/24 -oA scans/ping

# Scan
sudo nmap -Pn -n -p- --min-rate 2000 -oA scans/alltcp $TARGET
ports=$(grep -oP '\d+(?=/open/tcp)' scans/alltcp.gnmap | sort -nu | tr '\n' ',' | sed 's/,$//')
sudo nmap -Pn -n -sC -sV -O -p $ports -oA scans/serv $TARGET

# Web
whatweb -v $URL | tee scans/whatweb.txt
curl -I $URL | tee scans/headers.txt
gobuster dir -u $URL -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,js -o scans/gobuster.txt
nikto -h $URL -o scans/nikto.txt

# SMB
sudo nmap -Pn -p139,445 --script "smb-* and not brute" -oA scans/smb $TARGET
smbclient -L \\\\$TARGET\\ -N | tee scans/smb-shares.txt
enum4linux-ng -A $TARGET | tee scans/enum4linux.txt

# FTP/SSH
sudo nmap -Pn -p21 --script ftp-anon,ftp-syst -oA scans/ftp $TARGET
ssh-keyscan -T 5 -p 22 $TARGET | tee scans/ssh_fingerprint.txt

# DNS/SNMP (if in scope)
# dig @${TARGET} axfr example.local
# snmpwalk -v2c -c public $TARGET 1.3.6.1.2.1.1 | tee scans/snmp.txt

# Vuln cues
sudo nmap -Pn -sV --script vuln -p $ports -oA scans/vuln
searchsploit -w -t "service version" | tee scans/searchsploit.txt
```

## Summary
- The video introduces how auditing differs from penetration testing, why both matter, and how to structure authorized testing safely and effectively.
- Adopt a repeatable, evidence-first workflow: scope → recon → scan → enumerate → analyze → safely validate exposure → report and remediate.
- Use common toolchains (nmap, whatweb/nikto/gobuster, smbclient/enum4linux, dig/snmpwalk, searchsploit) and keep operations within ROE to minimize risk and maximize actionable output.