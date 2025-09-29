# 01 – Active Information Gathering (eJPT)

Note: No transcript was provided. The following is a conservative, best-effort summary based on the filename and typical eJPT curriculum for “Active Information Gathering.”

## What the video covers (Introduction / big picture)
- What “active information gathering” is and how it differs from passive recon (you send traffic to targets).
- Legal and ethical guardrails: scope, ROE, rate limiting, logging your actions.
- A practical, repeatable workflow:
  - Host discovery (who is alive).
  - Port scanning (what is open).
  - Service/version/OS detection.
  - Targeted service enumeration (HTTP, SMB, FTP, DNS, SMTP, SNMP, etc.).
  - Saving results and pivoting to the next phase.
- Core tools you’ll use on the exam: nmap and common service-enumeration utilities.

## Flow (ordered)
1. Confirm scope and rules of engagement; set a workspace directory.
2. Discover live hosts (ARP/ICMP/TCP pings).
3. Fast reconnaissance scan (top ports) to triage.
4. Full TCP scan and targeted UDP scan.
5. Service, version, OS detection and default NSE scripts.
6. Parse scan output and prioritize targets.
7. Enumerate per-service (HTTP/HTTPS, SMB, FTP, SMTP, DNS, SNMP, RDP, databases).
8. Save all outputs (-oA), take notes, and build a findings list.
9. Adjust rate/timeouts if remote/latent networks; avoid noisy scans unless approved.
10. Prepare for exploitation based on enumeration results.

## Tools highlighted
- Network/host discovery: nmap, fping, arp-scan, netdiscover
- Port scanning: nmap (SYN, UDP, NSE), masscan (optional/high-speed)
- Banner grabbing: nc (netcat), curl, openssl s_client, whatweb
- Web enumeration: gobuster or ffuf, nikto, whatweb, curl/wget
- SMB enumeration: smbclient, smbmap, enum4linux-ng, rpcclient, nmap smb NSE scripts
- DNS enumeration: dig, host, dnsrecon/dnsenum
- SMTP enumeration: nmap smtp NSE scripts, nc, smtp-user-enum
- SNMP enumeration: onesixtyone, snmpwalk, snmp-check
- Other services: showmount (NFS), mysql client, nmap NSE for common databases
- Utilities: tee, awk/sed/grep for parsing, tmux/screen for session management

## Typical command walkthrough (detailed, copy-paste friendly)
The following commands assume a Debian/Kali-like environment. Adjust to your target IPs/domains.

Optional: install common tools
```
sudo apt update && sudo apt install -y nmap fping arp-scan netdiscover whatweb gobuster nikto \
  smbclient smbmap enum4linux-ng snmp snmpcheck onesixtyone dnsutils dnsrecon ffuf
```

Setup workspace and variables
```
mkdir -p ~/engagement/scans && cd ~/engagement
NET="10.10.10.0/24"     # target subnet
DOMAIN="example.local"  # target domain if known
WORDLIST="/usr/share/wordlists/dirb/common.txt"
VHOSTS="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
```

1) Host discovery (pick one or combine)
```
# ICMP/TCP ping sweep (nmap)
sudo nmap -sn -oA scans/discover_icmp $NET

# Fast ping sweep (fping)
fping -a -g $NET 2>/dev/null | tee scans/live-hosts.txt

# Layer-2 discovery (same LAN)
sudo arp-scan -l | tee scans/arp-scan.txt
```

If you used nmap -sn and didn’t create live-hosts.txt:
```
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' scans/discover_icmp.gnmap | sort -u > scans/live-hosts.txt
```

2) Fast triage scan (optional but useful on many hosts)
```
while read -r H; do
  echo "[*] Top ports TCP on $H"
  sudo nmap -Pn -T4 --top-ports 200 --open -oA scans/${H}-tcp-top200 $H
done < scans/live-hosts.txt
```

3) Full TCP and targeted UDP scanning per host
```
while read -r H; do
  echo "[*] Full TCP scan on $H"
  sudo nmap -Pn -sS -p- --min-rate 3000 -T4 -oA scans/${H}-tcp-full $H

  # Extract open TCP ports from greppable output
  TCP_PORTS=$(grep "/open/" scans/${H}-tcp-full.gnmap | sed -n 's/.*Ports: //p' | tr ',' '\n' \
    | awk -F/ '/open/{print $1}' | paste -sd, -)

  echo "[*] Targeted TCP enumeration on $H ($TCP_PORTS)"
  if [ -n "$TCP_PORTS" ]; then
    sudo nmap -Pn -sC -sV -O -p "$TCP_PORTS" -oA scans/${H}-tcp-enum $H
  fi

  echo "[*] Top UDP scan on $H"
  sudo nmap -Pn -sU --top-ports 100 --defeat-rst-ratelimit -oA scans/${H}-udp-top100 $H

done < scans/live-hosts.txt
```

4) Quick banner grabs (safe, low bandwidth)
```
H=10.10.10.10
echo | nc -nv $H 21
echo | nc -nv $H 22
echo | nc -nv $H 25
echo | nc -nv $H 80
echo | nc -nv $H 110
echo | nc -nv $H 143
echo | nc -nv $H 443
```

5) HTTP/HTTPS enumeration
```
H=10.10.10.10
whatweb http://$H
curl -I http://$H
# If HTTPS:
whatweb https://$H
curl -kI https://$H

# Directories/files brute force
gobuster dir -u http://$H/ -w "$WORDLIST" -x php,txt,html -t 50 --no-error -o scans/${H}-gobuster.txt

# Quick vulnerability scan (low false negatives, high noise; use within scope)
nikto -h http://$H | tee scans/${H}-nikto.txt

# Virtual hosts (if you have a domain or suspect name-based vhosts)
ffuf -u http://$H/ -H "Host: FUZZ.$DOMAIN" -w "$VHOSTS" -fc 400,401,403,404 -t 50 -o scans/${H}-vhosts.json
```

6) SMB enumeration (139/445)
```
H=10.10.10.10
# NSE scripts
sudo nmap -Pn -p445 --script smb-enum-shares,smb-os-discovery,smb-enum-users -oA scans/${H}-smb $H

# List shares (null session)
smbclient -L //$H/ -N | tee scans/${H}-smbclient-list.txt

# Map shares and permissions
smbmap -H $H | tee scans/${H}-smbmap.txt

# Old but effective Linux/AD enumeration
enum4linux-ng -A $H | tee scans/${H}-enum4linux.txt

# Try RPC null session for user/group info
rpcclient -U "" -N $H -c "enumdomusers" | tee scans/${H}-rpc-users.txt
```

7) FTP enumeration (21)
```
H=10.10.10.10
sudo nmap -Pn -p21 --script ftp-anon,ftp-syst -oA scans/${H}-ftp $H

# Test anonymous login
ftp -inv $H << 'EOF'
user anonymous anonymous@
ls -la
bye
EOF
```

8) SMTP enumeration (25/465/587)
```
H=10.10.10.10
sudo nmap -Pn -p25,465,587 --script smtp-commands,smtp-enum-users -oA scans/${H}-smtp $H

# Manual banner + basic commands
nc -nv $H 25 << 'EOF'
EHLO test
VRFY root
EXPN postmaster
QUIT
EOF
```

9) DNS enumeration (53)
```
H=10.10.10.10
# Service discovery + recursion check
sudo nmap -Pn -sU -p53 --script dns-service-discovery,dns-recursion -oA scans/${H}-dns $H

# CHAOS TXT version and AXFR (zone transfer) if authoritative
dig @${H} version.bind txt chaos +short
dig @${H} axfr $DOMAIN
```

10) SNMP enumeration (161/162)
```
H=10.10.10.10
# Discover community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-default.txt $H | tee scans/${H}-snmp-community.txt

# Walk common trees (using 'public' as example)
snmpwalk -v2c -c public $H 1.3.6.1.2.1.1 | tee scans/${H}-snmp-system.txt
snmpwalk -v2c -c public $H 1.3.6.1.2.1 | tee scans/${H}-snmp-mibs.txt

# Quick summary
snmp-check $H -c public | tee scans/${H}-snmp-check.txt
```

11) RDP/WinRM checks (3389/5985/5986)
```
H=10.10.10.10
sudo nmap -Pn -p3389 --script rdp-enum-encryption,rdp-ntlm-info -oA scans/${H}-rdp $H
sudo nmap -Pn -p5985,5986 --script http-auth,ssl-cert -oA scans/${H}-winrm $H
```

12) NFS (111/2049)
```
H=10.10.10.10
sudo nmap -Pn -p111,2049 --script nfs-ls,nfs-showmount,nfs-statfs -oA scans/${H}-nfs $H
showmount -e $H | tee scans/${H}-nfs-exports.txt
```

13) Databases (examples)
```
H=10.10.10.10
# MySQL
sudo nmap -Pn -p3306 --script mysql-info,mysql-empty-password,mysql-users -oA scans/${H}-mysql $H
mysql -h $H -u root -p

# MSSQL (if present)
sudo nmap -Pn -sU -p1434 --script ms-sql-info -oA scans/${H}-mssql-udp $H
sudo nmap -Pn -p1433 --script ms-sql-info,ms-sql-ntlm-info -oA scans/${H}-mssql $H
```

14) Save and consolidate findings
```
# Example: collect open ports per host into one CSV
echo "host,protocol,port,service" > scans/open-ports.csv
for f in scans/*-tcp-full.gnmap; do
  H=$(basename "$f" | cut -d'-' -f1)
  grep "/open/" "$f" | sed -n 's/.*Ports: //p' | tr ',' '\n' \
    | awk -F/ -v host="$H" '/open/{printf "%s,%s,%s,%s\n", host,"tcp",$1,$5}' >> scans/open-ports.csv
done
```

## Practical tips
- Always respect scope. If in doubt, slow down or ask for clarification before scanning aggressively.
- Start broad, then go deep: discovery → ports → service details → targeted enumeration.
- Use -oA everywhere to keep normal, greppable, and XML outputs for later parsing.
- On remote/latent networks, prefer T2–T3 and lower --min-rate to avoid drops; locally you can use T4–T5.
- If ping probes are filtered, use -Pn for port scans but still do an initial -sn to enumerate likely hosts.
- UDP is slow and noisy; start with --top-ports 50–200, then expand if findings warrant.
- Parse greppable output (-oG) to extract port lists quickly for follow-up scans.
- For HTTP, confirm HTTP→HTTPS redirects, enumerate tech (whatweb), content (gobuster/ffuf), and low-hanging findings (nikto).
- For SMB, always check null sessions and readable shares; enum4linux-ng is a quick win.
- For DNS, try AXFR only against in-scope, authoritative nameservers.
- Keep notes: credentials, anonymous access, versions, interesting files/endpoints, and errors/timeouts.

## Minimal cheat sheet (one-screen flow)
```
# Vars
NET="10.10.10.0/24"; DOMAIN="example.local"; WORDLIST="/usr/share/wordlists/dirb/common.txt"

mkdir -p scans

# 1) Discovery
fping -a -g $NET 2>/dev/null | tee scans/live-hosts.txt

# 2) Full TCP + targeted UDP + enumerate
while read -r H; do
  sudo nmap -Pn -sS -p- --min-rate 3000 -T4 -oA scans/${H}-tcp-full $H
  TCP_PORTS=$(grep "/open/" scans/${H}-tcp-full.gnmap | sed -n 's/.*Ports: //p' | tr ',' '\n' \
    | awk -F/ '/open/{print $1}' | paste -sd, -)
  [ -n "$TCP_PORTS" ] && sudo nmap -Pn -sC -sV -O -p "$TCP_PORTS" -oA scans/${H}-tcp-enum $H
  sudo nmap -Pn -sU --top-ports 100 --defeat-rst-ratelimit -oA scans/${H}-udp-top100 $H
done < scans/live-hosts.txt

# 3) Quick service checks (per host, as needed)
H=10.10.10.10
whatweb http://$H; curl -I http://$H
gobuster dir -u http://$H/ -w "$WORDLIST" -x php,txt,html -t 50 --no-error -o scans/${H}-gobuster.txt
smbclient -L //$H/ -N | tee scans/${H}-smbclient-list.txt
enum4linux-ng -A $H | tee scans/${H}-enum4linux.txt
dig @${H} axfr $DOMAIN
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-default.txt $H | tee scans/${H}-snmp-community.txt
snmpwalk -v2c -c public $H 1.3.6.1.2.1.1 | tee scans/${H}-snmp-system.txt
```

## Summary
- Active information gathering is the deliberate interaction with targets to discover hosts, open ports, services, versions, and misconfigurations.
- A reliable flow: discover → scan → enumerate → save results → prioritize findings.
- Nmap is your core tool; combine it with service-specific utilities for depth (HTTP, SMB, DNS, SNMP, SMTP, FTP).
- Save all outputs, parse them to accelerate follow-up, and adjust scan intensity to match network conditions and ROE.
- The goal is actionable data that informs exploitation paths while remaining within scope and minimizing unnecessary noise.