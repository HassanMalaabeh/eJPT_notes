# 02 - Introduction To Enumeration (eJPT)

Note: No transcript was provided. The following summary infers typical eJPT “Introduction to Enumeration” content based on the filename and context. Commands and tools below are standard, exam‑appropriate examples—adapt paths, scope, and rates to your lab/exam rules.

## What the video covers (Introduction / big picture)
- Defines enumeration in a penetration test: actively interacting with discovered hosts/services to extract actionable details (versions, users, shares, directories, configs).
- Differentiates recon vs scanning vs enumeration:
  - Recon: passive info gathering (OSINT).
  - Scanning: host/port discovery.
  - Enumeration: service/application-level data extraction that informs exploitation.
- Emphasizes a methodical, layered approach:
  1) Scope and host discovery.
  2) TCP/UDP port scans.
  3) Service/version detection and targeted scripts.
  4) Protocol-specific enumeration (HTTP/SMB/FTP/DNS/SNMP/etc.).
  5) Record findings and pivot to exploitation paths.
- Encourages note-taking, saving outputs, and iterating as new information appears.

## Flow (ordered)
1. Confirm scope and set up workspace and variables.
2. Discover live hosts (ping/ARP sweep).
3. Scan TCP ports broadly, then refine.
4. Scan key UDP ports.
5. Enumerate services with version detection and safe NSE scripts.
6. Deep-dive per protocol (HTTP, SMB, FTP, DNS, SNMP, etc.).
7. Save artifacts and maintain a findings map (ports → services → versions → potential vulns/creds).
8. Re-scan targets as new info emerges (e.g., credentials, vhosts, new subnets).

## Tools highlighted
- Network/Port:
  - nmap, arp-scan, fping
  - masscan or rustscan (optional)
- Service/Banner:
  - netcat (nc), telnet, curl, whatweb
- Web enumeration:
  - gobuster or feroxbuster, nikto, wafw00f
- SMB/Windows:
  - smbclient, smbmap, enum4linux/enum4linux-ng, rpcclient, nbtscan
- DNS:
  - dig, nslookup, dnsrecon
- SNMP:
  - snmpwalk, snmp-check, onesixtyone
- Misc protocol helpers:
  - showmount (NFS), rpcinfo, ldapsearch, mysql, xfreerdp
- Wordlists:
  - SecLists (commonly under /usr/share/seclists or /usr/share/wordlists/SecLists)

## Typical command walkthrough (detailed, copy-paste friendly)
Adjust variables, CIDRs, and wordlists as needed.

### 0) Setup
```bash
# Target variables
export RANGE="10.10.10.0/24"
export TARGET="10.10.10.10"
mkdir -p scans notes
```

### 1) Host discovery
```bash
# Ping sweep (fast). -sn disables port scan, just host discovery.
nmap -sn -oA scans/ping_sweep "$RANGE"

# Alternative for local L2 networks (ARP)
sudo arp-scan --localnet | tee scans/arp_scan.txt

# Alternative with fping
fping -a -g "$RANGE" 2>/dev/null | tee scans/fping_alive.txt
```

### 2) TCP port discovery (broad → focused)
```bash
# Full TCP SYN scan; adjust --min-rate to your environment
sudo nmap -p- -sS -n -Pn --min-rate 5000 -oA "scans/${TARGET}_tcp_all" "$TARGET"

# Extract open TCP ports as a comma list
ports=$(grep -oP '\d{1,5}/open' "scans/${TARGET}_tcp_all.gnmap" | awk -F'/' '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
echo "Open TCP ports: $ports"

# Targeted service/version + default scripts on discovered ports
sudo nmap -sC -sV -p "$ports" -oA "scans/${TARGET}_tcpsv" "$TARGET"

# Optional OS detection (can be noisy)
sudo nmap -O --osscan-guess -p "$ports" -oA "scans/${TARGET}_os" "$TARGET"
```

### 3) UDP discovery (top ports)
```bash
# Top UDP ports to cut noise/time; increase as needed
sudo nmap -sU --top-ports 200 --open -n -Pn -oA "scans/${TARGET}_udp_top" "$TARGET"

# Optional deeper UDP enumeration on interesting ports
udp_ports=$(grep -oP '\d{1,5}/open' "scans/${TARGET}_udp_top.gnmap" | awk -F'/' '{print $1}' | tr '\n' ',' | sed 's/,$//')
[ -n "$udp_ports" ] && sudo nmap -sU -sV -p "$udp_ports" -oA "scans/${TARGET}_udpsv" "$TARGET"
```

### 4) Protocol-specific enumeration

#### HTTP/HTTPS (80/443/other)
```bash
whatweb -v "http://$TARGET" | tee "scans/${TARGET}_whatweb.txt"
curl -I "http://$TARGET" | tee "scans/${TARGET}_http_headers.txt"
curl -ksI "https://$TARGET" | tee "scans/${TARGET}_https_headers.txt"
curl -s "http://$TARGET/robots.txt" | tee "scans/${TARGET}_robots.txt"

# Directory/File brute-forcing (choose one)
gobuster dir -u "http://$TARGET" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,html -t 50 -o "scans/${TARGET}_gobuster_http.txt"

# or feroxbuster
feroxbuster -u "http://$TARGET" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -x php,txt,html -t 50 -k -o "scans/${TARGET}_ferox_http.txt"

# Basic vuln scanning (safe checks)
nikto -h "http://$TARGET" -o "scans/${TARGET}_nikto_http.txt"

# If HTTPS, enumerate TLS
sslscan "$TARGET" | tee "scans/${TARGET}_sslscan.txt"
```

Virtual hosts (if you know/guess a domain):
```bash
# Replace example.com with the FQDN pointing to TARGET
gobuster vhost -u "http://$TARGET" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 50 --append-domain -d example.com -o "scans/${TARGET}_vhosts.txt"
```

#### SMB (139/445)
```bash
# Null session tests
smbclient -L "//$TARGET/" -N | tee "scans/${TARGET}_smb_shares.txt"
smbmap -H "$TARGET" | tee "scans/${TARGET}_smbmap.txt"

# Enum users/shares via NSE
nmap --script smb-os-discovery,smb-enum-users,smb-enum-shares -p 139,445 -oA "scans/${TARGET}_smb_nse" "$TARGET"

# enum4linux (classic) or enum4linux-ng
enum4linux -a "$TARGET" | tee "scans/${TARGET}_e4l.txt"
# or:
enum4linux-ng -A "$TARGET" | tee "scans/${TARGET}_e4lng.txt"

# Connect to a found share (example: 'public')
smbclient "//${TARGET}/public" -N -c 'recurse;ls'
```

#### FTP (21)
```bash
# Check for anonymous access
nmap -p21 --script ftp-anon,ftp-syst -oA "scans/${TARGET}_ftp_nse" "$TARGET"
ftp -inv "$TARGET" << 'EOF'
user anonymous anonymous@
ls -la
quit
EOF

# Mirror anonymous ftp if accessible
wget -m "ftp://anonymous:anonymous@${TARGET}"
```

#### DNS (53)
```bash
# Replace example.com if a domain is in scope
dig @"$TARGET" any +nocmd +noall +answer
dig @"$TARGET" axfr example.com +nocmd +noall +answer  # Zone transfer attempt (if allowed)
dnsrecon -d example.com -t std,axfr -n "$TARGET" | tee "scans/${TARGET}_dnsrecon.txt"
```

#### SNMP (161/udp)
```bash
# Community string discovery (be gentle with wordlists)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-default.txt "$TARGET" | tee "scans/${TARGET}_snmp_community.txt"

# Common default community "public"
snmpwalk -v2c -c public "$TARGET" 1.3.6.1.2.1.1 | tee "scans/${TARGET}_snmp_sysdescr.txt"
snmpwalk -v2c -c public "$TARGET" 1.3.6.1.2.1 | tee "scans/${TARGET}_snmp_full.txt"
```

#### LDAP (389/636)
```bash
# Replace base DN appropriately if known
nmap --script ldap-rootdse,ldap-search -p 389,636 -oA "scans/${TARGET}_ldap_nse" "$TARGET"

# Anonymous read (if allowed); adjust base DN
ldapsearch -x -H "ldap://$TARGET" -b "dc=example,dc=com" | tee "scans/${TARGET}_ldapsearch.txt"
```

#### RDP (3389)
```bash
nmap --script rdp-enum-encryption,rdp-ntlm-info -p 3389 -oA "scans/${TARGET}_rdp_nse" "$TARGET"
xfreerdp /v:"$TARGET" /cert:ignore
```

#### NFS (111/2049)
```bash
nmap -p111,2049 --script=nfs* -oA "scans/${TARGET}_nfs_nse" "$TARGET"
showmount -e "$TARGET" | tee "scans/${TARGET}_nfs_exports.txt"

# Example mounting an export
sudo mkdir -p /mnt/nfs
sudo mount -t nfs -o vers=3 "$TARGET:/export" /mnt/nfs
```

#### Databases (examples)
```bash
# MySQL (3306)
nmap -p3306 --script mysql-info,mysql-user,mysql-enum -oA "scans/${TARGET}_mysql_nse" "$TARGET"
mysql -h "$TARGET" -uroot -p

# PostgreSQL (5432)
nmap -p5432 --script pgsql-brute,pgsql-info -oA "scans/${TARGET}_pgsql_nse" "$TARGET"
```

#### Banners and quick checks
```bash
# Banner grabbing
nc -nv "$TARGET" 22
nc -nv "$TARGET" 25
telnet "$TARGET" 80

# Re-check service after change
curl -sI "http://$TARGET"
```

### 5) Save and search findings
```bash
# Convert nmap XML to HTML (if xsltproc installed)
xsltproc "scans/${TARGET}_tcpsv.xml" -o "scans/${TARGET}_tcpsv.html"

# Grep for versions to feed into searchsploit
grep -Eo '([A-Za-z0-9._-]+) [0-9]+\.[0-9.]*' "scans/${TARGET}_tcpsv.nmap" | sort -u | tee "notes/${TARGET}_versions.txt"

# Example lookup
searchsploit "$(head -n1 notes/${TARGET}_versions.txt)"
```

## Practical tips
- Start broad, then focus: quick top scans → full scans → targeted scripts.
- Use -oA to save all nmap output formats for later parsing.
- If ICMP is blocked, add -Pn to nmap to skip host discovery.
- Mind performance vs stealth: T4 with --min-rate for labs; slow down if needed.
- UDP is slow and lossy; target known ports (53, 67/68, 69, 123, 137, 161, 500, 1900).
- Always try anonymous/null access on FTP/SMB/LDAP/SNMP.
- Web: check robots.txt, default creds, hidden dirs; try vhosts if a domain is involved.
- Keep meticulous notes (ports, versions, creds, accessible shares/dirs).
- Re-enumerate after each new credential or hint; new avenues often open.
- Respect scope and lab rules—avoid brute-forcing unless permitted.

## Minimal cheat sheet (one-screen flow)
```bash
# Setup
export RANGE="10.10.10.0/24"; export TARGET="10.10.10.10"; mkdir -p scans notes

# Discovery
nmap -sn -oA scans/ping_sweep "$RANGE" || true
sudo arp-scan --localnet | tee scans/arp_scan.txt

# TCP/UDP
sudo nmap -p- -sS -n -Pn --min-rate 5000 -oA scans/${TARGET}_tcp_all "$TARGET"
ports=$(grep -oP '\d{1,5}/open' scans/${TARGET}_tcp_all.gnmap | awk -F'/' '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
sudo nmap -sC -sV -p "$ports" -oA scans/${TARGET}_tcpsv "$TARGET"
sudo nmap -sU --top-ports 200 --open -n -Pn -oA scans/${TARGET}_udp_top "$TARGET"

# Web
whatweb -v http://$TARGET | tee scans/${TARGET}_whatweb.txt
gobuster dir -u http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,html -t 50 -o scans/${TARGET}_gobuster_http.txt
nikto -h http://$TARGET -o scans/${TARGET}_nikto_http.txt

# SMB
smbclient -L //$TARGET/ -N | tee scans/${TARGET}_smb_shares.txt
smbmap -H $TARGET | tee scans/${TARGET}_smbmap.txt
nmap --script smb-os-discovery,smb-enum-users,smb-enum-shares -p 139,445 -oA scans/${TARGET}_smb_nse $TARGET

# FTP
nmap -p21 --script ftp-anon,ftp-syst -oA scans/${TARGET}_ftp_nse $TARGET
ftp -inv $TARGET << 'EOF'
user anonymous anonymous@
ls -la
quit
EOF

# DNS/SNMP (if applicable)
dig @$TARGET any +nocmd +noall +answer | tee scans/${TARGET}_dns_any.txt
snmpwalk -v2c -c public $TARGET 1.3.6.1.2.1.1 | tee scans/${TARGET}_snmp_sysdescr.txt
```

## Summary
- Enumeration turns raw port data into actionable intel: versions, exposures, and misconfigurations.
- Proceed in layers: host discovery → TCP/UDP scans → service/version detection → protocol-specific enumeration.
- Prioritize common services (HTTP, SMB, FTP, DNS, SNMP) with proven tools and safe NSE scripts.
- Save outputs, extract versions, and research likely weaknesses.
- Iterate as new clues appear. A disciplined enumeration phase sets up faster, cleaner exploitation in eJPT labs.