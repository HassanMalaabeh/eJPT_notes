# 01 - Port Scanning & Enumeration With Nmap

Note: The transcript isn’t provided; the following is a conservative, exam-focused summary inferred from the filename and folder context (01-Nmap). Commands and flags reflect typical eJPT workflows.

## What the video covers (Introduction / big picture)
- How to use Nmap to discover live hosts, scan TCP/UDP ports, and enumerate services.
- Choosing scan types for speed vs stealth and accuracy.
- Prioritizing targets and focusing enumeration with Nmap Scripting Engine (NSE).
- Saving, parsing, and reusing results efficiently for the rest of your assessment.
- Interpreting port states and common pitfalls (firewalls, filtered hosts, UDP slowness).

## Flow (ordered)
1. Define scope and target ranges.
2. Host discovery (ping/ARP sweep) to find live targets.
3. Quick TCP scan to get an initial service footprint.
4. Full TCP scan of all ports; extract open ports.
5. Service/version detection, default scripts, and OS detection against discovered ports.
6. Targeted UDP scanning (top ports, then focused enumeration).
7. Service-focused NSE enumeration (HTTP, SMB, FTP, SSH, SMTP, SNMP, etc.).
8. Save outputs (normal, greppable, XML); parse for lists and port sets.
9. Iterate with more scripts where findings warrant (safe/intrusive categories).
10. Summarize results to guide exploitation and further testing.

## Tools highlighted
- nmap (core scanner)
- Nmap Scripting Engine (NSE)
- nping (optional for packet-level reachability checks)
- ndiff (optional for diffing scan results)
- Standard UNIX text tools for parsing output (grep/awk/sed)

NSE scripts live at: /usr/share/nmap/scripts/
Update script database: sudo nmap --script-updatedb

## Typical command walkthrough (detailed, copy-paste friendly)

Set convenience variables and output directory:
```
export NET="10.10.10.0/24"
export T="10.10.10.50"
mkdir -p scans
```

1) Host discovery (live hosts)
- ARP/ping sweep on a local subnet (fast and reliable on LANs):
```
sudo nmap -sn -PR -n -oA scans/disco_arp "$NET"
```
- If ICMP is filtered (common on WANs), disable host discovery:
```
sudo nmap -sn -Pn -n -oA scans/disco_noping "$NET"
```
- TCP/UDP probe-based discovery (try getting around ICMP filters):
```
sudo nmap -sn -PS22,80,443 -PA80,443 -PU53 -n -oA scans/disco_mixed "$NET"
```

2) Quick TCP scan (fast triage)
```
sudo nmap -sS -F -T4 --open -n -oA "scans/${T//\//_}_fast" "$T"
```

3) Full TCP scan (all 65k ports)
- Faster, but can miss on slow links; tune min-rate if needed:
```
sudo nmap -sS -p- --min-rate 2000 -T4 --open -n -oA "scans/${T//\//_}_tcp_all" "$T"
```

4) Extract open TCP ports as a CSV list for reuse
- From the normal output:
```
open_tcp=$(awk '/\/tcp/ && /open/ {print $1}' scans/${T//\//_}_tcp_all.nmap | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
echo "$open_tcp"
```
- Or from greppable output:
```
open_tcp=$(grep -oE '[0-9]{1,5}/open/tcp' scans/${T//\//_}_tcp_all.gnmap | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
echo "$open_tcp"
```

5) Service/version detection + default scripts + OS detection
```
sudo nmap -sV -sC -O -p "$open_tcp" -T4 -n --version-all --reason -oA "scans/${T//\//_}_tcp_enum" "$T"
```

6) UDP scanning
- Quick triage of top UDP ports:
```
sudo nmap -sU --top-ports 50 --open -T4 -n -oA "scans/${T//\//_}_udp_top" "$T"
```
- Extract open UDP ports:
```
open_udp=$(awk '/\/udp/ && /open/ {print $1}' scans/${T//\//_}_udp_top.nmap | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
echo "$open_udp"
```
- Enumerate versions on discovered UDP ports (slower; be patient):
```
[ -n "$open_udp" ] && sudo nmap -sU -sV -p "$open_udp" -T3 -n --reason -oA "scans/${T//\//_}_udp_enum" "$T"
```

7) Targeted NSE enumeration by service
- HTTP/HTTPS:
```
sudo nmap -p80,443,8080,8443 --script http-title,http-server-header,http-methods,http-robots.txt,http-enum -n -oA "scans/${T//\//_}_http_enum" "$T"
```
- SMB (Windows file sharing):
```
sudo nmap -p445 --script smb-os-discovery,smb2-security-mode,smb2-time,smb-enum-shares,smb-enum-users --script-args smbmaxprotocol=SMB3 -n -oA "scans/${T//\//_}_smb_enum" "$T"
```
- FTP:
```
sudo nmap -p21 --script ftp-anon,ftp-syst -n -oA "scans/${T//\//_}_ftp_enum" "$T"
```
- SSH:
```
sudo nmap -p22 --script ssh2-enum-algos,ssh-hostkey -n -oA "scans/${T//\//_}_ssh_enum" "$T"
```
- SMTP:
```
sudo nmap -p25,465,587 --script smtp-commands,smtp-enum-users -n -oA "scans/${T//\//_}_smtp_enum" "$T"
```
- SNMP (requires UDP 161; common community strings: public/private):
```
sudo nmap -sU -p161 --script snmp-info -n -oA "scans/${T//\//_}_snmp_info" "$T"
# If permitted and within scope:
sudo nmap -sU -p161 --script snmp-brute --script-args snmpcommunity=public -n -oA "scans/${T//\//_}_snmp_brute" "$T"
```

8) Helpful NSE usage
- Search for scripts and see help:
```
ls /usr/share/nmap/scripts | grep -i http-
nmap --script-help 'smb-*'
```
- Run safe/default categories:
```
sudo nmap -p "$open_tcp" --script "default,safe" -n -oA "scans/${T//\//_}_safe_scripts" "$T"
```

9) Output management
- One flag to get all formats:
```
# Already used above, but for reference:
-oA scans/basename   # produces .nmap, .gnmap, .xml
```
- Exclude noisy hosts / import lists:
```
nmap -iL targets.txt --exclude 10.10.10.1,10.10.10.254 -oA scans/batch_scan
```

10) When ICMP is blocked or you know the host is up
```
sudo nmap -Pn -sS -p- -T4 -n -oA "scans/${T//\//_}_noprobe_full" "$T"
```

## Practical tips
- Run with sudo for SYN (-sS), OS detection (-O), and UDP accuracy.
- Use -n to skip DNS and speed up; add -R when you actually need reverse DNS.
- Start broad, then focus: discovery -> fast TCP -> full TCP -> UDP -> NSE per service.
- Use --open to reduce noise in output; use --reason to understand why a port is in a given state.
- Prefer -T4 for speed on local/VPN links; avoid -T5 unless you accept higher false negatives.
- UDP is slow and lossy; start with --top-ports 50/100 and then target only what’s open.
- Respect scope and ROE: avoid intrusive/dos/vuln categories unless explicitly allowed.
- Save everything with -oA; you’ll reuse ports and host lists without rescanning.
- Common states: open, closed, filtered, unfiltered, open|filtered. Filtered often means a firewall; try alternative probes or -Pn.
- If initial discovery finds nothing, try -Pn and TCP-based discovery (e.g., -PS -PA -PU).

## Minimal cheat sheet (one-screen flow)
```
# Setup
export NET="10.10.10.0/24"; export T="10.10.10.50"; mkdir -p scans

# 1) Discovery
sudo nmap -sn -PR -n -oA scans/disco_arp "$NET" || true
sudo nmap -sn -Pn -n -oA scans/disco_noping "$NET"

# 2) Quick TCP
sudo nmap -sS -F -T4 --open -n -oA "scans/${T//\//_}_fast" "$T"

# 3) Full TCP + extract ports
sudo nmap -sS -p- --min-rate 2000 -T4 --open -n -oA "scans/${T//\//_}_tcp_all" "$T"
open_tcp=$(awk '/\/tcp/ && /open/ {print $1}' scans/${T//\//_}_tcp_all.nmap | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')

# 4) Enum TCP
sudo nmap -sV -sC -O -p "$open_tcp" -T4 -n --version-all --reason -oA "scans/${T//\//_}_tcp_enum" "$T"

# 5) UDP triage + enum
sudo nmap -sU --top-ports 50 --open -T4 -n -oA "scans/${T//\//_}_udp_top" "$T"
open_udp=$(awk '/\/udp/ && /open/ {print $1}' scans/${T//\//_}_udp_top.nmap | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
[ -n "$open_udp" ] && sudo nmap -sU -sV -p "$open_udp" -T3 -n -oA "scans/${T//\//_}_udp_enum" "$T"

# 6) Targeted NSE (examples)
sudo nmap -p80,443 --script http-title,http-methods,http-enum -n -oA "scans/${T//\//_}_http_enum" "$T"
sudo nmap -p445 --script smb-os-discovery,smb-enum-shares -n -oA "scans/${T//\//_}_smb_enum" "$T"
```

## Summary
- Use Nmap systematically: discover hosts, scan TCP/UDP, enumerate versions, then run targeted NSE scripts per service.
- Tune performance with -T, --min-rate, and -n; adapt to filtered environments with -Pn and TCP/UDP probes.
- Save outputs (-oA) and parse them to feed subsequent, focused scans.
- Stick to default/safe scripts unless ROE permits intrusive or brute-force categories.
- The goal is to quickly build an accurate service map, extract actionable details (versions, banners, shares, methods), and prioritize further testing.