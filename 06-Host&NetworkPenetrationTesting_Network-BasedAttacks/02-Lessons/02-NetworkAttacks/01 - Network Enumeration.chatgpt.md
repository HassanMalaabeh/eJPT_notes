# 02-NetworkAttacks – 01: Network Enumeration (eJPT) — Study Notes

Note: No transcript was provided. The following summary is inferred conservatively from the filename and module context (Network Attacks). Commands and flows are standard, exam-friendly eJPT practices.

## What the video covers (Introduction / big picture)
- Purpose of network enumeration in internal/VPN lab settings: find live hosts, open ports, and fingerprint services.
- Host discovery methods (ARP vs ICMP/SYN), local vs remote networks.
- TCP/UDP port scanning strategies: speed vs accuracy.
- Service enumeration with Nmap NSE and common protocol tools (SMB, SNMP, HTTP, etc.).
- Recording/organizing results for follow-on exploitation.

## Flow (ordered)
1. Confirm IP, interface, and scope (CIDR) on the attack box.
2. Host discovery:
   - Local subnet: ARP-based discovery (fast, accurate).
   - Remote/VPN subnets: ICMP and TCP SYN discovery.
3. Build a target list of live hosts (hosts.txt).
4. Initial port discovery:
   - Fast top-ports or full TCP sweep.
   - Optional: masscan for very large ranges, then validate with Nmap.
5. Targeted enumeration with Nmap:
   - Service/version detection, default scripts, OS detection.
   - Save outputs in multiple formats.
6. UDP checks for common services (DNS, SNMP, NTP, NetBIOS, etc.).
7. Service-specific enumeration (HTTP, SMB, SNMP, FTP, SSH, RDP, DBs).
8. Parse and consolidate results; prioritize attack paths.
9. Adjust techniques for filtering/firewalls (e.g., -Pn, timing, host timeouts).

## Tools highlighted
- System/network basics: ip, ip route, ipcalc (optional), arp
- Host discovery:
  - Local: arp-scan, netdiscover
  - Generic: nmap -sn, fping
- Port scanning: nmap, masscan (optional, then validate with nmap)
- Enumeration:
  - Nmap NSE scripts (smb-enum-*, http-*, snmp-*, vuln)
  - SMB: smbclient, smbmap, enum4linux
  - SNMP: snmpwalk, onesixtyone
  - Web: whatweb, nikto, gobuster/feroxbuster, curl
  - Others: nc (banner grabbing), nbtscan
- Output handling: nmap -oA, -oN, -oG; grep/awk/sed for parsing

## Typical command walkthrough (detailed, copy-paste friendly)
Adjust NET and IF to your lab. Run as sudo for accuracy.

```bash
# 0) Setup
export IF=tun0                     # or eth0, etc.
export NET=10.10.10.0/24           # target subnet (CIDR)
mkdir -p scans

# 1) Understand local context
ip -br a
ip r

# 2) Host discovery
# Local subnet (fast/accurate ARP):
arp-scan -I $IF -l | tee scans/arp-scan.txt

# Generic ICMP/TCP discovery:
nmap -n -sn -PE -PS80,443,3389 -PA22,80 $NET -oA scans/discovery
awk '/Up$/{print $2}' scans/discovery.gnmap | sort -u > hosts.txt
wc -l hosts.txt

# Alternative quick sweep:
# fping -a -g $NET 2>/dev/null | tee hosts.txt

# 3) TCP port discovery (per-host approach: accurate, simple parsing)
while read -r ip; do
  echo "== TCP all-ports for $ip =="
  nmap -n -Pn -T4 -p- --min-rate 2000 -oA scans/${ip}_alltcp $ip
  # Extract open ports to a comma list
  open=$(awk -F/ '/open/{print $1}' scans/${ip}_alltcp.nmap | tr '\n' ',' | sed 's/,$//')
  if [ -n "$open" ]; then
    nmap -n -Pn -sV -sC -O -p "$open" -oA scans/${ip}_detail $ip
  fi
done < hosts.txt

# Optional: masscan (fast discovery; ALWAYS validate with nmap)
# masscan -e $IF -p1-65535 --rate 3000 $NET --wait 0 -oL scans/masscan.lst
# Then validate found ports with targeted nmap as above.

# 4) UDP checks (top common ports or specific)
while read -r ip; do
  echo "== UDP top-25 for $ip =="
  nmap -n -Pn -sU --top-ports 25 --defeat-rst-ratelimit -T4 -oA scans/${ip}_udp_top25 $ip
done < hosts.txt
# Or target typical UDP services:
# nmap -n -Pn -sU -p 53,67,69,123,137,161,500,1900,5353 -oA scans/${ip}_udp_common $ip

# 5) Service-specific enumeration examples

# SMB
while read -r ip; do
  nmap -n -Pn -p 139,445 --script smb-os-discovery,smb-enum-shares,smb-enum-users -oA scans/${ip}_smb $ip
  smbclient -N -L //$ip | tee scans/${ip}_smbclient.txt
  smbmap -H $ip | tee scans/${ip}_smbmap.txt
  enum4linux -a $ip | tee scans/${ip}_enum4linux.txt
done < hosts.txt

# SNMP (check common communities, then walk)
# Quick spray for communities:
# onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-communities-default.txt -i hosts.txt | tee scans/snmp_onesixtyone.txt
# If "public" works, try info walk:
while read -r ip; do
  snmpwalk -v2c -c public -t 1 -r 1 -Oa $ip 1.3.6.1.2.1.1 2>/dev/null | tee -a scans/snmp_public_sysdescr.txt
done < hosts.txt

# HTTP/HTTPS quick triage
while read -r ip; do
  for p in 80 443 8080 8443; do
    timeout 3 bash -c "echo > /dev/tcp/$ip/$p" 2>/dev/null && {
      echo "== Web check $ip:$p =="
      whatweb -a 3 http://$ip:$p 2>/dev/null | tee -a scans/web_whatweb.txt
      nmap -n -Pn -p $p --script http-title,http-headers,http-server-header -oA scans/${ip}_http_$p $ip
      # Directory brute (adjust wordlist):
      # gobuster dir -u http://$ip:$p -w /usr/share/wordlists/dirb/common.txt -q -o scans/${ip}_gobuster_$p.txt
      # nikto -host http://$ip:$p -output scans/${ip}_nikto_$p.txt
    }
  done
done < hosts.txt

# FTP
while read -r ip; do
  nmap -n -Pn -p21 --script ftp-anon,ftp-syst -oA scans/${ip}_ftp $ip
done < hosts.txt

# SSH
while read -r ip; do
  nmap -n -Pn -p22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -oA scans/${ip}_ssh $ip
done < hosts.txt

# 6) Quick OS fingerprinting (if not done above)
# Already included with -O; for stubborn hosts:
# nmap -n -Pn -O --osscan-guess --max-retries 2 --host-timeout 30s -iL hosts.txt -oA scans/osguess

# 7) Collate open ports across all hosts (from *_alltcp.nmap)
grep -h "open" scans/*_alltcp.nmap | sed -E 's/Nmap scan report for ([^ ]+)/\n\1/g' | awk 'NF' > scans/all_open_ports_summary.txt
```

Firewall/IDS evasion flags to consider if discovery seems blocked (use only if needed and allowed):
- -Pn (skip host discovery), -f or --mtu 16 (fragmentation), --scan-delay, --max-retries 2, -T2 (slower), -D RND:10 (decoys), -g 53 (source port), --data-length 25 (pad). Always validate legality and impact.

## Practical tips
- Use -n to skip reverse DNS for speed; always save outputs with -oA.
- Prefer ARP discovery on local subnets; use ICMP/SYN on remote/VPN ranges.
- Scan all TCP ports (-p-) for priority targets; otherwise start with --top-ports 1000.
- Follow up UDP selectively; it’s slower and noisier. Start with 53, 123, 137, 161, 5353.
- When using masscan, always validate with nmap -sV before acting on results.
- If ping is blocked, add -Pn to nmap scans to still probe ports.
- Use --reason and --packet-trace when debugging weird results.
- Exclude your gateway/infrastructure devices when appropriate: --exclude or --excludefile.
- Keep a simple structure for outputs (per-host files) to speed up exploitation later.

## Minimal cheat sheet (one-screen flow)
```bash
# Set scope
export IF=tun0; export NET=10.10.10.0/24; mkdir -p scans

# Host discovery
nmap -n -sn -PE -PS80,443,3389 -PA22,80 $NET -oA scans/discovery
awk '/Up$/{print $2}' scans/discovery.gnmap > hosts.txt

# TCP all-ports per host → detailed enumeration
while read -r ip; do
  nmap -n -Pn -T4 -p- --min-rate 2000 -oA scans/${ip}_alltcp $ip
  open=$(awk -F/ '/open/{print $1}' scans/${ip}_alltcp.nmap | paste -sd, -)
  [ -n "$open" ] && nmap -n -Pn -sV -sC -O -p "$open" -oA scans/${ip}_detail $ip
done < hosts.txt

# UDP quick check
while read -r ip; do nmap -n -Pn -sU --top-ports 25 -oA scans/${ip}_udp $ip; done < hosts.txt

# Common services
while read -r ip; do nmap -n -Pn -p 139,445 --script smb-os-discovery,smb-enum-shares -oA scans/${ip}_smb $ip; done < hosts.txt
while read -r ip; do nmap -n -Pn -p21 --script ftp-anon -oA scans/${ip}_ftp $ip; done < hosts.txt
while read -r ip; do nmap -n -Pn -p22 --script ssh2-enum-algos,ssh-auth-methods -oA scans/${ip}_ssh $ip; done < hosts.txt
```

## Summary
- Network enumeration starts with confirming scope and discovering live hosts using ARP locally and ICMP/SYN remotely.
- Use Nmap for comprehensive TCP scanning and targeted enumeration (-sC -sV -O). Consider UDP for key services.
- Leverage NSE scripts and protocol-specific tools (SMB, SNMP, HTTP) to extract actionable details.
- Save and parse outputs systematically to build a clear target map and prioritize exploitation paths.
- Without the transcript, the above reflects common, safe, and effective eJPT-aligned workflows for internal network enumeration in the Network Attacks module.