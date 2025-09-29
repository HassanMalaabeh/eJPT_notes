# 01 - Networking Fundamentals (eJPT) — Study Notes

Note: No transcript was provided. The outline and commands below are inferred conservatively from the filename and typical eJPT “Networking Fundamentals” module content.

## What the video covers (Introduction / big picture)
- Core networking models and concepts that underpin penetration testing:
  - OSI vs TCP/IP models, encapsulation/decapsulation
  - IPv4 addressing, CIDR/subnetting, gateways, DNS, DHCP
  - MAC addressing, ARP, switching vs routing, VLANs (at a high level)
  - TCP vs UDP, ports, 3‑way handshake, ICMP, common services
  - NAT/PAT and basic firewall behavior
- Practical, command-line networking on Linux/Windows:
  - Identifying your interface, IP, route, DNS
  - Connectivity tests (ping, traceroute)
  - Host discovery (ARP/ping sweep)
  - Name resolution (nslookup/dig/host)
  - Port scanning and basic service enumeration (nmap, nc, curl)
  - Packet capture basics (tcpdump/Wireshark)
- Applying fundamentals to early-phase network recon in eJPT labs

## Flow (ordered)
1. Networking models: OSI (7 layers) vs TCP/IP (4/5 layers), how packets flow
2. Addressing essentials:
   - MAC vs IP, ARP role
   - IPv4 structure, private ranges, subnet masks/CIDR
   - Default gateway, DNS, DHCP leases
3. Switching and routing:
   - Broadcast vs unicast vs multicast
   - VLAN (802.1Q) basics, routing tables, static vs dynamic routes
4. Protocols and ports:
   - TCP vs UDP differences, 3-way handshake, common port numbers
   - ICMP (ping), DNS (53), HTTP(S) (80/443), SMB (445), SSH (22), RDP (3389), etc.
5. NAT/PAT and firewall behavior; effect on scans and connectivity
6. Local system footprint discovery (interfaces, IPs, routes, DNS servers)
7. Connectivity verification (ping, traceroute/mtr, TTL/MTU basics)
8. Name resolution and troubleshooting (nslookup/dig/host)
9. LAN host discovery (ARP table, ARP/ping sweeps)
10. Packet capture and filtering (tcpdump/Wireshark)
11. Port scanning and service discovery (nmap)
12. Banner grabbing and simple protocol interaction (nc, curl)
13. Windows equivalents for common tasks

## Tools highlighted
- Linux:
  - ip, ifconfig (legacy), ip route, ip neigh
  - ping, traceroute (or mtr), arping, arp/arp-scan
  - nslookup, dig, host
  - nmap
  - nc (netcat), curl, wget, telnet (legacy)
  - tcpdump, Wireshark
  - ss/netstat
  - ipcalc/sipcalc (optional helpers)
- Windows:
  - ipconfig, route print, arp -a
  - ping, tracert
  - nslookup, Resolve-DnsName (PowerShell)
  - Test-NetConnection (PowerShell)
  - netstat -ano
  - Get-NetIPConfiguration, Get-NetRoute, Get-NetNeighbor (PowerShell)

## Typical command walkthrough (detailed, copy-paste friendly)

Linux (Debian/Ubuntu/Kali-style) unless noted. Replace example IPs/subnets as needed.

1) Identify interface, IP, routes, DNS
```
# Interfaces (brief)
ip -br a

# Default route and interface
ip route
ip -o -4 route show to default

# Store interface and gateway in variables
IFACE=$(ip -o -4 route show to default | awk '{print $5}')
GW=$(ip route | awk '/default/ {print $3}')

echo "Interface: $IFACE, Gateway: $GW"

# Get your IPv4/CIDR on that interface
ip -o -4 addr show dev "$IFACE"

# Get the directly connected network (CIDR)
NET=$(ip route list dev "$IFACE" | awk '/proto kernel/ {print $1; exit}')
echo "Local network: $NET"

# DNS resolvers
cat /etc/resolv.conf
```

Optional helpers (if installed):
```
# ipcalc/sipcalc can help visualize subnets
ipcalc 10.10.10.5/24
sipcalc 10.10.10.5/24
```

2) Connectivity and path
```
# Ping gateway and an internet IP (if allowed)
ping -c 4 "$GW"
ping -c 4 8.8.8.8

# Traceroute (numeric to avoid slow DNS lookups)
traceroute -n 8.8.8.8
```

3) Name resolution
```
# Query A record
dig A example.com +short
# Query PTR (reverse)
dig -x 8.8.8.8 +short
# Using nslookup
nslookup example.com
host example.com
```

4) ARP and LAN discovery
```
# Current ARP cache
ip neigh
arp -a

# ARP scan (install if missing): sudo apt -y install arp-scan
sudo arp-scan --interface="$IFACE" "$NET"

# If arp-scan is unavailable, use an nmap ping sweep
nmap -sn -n "$NET" -oN hosts-ping-sweep.txt
```

5) Packet capture basics (run in one terminal while testing in another)
```
# ICMP echo/echo-reply on your interface
sudo tcpdump -ni "$IFACE" icmp

# Capture TCP SYN packets (scan detection)
sudo tcpdump -ni "$IFACE" 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'

# Save to pcap for Wireshark
sudo tcpdump -ni "$IFACE" -w capture.pcap
```

6) Port scanning and service discovery (nmap)
```
# Quick live-host discovery (already shown)
nmap -sn -n "$NET" -oA discovery

# Fast top ports scan against one host
TARGET=10.10.10.50
nmap -n -Pn -T4 --top-ports 1000 -sS "$TARGET" -oA scan_top1000

# Full TCP scan (all 65k ports) - more thorough
nmap -n -Pn -T4 -sS -p- "$TARGET" -oA scan_fulltcp

# Version detection + default scripts on discovered ports
# Replace 22,80,443 with actual open ports you found
nmap -n -Pn -sV -sC -O -p 22,80,443 "$TARGET" -oA scan_enum
```

7) Service interaction and banner grabbing
```
# Generic TCP banner grab
printf "HEAD / HTTP/1.0\r\n\r\n" | nc -nv "$TARGET" 80

# Simple HTTP checks
curl -I http://$TARGET/
curl -sS http://$TARGET/ | head -n 20

# HTTPS with insecure (ignore cert) and verbose
curl -k -v https://$TARGET/

# DNS banner/records (if DNS service exposed)
dig @${TARGET} version.bind chaos txt +short

# SMB quick check (if smbclient available)
# sudo apt -y install smbclient
smbclient -L //$TARGET/ -N
```

8) Windows equivalents (PowerShell where noted)
```
:: Interface and IP details
ipconfig /all

:: Routing table
route print

:: ARP cache
arp -a

:: Ping and traceroute
ping 8.8.8.8
tracert -d 8.8.8.8

:: DNS resolution
nslookup example.com
powershell -c "Resolve-DnsName example.com"

:: Test TCP port connectivity
powershell -c "Test-NetConnection -ComputerName 10.10.10.50 -Port 80"

:: Active connections/listening ports
netstat -ano

:: PowerShell networking info
powershell -c "Get-NetIPConfiguration"
powershell -c "Get-NetRoute"
powershell -c "Get-NetNeighbor"
```

9) Common ports to remember (non-exhaustive)
- 20/21 FTP, 22 SSH, 23 Telnet, 25 SMTP, 53 DNS, 67/68 DHCP, 80 HTTP, 110 POP3, 123 NTP, 135/137/138/139/445 MSRPC/NetBIOS/SMB, 143 IMAP, 161/162 SNMP, 389 LDAP, 443 HTTPS, 3306 MySQL, 3389 RDP, 5432 Postgres, 5900 VNC, 8080/8443 Alt HTTP/HTTPS

## Practical tips
- Use -n on tools (nmap/traceroute) to disable DNS and speed up scans.
- Expect ICMP to be blocked; “host down” does not mean “no services.” Consider -Pn in nmap judiciously.
- Start broad and get specific: ping/ARP sweep → port scan → version/scripts → protocol interaction.
- Save outputs (-oN/-oA in nmap) for reporting and to avoid re-running expensive scans.
- Know your subnet: private IPv4 ranges are 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
- Watch rate limiting and IDS: tune -T, use --max-rate, and avoid noisy scans unless permitted.
- Packet captures help explain odd behavior (MTU, resets, filtering) and verify handshakes.
- Prefer ip/ss over legacy ifconfig/netstat on modern Linux.
- On segmented networks, traceroute can hint at where filtering/NAT occurs.
- Always operate within allowed scope and authorization.

## Minimal cheat sheet (one-screen flow)
```
# 0) Detect interface, gateway, network
IFACE=$(ip -o -4 route show to default | awk '{print $5}')
GW=$(ip route | awk '/default/ {print $3}')
NET=$(ip route list dev "$IFACE" | awk '/proto kernel/ {print $1; exit}')
echo "IFACE=$IFACE  GW=$GW  NET=$NET"

# 1) Connectivity check
ping -c 2 "$GW" || echo "Gateway not responding"
traceroute -n 8.8.8.8 | head -n 5

# 2) Discover hosts (fallback if arp-scan missing)
nmap -sn -n "$NET" -oN hosts.txt

# 3) Extract live IPs
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}$' hosts.txt > live_ips.txt

# 4) Quick port scans on live hosts (top 100)
mkdir -p scans
while read -r H; do
  nmap -n -Pn -T4 --top-ports 100 -sS "$H" -oN "scans/$H.top100.txt"
done < live_ips.txt

# 5) Deepen on interesting hosts (replace TARGET and ports)
TARGET=$(head -n1 live_ips.txt)
nmap -n -Pn -T4 -sS -p- "$TARGET" -oN "scans/$TARGET.alltcp.txt"
OPEN=$(grep -Eo '^[0-9]+/tcp' "scans/$TARGET.alltcp.txt" | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
[ -n "$OPEN" ] && nmap -n -Pn -sV -sC -O -p "$OPEN" "$TARGET" -oN "scans/$TARGET.enum.txt"

# 6) Grab simple HTTP banner (if 80/8080/443 open)
printf "HEAD / HTTP/1.0\r\n\r\n" | nc -nv "$TARGET" 80 || true
```

## Summary
- Networking fundamentals on eJPT underpin all reconnaissance: understand OSI/TCP-IP models, addressing/ARP, routing/NAT, and core protocols.
- Master a small toolkit to map the network: ip/ipconfig, ping/traceroute, arp/arp-scan, nslookup/dig, nmap, nc/curl, tcpdump/Wireshark.
- Apply a disciplined flow: identify your footprint → verify connectivity → discover hosts → scan ports → enumerate services → interact and validate findings.
- Save results, use numeric/no-DNS options for speed, and adapt to filtering/NAT behaviors commonly encountered in labs and real networks.