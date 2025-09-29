# 03 - Network Layer (eJPT Networking Primer)

Note: No transcript was provided. The following summary is inferred conservatively from the filename and the course context (Networking Primer). Commands and flows reflect typical eJPT-relevant Network Layer topics.

## What the video covers (Introduction / big picture)
- The Network Layer (OSI Layer 3) responsibilities:
  - Logical addressing (IPv4), subnetting/CIDR, routing between networks.
  - How packets move across routers using routing tables and the default gateway.
  - ICMP basics (ping, traceroute), TTL and path discovery.
  - Private vs public IPs, NAT and its impact on testing.
  - MTU/fragmentation and path MTU discovery fundamentals.
- How to verify Layer 3 connectivity and enumerate networks in practice on eJPT labs.

## Flow (ordered)
1. Network Layer purpose in the OSI model.
2. IPv4 addressing:
   - Structure (IP + subnet mask), CIDR notation (/24, /16, etc.), network/broadcast/host ranges.
   - RFC1918 private ranges, loopback, APIPA.
3. Default gateway and routing:
   - Longest-prefix match, routing tables, 0.0.0.0/0 default route.
4. ARP as the glue between L2 and L3 on local networks (mapping IP to MAC).
5. ICMP essentials:
   - Echo request/reply (ping), Time Exceeded, Destination Unreachable (codes).
   - TTL and how traceroute discovers hops.
6. NAT/PAT:
   - Why your private IP differs from your public IP; implications for scans and reachability.
7. MTU and fragmentation:
   - DF bit, path MTU discovery; testing with ping.
8. Practical workflow to verify and enumerate at L3:
   - Check local config → confirm routes → test gateway → test external → traceroute → sweep networks.

## Tools highlighted
- Linux:
  - ip (ip addr, ip route, ip neigh), route, arp
  - ping (ICMP), traceroute (ICMP/UDP/TCP variants), mtr
  - nmap (for ARP/ICMP ping sweeps)
  - ipcalc or sipcalc (CIDR math)
  - curl/wget for public IP checks
  - whois (ownership info)
- Windows:
  - ipconfig, route print, arp -a
  - ping, tracert, pathping
  - PowerShell: Get-NetIPConfiguration, Get-NetRoute
- Optional:
  - hping3 (crafted probes; DF/TTL), fping (fast sweeps)

## Typical command walkthrough (detailed, copy-paste friendly)
Replace placeholders like <TARGET>, <CIDR>, and <GW>.

- Identify local IP, mask, gateway, DNS (Linux):
```
ip -br a
ip route show
cat /etc/resolv.conf
```

- Quick JSON-ish view and source for a route (egress interface and source IP):
```
ip -br a
ip route get 1.1.1.1
```

- Windows equivalents:
```
ipconfig /all
route print
arp -a
```

- Calculate network/broadcast/host range from an IP/CIDR:
```
ipcalc 10.10.10.25/24
# or
sipcalc 10.10.10.25/24
```

- Verify L3 reachability: gateway then Internet:
```
ping -c 4 <GW>
ping -c 4 8.8.8.8
```

- If DNS issues suspected:
```
nslookup google.com
# or
dig +short google.com
```

- Get your public IP (behind NAT):
```
curl -s ifconfig.me
# or
curl -s https://api.ipify.org
```

- Traceroute (ICMP, no reverse DNS lookups for speed):
```
traceroute -n -I 8.8.8.8
```

- TCP traceroute (useful when ICMP is filtered):
```
traceroute -n -T -p 443 <TARGET>
```

- Windows traceroute:
```
tracert -d 8.8.8.8
```

- Check ARP/neighbor table on local LAN:
```
ip neigh
# or
arp -an
```

- Ping with specific TTL (demonstrates hop scoping on Linux; small TTL often elicits "Time Exceeded"):
```
ping -c 1 -t 1 <TARGET>
```

- Path MTU discovery test (DF bit set; adjust -s until it passes):
```
# For standard Ethernet MTU 1500, payload 1472 (+28 bytes IP/ICMP headers) often works:
ping -c 1 -M do -s 1472 8.8.8.8
# Reduce -s (e.g., 1464, 1400, 1300) if "Frag needed" is reported.
```

- Enumerate live hosts on a local subnet via ARP (fast and reliable on same L2):
```
sudo nmap -sn -PR 10.10.10.0/24
```

- Enumerate live hosts on a remote subnet via ICMP Echo:
```
nmap -sn -PE 10.20.30.0/24
```

- Mixed host discovery when ICMP is filtered (TCP SYN to common ports):
```
nmap -sn -PS80,443 -PA80,443 10.20.30.0/24
```

- Observe ownership of a public network block:
```
whois 8.8.8.0/24
```

- Continuous path monitoring (combines ping + traceroute):
```
mtr -ezbw 8.8.8.8
```

- Craft a single TCP SYN with custom TTL/DF (optional, requires hping3):
```
sudo hping3 -S -p 80 --ttl 2 --df -c 1 <TARGET>
```

## Practical tips
- Prefer ip over ifconfig/route; it’s more accurate and ubiquitous on modern Linux.
- Always test the default gateway first; if that fails, focus on local/L2 issues before L3.
- Use -n for traceroute/nmap to avoid slow reverse DNS lookups when mapping paths.
- ICMP may be rate-limited/blocked. Switch to TCP traceroute (-T -p 80/443) or nmap host discovery with -PS/-PA.
- Private vs public: your local 10/172/192 address will differ from curl ifconfig.me. Document both in reports.
- TTL hints OS families (typical defaults): 64 (Linux), 128 (Windows), 255 (network gear). Observed TTL helps infer hop count from source.
- MTU problems cause odd behavior (e.g., some sites unreachable). Validate with ping -M do and adjust size.
- On local LANs, ARP-based discovery (-PR) is superior and faster than ICMP.
- Longest-prefix match rules the route chosen; check ip route get <IP> to see actual path and source IP used.

## Minimal cheat sheet (one-screen flow)
```
# 1) Local info
ip -br a
ip route show
cat /etc/resolv.conf

# 2) Egress/source for Internet
ip route get 1.1.1.1
curl -s ifconfig.me

# 3) Network math
ipcalc 10.10.10.25/24

# 4) Basic reachability
ping -c 4 <GW>
ping -c 4 8.8.8.8

# 5) Path discovery
traceroute -n -I 8.8.8.8
traceroute -n -T -p 443 <TARGET>

# 6) MTU check
ping -c 1 -M do -s 1472 8.8.8.8

# 7) LAN discovery
sudo nmap -sn -PR 10.10.10.0/24

# 8) Remote discovery (ICMP/TCP)
nmap -sn -PE 10.20.30.0/24
nmap -sn -PS80,443 -PA80,443 10.20.30.0/24

# 9) ARP/Neighbor cache
ip neigh
```

## Summary
- The Network Layer (L3) handles logical addressing and routing across networks using IP and routing tables. 
- For eJPT tasks, you’ll regularly:
  - Determine your IP/mask/gateway, confirm routes, and validate connectivity with ping.
  - Use ICMP/TCP traceroute to map paths and understand filtering.
  - Calculate subnets and enumerate hosts via ARP (local) or ICMP/TCP probes (remote).
  - Recognize NAT’s impact on public vs private IP visibility.
  - Diagnose MTU issues when connectivity is flaky.
- Mastering these L3 checks and commands gives you a reliable, fast workflow for the discovery and enumeration phases in typical eJPT labs.