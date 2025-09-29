# 01 - Networking Fundamentals (eJPT Networking Primer)

Note: The transcript wasn’t provided. The notes below are inferred conservatively from the filename “01 - Networking Fundamentals.mp4” in the “02-NetworkingPrimer” folder and reflect typical eJPT-oriented networking content.

## What the video covers (Introduction / big picture)
- Core networking models and where attackers/analysts operate:
  - OSI vs TCP/IP layers, encapsulation/decapsulation
  - Layer 2 (MAC/ARP), Layer 3 (IP routing), Layer 4 (TCP/UDP), Layer 7 (applications)
- IP addressing basics:
  - IPv4, private vs public ranges, CIDR, subnet masks, gateways, broadcast addresses
- Foundational protocols:
  - ARP, ICMP, TCP 3-way handshake, UDP, DNS, DHCP, NAT
- Ports and services:
  - Common ports, sockets, ephemeral ports, well-known vs dynamic ranges
- LAN vs WAN considerations:
  - Broadcast domains, VLANs, routing, TTL, MTU/fragmentation
- Practical tooling for eJPT:
  - Enumerating interfaces/routes/DNS, host discovery, basic scanning, name resolution, packet capture

## Flow (ordered)
1. Networking models: OSI ↔ TCP/IP mapping and why it matters for troubleshooting and attacks
2. Addresses and ranges: IPv4, private ranges, subnetting/CIDR, gateways, broadcast, DNS servers
3. L2 discovery with ARP; L3 probing with ICMP; TTL; MTU basics
4. TCP vs UDP behaviors; 3-way handshake; common ports/services
5. Routing: local vs remote networks, default routes, adding static routes
6. Name resolution: DNS queries, forward/reverse lookups, SRV records
7. NAT and what you actually “see” vs external IP
8. Tools and commands to enumerate, discover, and map a target environment
9. Putting it together: a minimal workflow to get oriented on any network

## Tools highlighted
- Linux:
  - ip, ip addr/link/route, ip neigh; ifconfig (legacy)
  - ping, traceroute, mtr
  - arp, arp-scan, netdiscover, fping, nmap
  - dig, host, nslookup
  - ss or netstat
  - tcpdump, tshark, Wireshark
  - ipcalc, sipcalc
  - curl, wget
- Windows:
  - ipconfig, route, arp
  - ping, tracert, pathping
  - netstat, Test-NetConnection
  - nslookup, Resolve-DnsName
  - Get-NetIPAddress, Get-NetRoute, Get-DnsClientServerAddress

## Typical command walkthrough (detailed, copy-paste friendly)
Replace eth0 with your interface; replace networks/hosts as appropriate.

1) Identify your interface, IP, MAC, gateway, DNS (Linux)
```
ip -br link
ip -br a
ip route show
ip route get 1.1.1.1
cat /etc/resolv.conf
```

2) Identify your interface, IP, gateway, DNS (Windows)
```
ipconfig /all
route print
netsh interface ip show config
Get-DnsClientServerAddress
```

3) Quick connectivity and path checks
- Linux:
```
ping -c 4 1.1.1.1
ping -c 1 -W 1 $(ip route | awk '/default/ {print $3}')   # ping default gateway
traceroute -I 1.1.1.1
mtr -rw 1.1.1.1
```
- Windows:
```
ping -n 4 1.1.1.1
tracert 1.1.1.1
pathping 1.1.1.1
```

4) Local network discovery (L2 ARP and ICMP)
- Linux (ARP-based is reliable on the local LAN):
```
arp -an
ip neigh show
sudo arp-scan --interface=eth0 --localnet
sudo netdiscover -r 10.10.20.0/24
```
- Ping sweep (Linux):
```
fping -aqg 10.10.20.0/24
# or with nmap host discovery only:
nmap -sn -n -T4 10.10.20.0/24
```

5) DNS resolution and records
- Linux:
```
dig +short A example.com
dig @1.1.1.1 -x 10.10.20.15 +short
host -t srv _ldap._tcp.domain.local
```
- Windows:
```
nslookup example.com
nslookup 10.10.20.15
Resolve-DnsName example.com
```

6) Ports/services on discovered hosts
- Fast top-ports scan:
```
nmap -Pn -n -T4 --top-ports 1000 10.10.20.15
```
- Full TCP scan then service/version detection:
```
nmap -Pn -n -T4 -p- --min-rate 2000 10.10.20.15 -oA tcp_full
nmap -Pn -n -T4 -sV -sC -p $(cat tcp_full.nmap | awk -F/ '/open/ {print $1}' | paste -sd, -) 10.10.20.15 -oA enum
```
- Quick UDP top ports:
```
nmap -Pn -n -sU --top-ports 100 10.10.20.15 -oA udp_top
```
- Quick checks:
```
ss -tulpen
nc -vz 10.10.20.15 22 80 443
curl -I http://10.10.20.15/
```

7) Routes and adding routes (useful when multiple subnets are present)
- Linux:
```
ip route show
sudo ip route add 172.16.50.0/24 via 10.10.20.1 dev eth0
```
- Windows:
```
route print
route ADD 172.16.50.0 MASK 255.255.255.0 10.10.20.1 METRIC 1
```

8) Packet capture for verification
- Linux:
```
sudo tcpdump -i eth0 -n arp
sudo tcpdump -i eth0 -n host 10.10.20.15 and port 80
sudo tshark -i eth0 -Y "tcp.flags.syn==1 and tcp.flags.ack==0"
```

9) Subnet math helpers
```
ipcalc -b 10.10.20.37/27
sipcalc 192.168.1.37/27
```

10) NAT and external IP check (outbound visibility)
```
curl -s https://ifconfig.me
curl -s https://api.ipify.org
```

## Practical tips
- On a LAN, ARP-based scanning (arp-scan/netdiscover) is more reliable than ICMP; many hosts drop ICMP.
- Use -n with scanners to avoid DNS delays; resolve selectively with dig/host when needed.
- If ping/ICMP is blocked, use nmap -Pn to skip host discovery and probe ports directly.
- Start wide and get precise: host discovery → quick top ports → full TCP → focused scripts/versions.
- Watch TTL in replies for rough OS hints (typical defaults: Linux ~64, Windows ~128, Cisco ~255).
- MTU issues cause weird hangs; test the path MTU if large payloads fail:
  - ping -M do -s 1472 1.1.1.1 (Linux)
- Keep your interface straight (eth0/ens33/wlan0); use ip -br link to list quickly.
- Take note of gateway and DNS early. Misconfigured DNS can make everything seem “down.”
- Multiple subnets? Add routes; don’t rely on the default gateway alone.
- Private ranges to remember: 10.0.0.0/8, 172.16.0.0–172.31.255.255 (/12), 192.168.0.0/16.

## Minimal cheat sheet (one-screen flow)
- Where am I?
```
ip -br a; ip r; cat /etc/resolv.conf
```
- Local ARP/L2 discovery (LAN):
```
sudo arp-scan -I eth0 --localnet
```
- Quick host discovery (L3):
```
nmap -sn -n -T4 10.10.20.0/24
```
- Path and connectivity:
```
ping -c 1 1.1.1.1; traceroute -I 1.1.1.1
```
- DNS checks:
```
dig +short A example.com; dig -x 10.10.20.15 +short
```
- Fast port triage, then enum:
```
nmap -Pn -n -T4 --top-ports 1000 <host>
nmap -Pn -n -T4 -p- --min-rate 2000 <host> -oA tcp_full
nmap -Pn -n -T4 -sV -sC -p $(awk -F/ '/open/ {print $1}' tcp_full.nmap | paste -sd,) <host> -oA enum
```
- Route add if needed:
```
sudo ip route add <NET>/<CIDR> via <GW> dev <IFACE>
```
- Packet verify:
```
sudo tcpdump -i eth0 -n host <host> and port <port>
```
- Subnet helper:
```
ipcalc -b <IP/CIDR>
```

## Summary
This networking fundamentals module grounds you in the models (OSI/TCP-IP), core protocols (ARP, ICMP, TCP/UDP, DNS, DHCP), addressing/subnetting, and the practical tooling needed to orient yourself rapidly on any network—skills you’ll use constantly in eJPT workflows. The provided commands give a ready-to-run sequence: determine your local config, discover hosts, map paths, resolve names, scan ports/services, adjust routes if needed, and verify with packet capture.