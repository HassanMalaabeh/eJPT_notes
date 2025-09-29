# 01 - Network Mapping (Host Discovery)

Note: No transcript was provided. The following is a conservative, eJPT-focused summary inferred from the filename and folder (03-HostDiscovery). Commands and flags reflect standard eJPT techniques for network mapping and host discovery.

## What the video covers (Introduction / big picture)
- The purpose of network mapping in a penetration test: identify live hosts, gateways, and subnets before deeper enumeration.
- Differences between local network discovery (same broadcast domain) vs remote/VPN discovery.
- Common discovery techniques: ARP scans, ICMP echo, TCP/UDP probe pings.
- Choosing and tuning tools (nmap, arp-scan, netdiscover, fping) and understanding when ICMP is blocked.
- Producing a clean list of live targets for subsequent port scanning.

## Flow (ordered)
1. Establish scope and identify your interface and subnet.
2. Identify the default gateway and confirm connectivity.
3. Pick the discovery technique based on where you are:
   - Local LAN: ARP-based discovery (fast, reliable).
   - Remote/VPN/segmented networks: ICMP/TCP/UDP ping probes.
4. Run host discovery with multiple probes to bypass filters.
5. Validate results with ARP/neighbor tables.
6. Export/normalize live hosts into a clean list for later scans.
7. (Optional) On Windows, use PowerShell/Test-Connection for sweeps.

## Tools highlighted
- Linux:
  - ip (ip addr/ip route/ip neigh) to inspect interfaces, routes, and ARP/neighbor cache.
  - nmap for host discovery (-sn) with ICMP/TCP/UDP/ARP pings, saving outputs.
  - arp-scan for fast ARP enumeration on local segments.
  - netdiscover for ARP-based discovery (active/passive).
  - fping for fast ICMP sweeps.
  - traceroute (optional) to understand upstream routing.
- Windows:
  - ipconfig, route print, arp -a.
  - PowerShell Test-Connection for ping sweeps.

## Typical command walkthrough (detailed, copy-paste friendly)

Identify interface, subnet, and gateway:
```bash
# Show interfaces and addresses (Linux)
ip -br a

# Show route table and default gateway
ip route

# Quick default route/gateway check
ip route get 1.1.1.1
```

Export interface and network CIDR (adjust IFACE if needed):
```bash
# Pick an interface you intend to use (e.g., eth0, wlan0, tun0)
IFACE=$(ip route | awk '/default/ {print $5; exit}')
echo "Interface: $IFACE"

# Get the CIDR for that interface (set manually if multiple)
NET=$(ip -o -f inet addr show "$IFACE" | awk '{print $4}')
echo "CIDR: $NET"

# If you need to override manually:
# IFACE=tun0
# NET=10.10.10.0/24
```

Local LAN (same broadcast domain) – ARP-based discovery:
```bash
# arp-scan (fast; shows MAC vendors; requires sudo)
sudo arp-scan -I "$IFACE" "$NET"

# netdiscover (active ARP sweep)
sudo netdiscover -i "$IFACE" -r "$NET"

# nmap ARP ping scan (disable DNS for speed/noise)
sudo nmap -sn -PR -n -e "$IFACE" "$NET" -oG - | awk '/Up$/{print $2}' | sort -V | tee live_hosts.txt
```

Remote/VPN/segmented networks – ICMP/TCP/UDP host discovery:
```bash
# ICMP echo ping sweep with nmap
sudo nmap -sn -PE -n "$NET" -oG - | awk '/Up$/{print $2}' | sort -V | tee hosts_icmp.txt

# Mixed probes to bypass ICMP filtering (TCP SYN to common ports, TCP ACK, UDP 53)
sudo nmap -sn -PS22,80,443,3389 -PA80,443 -PU53 -n "$NET" -oG - | awk '/Up$/{print $2}' | sort -V | tee hosts_mixed.txt

# fping sweep (fast ICMP; prints only alive hosts)
fping -a -g "$NET" 2>/dev/null | sort -V | tee hosts_fping.txt
```

Merge and deduplicate discovered hosts:
```bash
cat live_hosts.txt hosts_icmp.txt hosts_mixed.txt hosts_fping.txt 2>/dev/null | sort -V -u > live_all.txt
wc -l live_all.txt
```

Validate with ARP/neighbor table (useful on local segments):
```bash
# Current ARP/neighbor entries with state
ip neigh show | sort -V

# Only entries considered reachable
ip neigh | awk '/REACHABLE|STALE|DELAY|PROBE/ {print $1, $5}'
```

Optional: quick connectivity check to a few hosts:
```bash
while read -r h; do ping -c1 -W1 "$h" >/dev/null && echo "OK $h" || echo "NO $h"; done < live_all.txt
```

Basic Bash ping sweep (portable fallback):
```bash
NETBASE=$(echo "$NET" | cut -d/ -f1 | cut -d. -f1-3)
for i in $(seq 1 254); do
  ip="$NETBASE.$i"
  ping -c1 -W1 "$ip" >/dev/null && echo "$ip"
done | tee hosts_basic.txt
```

Windows equivalents:
```powershell
# Interface and IP info
ipconfig
route print
arp -a

# PowerShell ICMP sweep (edit $net accordingly)
$net = "192.168.1"
1..254 | ForEach-Object {
  $ip = "$net.$_"
  if (Test-Connection -Count 1 -Quiet -TimeoutSeconds 1 $ip) { $ip }
} | Tee-Object -FilePath hosts_win.txt
```

Traceroute (optional, to visualize path/gateway):
```bash
traceroute 8.8.8.8
```

Notes:
- -sn in nmap disables port scanning; it performs host discovery only.
- -n skips reverse DNS for speed and stealth.
- -PR forces ARP pings (only effective on local Ethernet segments).
- Use sudo for ARP and some raw probe types.

## Practical tips
- Local vs remote matters: prefer ARP on local LAN; use ICMP/TCP/UDP probes on remote/VPN networks where ARP does not traverse.
- Combine probes: ICMP may be filtered; add -PS/-PA/-PU to increase hit rate.
- Disable DNS resolution (-n) to speed up and reduce noise.
- Save outputs in parseable formats: nmap -oG - and awk for fast extraction.
- Root privileges: arp-scan, ARP-based nmap, and some raw probes require sudo.
- Tuning and safety: avoid aggressive timing; discovery can still trip IDS/IPS. Start with default or -T3; only increase if needed.
- MAC vendor clues: arp-scan output can hint at device types (printers, network gear).
- Verify scope: on VPN labs (typical in eJPT), ensure you’re scanning the tun0 network, not your home LAN.
- Don’t blindly use -Pn for discovery; it treats all hosts as “up” and jumps straight to port scans, wasting time on dead IPs.

## Minimal cheat sheet (one-screen flow)
```bash
# 1) Pick interface and network (edit as needed)
IFACE=$(ip route | awk '/default/ {print $5; exit}')
NET=$(ip -o -f inet addr show "$IFACE" | awk '{print $4}')
echo "$IFACE -> $NET"

# 2) Local LAN (ARP) discovery
sudo nmap -sn -PR -n -e "$IFACE" "$NET" -oG - | awk '/Up$/{print $2}' > live.txt

# 3) Remote/VPN discovery (mixed probes)
sudo nmap -sn -PE -PS22,80,443,3389 -PA80,443 -PU53 -n "$NET" -oG - | awk '/Up$/{print $2}' >> live.txt

# 4) fping sweep (extra coverage)
fping -a -g "$NET" 2>/dev/null >> live.txt

# 5) Clean list
sort -V -u live.txt > live_all.txt; wc -l live_all.txt; head live_all.txt

# 6) Validate with neighbor table (local)
ip neigh | awk '/REACHABLE|STALE|DELAY|PROBE/ {print $1, $5}'
```

## Summary
- Network mapping in host discovery focuses on finding live hosts and gateways before deeper enumeration.
- On local networks, ARP-based discovery is fastest and most reliable (arp-scan, netdiscover, nmap -PR).
- On remote/VPN networks, use ICMP, TCP SYN/ACK, and UDP ping probes with nmap and fping; combine methods to handle filtering.
- Always save and normalize results into a clean target list for subsequent port scans.
- Keep scans efficient and minimally noisy: disable DNS resolution, choose appropriate timing, and run as root where necessary.