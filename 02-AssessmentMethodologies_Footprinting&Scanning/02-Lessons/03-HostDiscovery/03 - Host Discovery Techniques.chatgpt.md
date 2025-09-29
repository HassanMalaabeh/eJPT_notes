# 03 - Host Discovery Techniques

Note: No transcript was provided. The following is a careful, eJPT-aligned summary inferred from the video title and typical course flow for host discovery.

## What the video covers (Introduction / big picture)
- Why host discovery matters: quickly identify live systems to focus subsequent scanning/exploitation.
- Differences between local (same L2 segment) and remote (routed) discovery.
- How ICMP filtering/firewalls affect discovery and how to adapt.
- Core tools and flags for fast, accurate discovery with minimal noise.
- Building a clean target list for next steps (port scanning, enumeration).

## Flow (ordered)
1. Confirm your IP, interface, and target network range.
2. Local-network discovery first (ARP-based) for speed and accuracy.
3. Remote-network discovery with ICMP pings; fall back to TCP/UDP probes if ICMP is blocked.
4. Speed and noise control (DNS off, timing, retries).
5. Save, parse, and deduplicate results into a target list.

## Tools highlighted
- nmap (primary; -sn, -PR, -PE/-PP/-PM, -PS/-PA/-PU, -n, -oG/-oA)
- arp-scan (fast, L2 ARP scan on local segments)
- netdiscover (passive/active ARP discovery on local LAN)
- fping (quick ICMP sweep)
- System utilities: ip/ifconfig/ipconfig, ip neigh/arp -a
- Windows alternatives: PowerShell Test-Connection, cmd ping loops
- Optional/advanced: masscan (very fast TCP/UDP discovery, use carefully)

## Typical command walkthrough (detailed, copy-paste friendly)

Replace IFACE and CIDR with your environment. Use sudo/root for ARP and raw socket probes.

1) Identify interface and network range
```
ip route show default
ip -br addr show
# Example picks
IFACE=eth0
CIDR=192.168.1.0/24
```

2) Local network (same broadcast domain) – ARP-based
- nmap ARP ping sweep (fast, accurate on LAN):
```
sudo nmap -sn -PR -n -e "$IFACE" "$CIDR" -oG - | awk '/Up$/{print $2}' | sort -u | tee live-hosts.txt
```
- arp-scan (vendor info too):
```
sudo arp-scan --interface="$IFACE" --localnet | tee arp-scan.txt
# Extract IPs only
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' arp-scan.txt | sort -u | tee live-hosts.txt
```
- netdiscover:
```
sudo netdiscover -i "$IFACE" -r "$CIDR" | tee netdiscover.txt
```
- fping sweep:
```
sudo fping -a -g "$CIDR" 2>/dev/null | sort -u | tee live-hosts.txt
```
- Check ARP cache after any sweep:
```
ip neigh | awk '/REACHABLE|STALE|DELAY/{print $1}' | sort -u
```

3) Remote networks (routed) – ICMP and TCP/UDP probes
- Pure ICMP echo ping sweep:
```
sudo nmap -sn -PE -n 10.10.10.0/24 -oG - | awk '/Up$/{print $2}' | tee live-icmp.txt
```
- ICMP often blocked? Use TCP SYN/ACK and UDP pings to common allowed services:
```
sudo nmap -sn -n \
  -PS22,80,443,3389 -PA80,443 -PU53,123,161 \
  10.10.10.0/24 -oG - | awk '/Up$/{print $2}' | tee live-multi.txt
```
- Combine ICMP + TCP/UDP in one go:
```
sudo nmap -sn -n -PE -PP -PM -PS443 -PA80,443 -PU53 10.10.10.0/24 \
  -oG - | awk '/Up$/{print $2}' | sort -u | tee live-hosts.txt
```

4) Performance and noise control
- Disable reverse DNS for speed:
```
# Always include -n in discovery scans
```
- Faster timing and fewer retries (use judiciously):
```
sudo nmap -sn -n -T4 --max-retries 1 --min-rate 2000 "$CIDR" -oG - | awk '/Up$/{print $2}'
```

5) Save all formats for later parsing
```
sudo nmap -sn -n "$CIDR" -oA hostdisc
# Produces: hostdisc.nmap, hostdisc.gnmap, hostdisc.xml
```

6) Windows equivalents
- Quick ping sweep (cmd):
```
for /L %i in (1,1,254) do @ping -n 1 -w 200 192.168.1.%i | find "TTL=" && echo 192.168.1.%i
```
- PowerShell:
```
1..254 | ForEach-Object {
  $ip = "192.168.1.$_"
  if (Test-Connection -Quiet -Count 1 -TimeoutSeconds 1 $ip) { $ip }
}
```
- View ARP cache:
```
arp -a
```

7) Optional fast sweeps (use carefully; high packet rates)
- masscan (discover by hitting common ports):
```
sudo masscan 10.10.0.0/16 -p22,80,443,445 --rate 5000 --wait 0 | tee masscan.txt
# Extract IPs
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' masscan.txt | sort -u | tee live-hosts.txt
```

## Practical tips
- On local LANs, prefer ARP (-PR or arp-scan) for accuracy; ARP is not routed.
- On remote targets, start with ICMP (-PE) then add TCP SYN to likely allowed ports (e.g., -PS443, -PS80) if ICMP fails.
- Always use -n to skip DNS and speed things up; enable DNS only when you need names.
- Use -sn to avoid port scanning during discovery; do port scans later on the reduced target set.
- Privileges matter: ARP and raw SYN pings require sudo/root. Without it, nmap falls back to slower connect-based probes.
- Avoid -Pn for broad discovery; it assumes all hosts are up and can waste time. Use it selectively on specific hosts you must scan despite filtering.
- Save grepable output (-oG) and parse with awk/grep to produce clean target lists.
- Respect rate limiting and IDS/IPS; if detection matters, lower timing and widen timeouts (-T2, increase --max-retries).
- Validate results with a second method (e.g., ARP + TCP SYN) before deeper scans.

## Minimal cheat sheet (one-screen flow)
```
# 1) Pick interface and range
IFACE=eth0; CIDR=192.168.1.0/24

# 2) Local LAN (best): ARP
sudo nmap -sn -PR -n -e "$IFACE" "$CIDR" -oG - | awk '/Up$/{print $2}' | tee live.txt
# or
sudo arp-scan --interface="$IFACE" --localnet | awk '/^[0-9]+\./{print $1}' | sort -u | tee live.txt

# 3) Remote net: ICMP first, then TCP/UDP
sudo nmap -sn -PE -n 10.10.10.0/24 -oG - | awk '/Up$/{print $2}' | tee live.txt
sudo nmap -sn -n -PS443 -PA80,443 -PU53 10.10.10.0/24 -oG - | awk '/Up$/{print $2}' | tee -a live.txt
sort -u live.txt -o live.txt

# 4) Speed/noise knobs
#   -n (no DNS), -T4, --max-retries 1, --min-rate 2000

# 5) Save all formats
sudo nmap -sn -n "$CIDR" -oA hostdisc
```

## Summary
This session focuses on rapidly and reliably identifying live hosts before deeper scanning. On local networks, ARP-based discovery is the fastest and most accurate. Across routed networks, start with ICMP echo and add TCP SYN/ACK and UDP probes to bypass ICMP filtering. Use nmap’s -sn with the right ping types, keep DNS off with -n for speed, and save grepable output for easy parsing into a target list. Adjust timing and retries to balance speed versus stealth, and verify findings with multiple probe types where possible.