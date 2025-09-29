# What the video covers (Introduction / big picture)
Note: The transcript isn’t provided. Based on the filename “02 - Port Scanning With Nmap - Part 2.mp4” in the “04-PortScanning” module, this appears to be a continuation of Nmap scanning fundamentals. Typical Part 2 topics in eJPT courses include:
- Host discovery strategies beyond defaults (-sn, -PR, -PE/-PP, -PS/-PA/-PU).
- UDP scanning (-sU) and when/why to mix TCP/UDP.
- Triage vs deep scans (fast top-ports vs full -p-), and performance tuning (timing, retries, rate).
- Combining scans with service/version detection (-sV, -sC) and saving outputs (-oA).
- Building a practical, repeatable workflow to enumerate targets.

Only scan systems you have explicit permission to test.

# Flow (ordered)
1. Recap Nmap states and basics from Part 1 (open, closed, filtered; -sS vs -sT; port ranges -p).
2. Host discovery/sweeps:
   - Local LAN ARP discovery (-sn -PR).
   - Routed/ICMP-limited networks (-sn with -PE/-PP, TCP/UDP probes -PS/-PA/-PU).
   - When to use -Pn to skip host discovery.
3. Quick TCP triage:
   - Fast scan of common/top ports (-F or --top-ports).
   - Save outputs for parsing (-oA).
4. Full TCP coverage:
   - Full port sweep (-p-) with sane performance flags.
   - Extract open ports per host for focused enumeration.
5. Service/version and default script enumeration:
   - -sV and -sC against discovered open ports.
6. UDP scanning:
   - Targeted top/critical UDP ports (-sU, --top-ports or specific list).
   - Combining TCP+UDP where useful.
7. OS detection/traceroute when needed (-O, --traceroute).
8. Output management and repeatability (-oA, -oG, -oX; ndiff).
9. Tuning tips and pitfalls (timing, DNS resolution, false positives, permissions).

# Tools highlighted
- Nmap core scanner (nmap)
- Nmap Scripting Engine (NSE) via -sC or --script
- ndiff (compare scans; part of Nmap suite)
- Standard Unix text tools (grep, awk, sed, tr, sort, paste) for parsing -oG/.gnmap outputs

# Typical command walkthrough (detailed, copy-paste friendly)
Assume you’re on a Kali/Linux host. Prepend sudo for raw packet scans (SYN/UDP).

1) Identify live hosts (local network, fast ARP)
```
sudo nmap -sn -PR 192.168.1.0/24 -oG - | awk '/Up$/{print $2}' > live.txt
```

2) Identify live hosts (routed network; mix ICMP + TCP/UDP probes)
```
sudo nmap -sn -n -PE -PP -PS80,443 -PA443,3389 -PU53 10.10.0.0/24 -oG - | awk '/Up$/{print $2}' > live.txt
```

3) If pings are blocked but you must scan anyway (treat all as up)
```
# Use with care; will attempt to scan every target
sudo nmap -sS -F -n -Pn -iL live.txt -oA 01_quick_tcp
```

4) Quick TCP triage (common ports) for all live hosts
```
sudo nmap -sS -T4 -F -n -Pn -iL live.txt -oA 01_quick_tcp
```

5) Full TCP scan (all 65535 ports), tuned for lab/LAN
```
sudo nmap -sS -T4 -p- --min-rate 1000 --max-retries 2 -n -Pn -iL live.txt -oA 02_full_tcp
```

6) Extract open TCP ports per host from grepable output
```
# Produces lines like: 10.10.0.5 22,80,443
while read -r ip; do
  ports=$(grep -E "^Host: $ip\b" 02_full_tcp.gnmap \
    | awk -F'Ports: ' 'NF>1{print $2}' \
    | tr ',' '\n' \
    | awk -F/ '$2=="open"{print $1}' \
    | sort -n | paste -sd, -)
  echo "$ip $ports"
done < live.txt > tcp_open_ports.txt
```

7) Service/version + default scripts on discovered TCP ports
```
# Enumerate each host with its open ports list
while read -r ip ports; do
  [ -z "$ports" ] && continue
  sudo nmap -sV -sC -p "$ports" -T4 -n -Pn -oA "03_enum_${ip//./_}" "$ip"
done < tcp_open_ports.txt
```

8) Targeted UDP scan (top UDP or common service ports)
```
# Top 25 UDP ports (fast-ish triage)
sudo nmap -sU --top-ports 25 -T4 -n -Pn -iL live.txt -oA 04_udp_top

# Or: focus on high-value UDP services
sudo nmap -sU -p 53,67,68,69,123,137,161,500,1900 -sV -T4 -n -Pn 10.10.0.5 -oA 04_udp_targeted_10_10_0_5
```

9) Combined TCP+UDP (selected ports)
```
sudo nmap -sS -sU -p T:22,80,443,445,U:53,123,137,161 -T4 -n -Pn -iL live.txt -oA 05_combo
```

10) OS detection and traceroute (optional; more intrusive)
```
sudo nmap -O --osscan-guess --traceroute -T3 -n -Pn -iL live.txt -oA 06_os_trace
```

11) Output management and diffs
```
# Save all formats with one prefix
sudo nmap -sS -F -n -Pn 10.10.0.5 -oA host_10_10_0_5

# Compare two XML scans over time
ndiff 02_full_tcp.xml 02_full_tcp_rescan.xml
```

12) Helpful flags you may add
- Only show hosts with open ports:
```
--open
```
- Show why Nmap decided a state:
```
--reason
```
- Disable reverse DNS lookups (faster, less noisy):
```
-n
```

# Practical tips
- Privileges: SYN scans (-sS) and UDP scans (-sU) need root. Use sudo.
- Discovery choice:
  - On local LAN, ARP scanning (-sn/-PR) is fastest and most reliable.
  - If ICMP is filtered, try TCP/UDP probes (-PS/-PA/-PU). If all discovery fails, use -Pn but expect longer scans and more noise.
- Speed vs accuracy:
  - -T4 is fine in lab/LAN; prefer -T3 on WANs; -T5 often too aggressive.
  - Reduce retries (--max-retries 1-2) and raise rate (--min-rate) only when needed and safe.
- DNS resolution: Use -n to speed scans and reduce noise; resolve later if needed.
- UDP reality: UDP is slow and noisy, often “open|filtered.” Prioritize likely services (53, 123, 161, 137, 69, 500, 1900).
- Workflow: Triage fast (top ports), then full TCP (-p-), then service/version (-sV -sC), then targeted UDP.
- Output: Always save with -oA. Use .gnmap for quick parsing; .xml for tooling and ndiff.
- NSE scope: -sC is safe defaults. Only add broader NSE categories when you understand their impact.
- Ethics/logs: Port scans are visible. Get permission, and expect logging/alerts.

# Minimal cheat sheet (one-screen flow)
```
# 1) Find live hosts (LAN)
sudo nmap -sn -PR 192.168.1.0/24 -oG - | awk '/Up$/{print $2}' > live.txt

# 2) Quick TCP triage (common ports)
sudo nmap -sS -T4 -F -n -Pn -iL live.txt -oA 01_quick_tcp

# 3) Full TCP sweep
sudo nmap -sS -T4 -p- --min-rate 1000 --max-retries 2 -n -Pn -iL live.txt -oA 02_full_tcp

# 4) Extract open ports per host
while read -r ip; do
  ports=$(grep -E "^Host: $ip\b" 02_full_tcp.gnmap | awk -F'Ports: ' 'NF>1{print $2}' \
    | tr ',' '\n' | awk -F/ '$2=="open"{print $1}' | sort -n | paste -sd, -)
  echo "$ip $ports"
done < live.txt > tcp_open_ports.txt

# 5) Service/version + default scripts on found TCP ports
while read -r ip ports; do
  [ -z "$ports" ] && continue
  sudo nmap -sV -sC -p "$ports" -T4 -n -Pn -oA "03_enum_${ip//./_}" "$ip"
done < tcp_open_ports.txt

# 6) UDP (top 25)
sudo nmap -sU --top-ports 25 -T4 -n -Pn -iL live.txt -oA 04_udp_top
```

# Summary
This part likely deepens Nmap port scanning by covering host discovery strategies, fast vs comprehensive TCP scans, targeted UDP scanning, and practical performance/output handling. A solid eJPT workflow: discover hosts, triage with fast TCP, fully enumerate TCP ports, run service/version and safe scripts on those ports, then selectively scan UDP. Save everything (-oA), parse grepable output to drive focused enumeration, and tune timing/retry flags to balance speed and reliability.