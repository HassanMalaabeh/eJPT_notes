# 08 - Host Discovery With Nmap - Part 2

Note: The transcript was not provided. The following summary is inferred conservatively from the filename and course context (03-HostDiscovery). The content focuses on practical, advanced Nmap host discovery techniques beyond basic ICMP/ARP from Part 1.

## What the video covers (Introduction / big picture)
- Advanced Nmap host discovery (“ping scan”) methods to find live hosts when simple ICMP or ARP are blocked or insufficient.
- Using TCP SYN/ACK, UDP, SCTP, and IP protocol pings to bypass filtering.
- Combining multiple probe types, choosing ports strategically, speeding up scans, and exporting results for follow-up port scanning.
- Practical flags: -sn, -PS, -PA, -PU, -PY, -PO, -PE/-PP/-PM, -PR, -Pn, -n, -T4, --reason, --packet-trace, -oA/-oG, -iL.

## Flow (ordered)
1. Recap: -sn for host discovery only; ARP (-PR) on local Ethernet; basic ICMP (-PE/-PP/-PM).
2. When ICMP is blocked: TCP-based discovery
   - TCP SYN ping (-PS [ports])
   - TCP ACK ping (-PA [ports])
3. UDP-based discovery: -PU [ports] (DNS/NTP/SNMP likely ports)
4. Less common: SCTP INIT ping (-PY [ports]) and IP protocol ping (-PO [proto numbers])
5. Combining multiple discovery methods for reliability
6. Speed and reliability options: -n, -T4, --reason, --packet-trace, timeouts/rates
7. Output and parsing: -oA/-oG and extracting “Up” hosts for later scans
8. When to use -Pn (skip discovery) and its trade-offs

## Tools highlighted
- Nmap (primary)
- Shell utilities for parsing output: grep, awk, cut
- Optional: sudo (raw socket privileges recommended for ARP, SYN, etc.)

## Typical command walkthrough (detailed, copy-paste friendly)

General notes:
- Use sudo to allow ARP/SYN/ACK pings and raw sockets.
- Add -sn to disable port scanning and perform host discovery only.

1) Local network (Ethernet) — ARP discovery
```
sudo nmap -sn -PR 192.168.1.0/24
```

2) Basic ICMP discovery (often filtered on enterprise networks)
```
sudo nmap -sn -PE 10.10.10.0/24
sudo nmap -sn -PP 10.10.10.0/24
sudo nmap -sn -PM 10.10.10.0/24
```

3) TCP SYN ping — choose likely-allowed ports (e.g., 22, 80, 443, 3389, 445)
```
sudo nmap -sn -PS22,80,443,3389 203.0.113.0/24
```

4) TCP ACK ping — useful through some stateless filters
```
sudo nmap -sn -PA80,443,3389 203.0.113.0/24
```

5) UDP ping — target common UDP services (DNS/NTP/SNMP)
```
sudo nmap -sn -PU53,123,161 203.0.113.0/24
```

6) SCTP INIT ping (less common, can catch SCTP-enabled hosts)
```
sudo nmap -sn -PY22,80,443 203.0.113.0/24
```

7) IP protocol ping — send raw IP packets of chosen protocol numbers
- Common protocol numbers: 1(ICMP), 2(IGMP), 6(TCP), 17(UDP), 47(GRE)
```
sudo nmap -sn -PO1,2,6,17,47 203.0.113.0/24
```

8) Combine multiple discovery methods for higher hit rate
```
sudo nmap -sn -n -T4 --reason \
  -PE -PS22,80,443,3389 -PA80,443 -PU53 \
  203.0.113.0/24
```

9) Inspect what’s happening (why a host is “Up” and what packets are sent)
```
sudo nmap -sn --reason --packet-trace -PS443 203.0.113.5
```

10) Faster/broader sweeps (tune carefully to avoid network issues)
```
sudo nmap -sn -n -T4 --host-timeout 10s --max-retries 1 10.0.0.0/16
```

11) Output and parse live hosts to a file
```
sudo nmap -sn -oA hostdisc -n -PS80,443 -PA443 203.0.113.0/24
awk '/Status: Up/{print $2}' hostdisc.gnmap > live_hosts.txt
```

12) Use discovered hosts as input for subsequent port scans
```
sudo nmap -sS -p 1-1000 -iL live_hosts.txt -oA top1k
```

13) If discovery is blocked, skip it and assume hosts are up (-Pn)
- Use only when you know targets or discovery is unreliable:
```
sudo nmap -Pn -sS -p- -iL targets.txt -oA pn_fullscan
```

14) Force interface or disable DNS for speed/reliability
```
sudo nmap -sn -e eth0 -n -PR 192.168.56.0/24
```

## Practical tips
- Always start with -sn to avoid unintended port scanning during discovery.
- On local Ethernet, ARP (-PR) is most reliable (and is used by default on many systems).
- For remote networks, ICMP may be blocked; use -PS and -PA on common allowed ports:
  - Web: 80,443
  - SSH: 22
  - RDP: 3389
  - SMB: 445
  - Mail: 25,110,143,587,993
- For UDP discovery, pick services that respond or trigger ICMP port unreachables: 53 (DNS), 123 (NTP), 161 (SNMP).
- Combine multiple methods: -PE -PS -PA -PU to maximize detection across varied filters.
- Use -n to skip reverse DNS and speed up large sweeps; add -T4 for faster timing.
- Run with --reason to understand why Nmap considers a host “Up.”
- Use --packet-trace in labs to learn; avoid it on large/production scans.
- Export and parse results: -oG/-oA with awk/grep to build a clean live host list for follow-up scans.
- Resort to -Pn only when necessary; it increases scan time and noise by treating every target as up.

## Minimal cheat sheet (one-screen flow)
```
# LAN (Ethernet) ARP sweep
sudo nmap -sn -PR 192.168.1.0/24

# Remote: ICMP + TCP SYN/ACK combo
sudo nmap -sn -n -T4 --reason -PE -PS22,80,443,3389 -PA80,443 203.0.113.0/24

# Add UDP discovery
sudo nmap -sn -PU53,123,161 203.0.113.0/24

# Parse "Up" hosts from grepable output
sudo nmap -sn -oG hosts.gnmap -n -PS80,443 203.0.113.0/24
awk '/Status: Up/{print $2}' hosts.gnmap > live.txt

# Follow-up port scan of discovered hosts
sudo nmap -sS -p 1-1000 -iL live.txt -oA top1k

# If discovery blocked, skip it (be cautious)
sudo nmap -Pn -sS -p- -iL targets.txt -oA pn_fullscan

# Troubleshoot/learn packet behavior
sudo nmap -sn --reason --packet-trace -PS443 203.0.113.5
```

## Summary
This part builds on basic host discovery by showing how to find live hosts when simple ping is blocked. Use TCP SYN/ACK (-PS/-PA) against likely-open or allowed ports, add UDP (-PU) for services like DNS/NTP/SNMP, and optionally SCTP (-PY) or IP protocol pings (-PO). Combine probes for reliability, accelerate with -n and -T4, and use --reason/--packet-trace to understand results. Export with -oA/-oG and parse to live host lists for targeted port scans. Use -Pn only when discovery is unreliable or intentionally skipped.