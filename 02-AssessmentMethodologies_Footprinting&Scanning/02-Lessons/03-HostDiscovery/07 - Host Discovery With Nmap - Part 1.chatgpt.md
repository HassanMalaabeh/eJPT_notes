# 07 - Host Discovery With Nmap - Part 1

Note: The transcript isn’t provided; the following is a conservative, eJPT-aligned summary based on the filename and typical Nmap host discovery workflows.

## What the video covers (Introduction / big picture)
- The difference between host discovery and port scanning in Nmap.
- How to identify live hosts on a network quickly and reliably before deeper scans.
- Core Nmap host discovery options: ARP ping, ICMP ping, TCP SYN/ACK pings, UDP ping.
- When to use each technique (local LAN vs remote network, ICMP-blocked networks).
- Speed, accuracy, and output best practices for feeding later scans.

## Flow (ordered)
1. Define scope and identify your subnet/interface.
2. Perform a fast local LAN sweep with ARP (most reliable on the same broadcast domain).
3. Use ICMP-based discovery for general reachability (remote networks).
4. Add TCP SYN/ACK probes to catch ICMP-blocked hosts.
5. Optionally add UDP probes for services often allowed (DNS/SNMP).
6. Tune speed and disable DNS to reduce noise and time.
7. Save and parse results into a clean host list for later port scanning.
8. If discovery still misses hosts, plan to scan targets with -Pn during port scans.

## Tools highlighted
- Nmap (primary)
- ip (to identify local network info)
- awk/grep (parse Nmap results)
- tee (save output while viewing)
- Optional: sudo/Administrator privileges for raw packet features

## Typical command walkthrough (detailed, copy-paste friendly)

Replace 10.10.10.0/24 with your target subnet.

1) Identify your interface and subnet (Linux)
```
ip -br -4 addr show
ip route show
```

2) Quick, reliable local LAN discovery (ARP ping)
- Use on the same L2 network. ARP often finds hosts even if ICMP is blocked.
```
sudo nmap -sn -PR -n 10.10.10.0/24 -oA hd_arp
```
- See why Nmap marked hosts up:
```
sudo nmap -sn -PR -n --reason 10.10.10.0/24
```

3) General ICMP discovery (remote-friendly)
```
sudo nmap -sn -n -PE 10.10.10.0/24 -oA hd_icmp
```
- Add other ICMP probes (timestamp, netmask) if needed:
```
sudo nmap -sn -n -PE -PP -PM 10.10.10.0/24 -oA hd_icmp_plus
```

4) TCP SYN/ACK discovery to catch ICMP-blocked hosts
- SYN probes to common ports that are likely open:
```
sudo nmap -sn -n -PS22,80,443,3389 10.10.10.0/24 -oA hd_syn
```
- ACK probes that can traverse certain filters:
```
sudo nmap -sn -n -PA80,443 10.10.10.0/24 -oA hd_ack
```
- Combine ICMP + SYN + ACK for better coverage:
```
sudo nmap -sn -n -PE -PS22,80,443,3389 -PA80,443 10.10.10.0/24 -oA hd_mix
```

5) UDP discovery (optional; often blocked, but useful for DNS/SNMP-heavy networks)
```
sudo nmap -sn -n -PU53,161 10.10.10.0/24 -oA hd_udp
```

6) Speed and noise controls
- Disable DNS lookups:
```
-n
```
- Use a faster timing template (be considerate on production networks):
```
-T4
```
- Limit scope or exclude specific hosts:
```
--exclude 10.10.10.1,10.10.10.255
--excludefile exclude.txt
```
- Example fast mixed probe with exclusions:
```
sudo nmap -sn -n -T4 -PE -PS22,80,443,3389 -PA80,443 --exclude 10.10.10.1 10.10.10.0/24 -oA hd_fast
```

7) Save and parse live hosts for later scans
- Greppable output to live host list:
```
sudo nmap -sn -n 10.10.10.0/24 -oG - | awk '/Up$/{print $2}' | tee live_hosts.txt
```
- Use the list as input to later port scans:
```
sudo nmap -sS -p- -T4 -n -iL live_hosts.txt -oA ports_full
```

8) If discovery fails (heavily filtered networks)
- Consider scanning known targets with -Pn (skip host discovery) during port scans:
```
sudo nmap -sS -p- -T4 -n -Pn 10.10.10.50 -oA no_ping_scan
```
Note: -Pn is for port scanning when host discovery is unreliable; it treats targets as up.

9) Show reasons and debugging (helpful while tuning)
```
sudo nmap -sn -n --reason --stats-every 10s 10.10.10.0/24
```

## Practical tips
- Prefer ARP discovery (-PR) on local subnets; it’s the most accurate for LANs. Nmap typically uses ARP on local Ethernet automatically, but being explicit is fine.
- Many networks block ICMP; add TCP SYN/ACK pings (-PS/-PA) to avoid false negatives.
- Use -n to skip DNS and speed up host discovery; DNS can be slow and noisy.
- Run Nmap with sudo/Administrator rights to enable raw packet features (ICMP/ARP) and get accurate results.
- Choose TCP ports that are likely to be allowed in that environment (e.g., 80/443 in corporate, 22 for servers, 3389 for Windows-heavy).
- UDP pings (-PU) can help on networks where DNS/SNMP is reachable, but closed UDP ports may not respond (don’t rely on -PU alone).
- Always save raw output (-oA) and parse with -oG + awk/grep to create clean host lists for the next phase.
- Use --reason to understand what triggered a host as “Up”; this guides which probes to favor.
- Be deliberate with timing (-T4) and rate on production networks; faster isn’t always better for stability or stealth.

## Minimal cheat sheet (one-screen flow)

Local LAN (ARP, fast and reliable):
```
sudo nmap -sn -PR -n 10.10.10.0/24 -oG - | awk '/Up$/{print $2}' > live.txt
```

Remote subnet (ICMP + TCP mix):
```
sudo nmap -sn -n -PE -PS22,80,443,3389 -PA80,443 10.10.20.0/24 -oG - | awk '/Up$/{print $2}' > live.txt
```

Optional UDP assist:
```
sudo nmap -sn -n -PU53,161 10.10.20.0/24 -oG - | awk '/Up$/{print $2}' >> live.txt
```

Exclude sensitive hosts:
```
sudo nmap -sn -n --exclude 10.10.10.1,10.10.10.255 10.10.10.0/24 -oA hd_excl
```

Scan the live hosts later:
```
sudo nmap -sS -p- -T4 -n -iL live.txt -oA ports_full
```

Understand why hosts are up:
```
sudo nmap -sn -n --reason 10.10.10.0/24
```

## Summary
This session focuses on using Nmap for efficient host discovery without port scanning: -sn to perform ping sweeps, -PR (ARP) for local LANs, -PE/-PP/-PM for ICMP-based probing, and -PS/-PA/-PU to catch hosts that block ICMP. It emphasizes combining probes for coverage, tuning speed and DNS resolution for performance, saving/parsing results cleanly, and when to fall back to -Pn during later port scans if host discovery is unreliable.