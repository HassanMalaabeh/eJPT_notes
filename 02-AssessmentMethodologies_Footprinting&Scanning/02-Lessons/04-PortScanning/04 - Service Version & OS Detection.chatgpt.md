# What the video covers (Introduction / big picture)
Note: No transcript was provided. The notes below are inferred from the filename and module context (04-PortScanning). They reflect standard eJPT practice for Nmap service version detection (-sV) and OS detection (-O).

- How to identify what services are running on open ports and which exact versions they are using (service fingerprinting).
- How to fingerprint a target’s operating system using TCP/IP stack behavior.
- When and how to use Nmap’s -sV, -O, and -A options, and how to tune intensity and reliability.
- How to validate and enrich Nmap results with quick manual banner grabs and useful NSE scripts.
- Common pitfalls: privileges, firewalls/IDS, insufficient open/closed ports for OS detection, false positives, and scan noise.

## Flow (ordered)
1. Start from a basic port scan to identify open ports.
2. Run service version detection (-sV) on discovered ports.
3. Run OS detection (-O); optionally use --osscan-guess if initial detection is inconclusive.
4. If needed, increase/decrease version detection intensity to trade speed vs accuracy.
5. Enrich results with default scripts (-sC) or specific NSE scripts for common services.
6. Cross-check key banners manually (nc/curl/openssl) to confirm versions.
7. Save outputs (-oN/-oA), and use results to guide enumeration/exploitation.

## Tools highlighted
- Nmap core:
  - -sV: Service version detection
  - -O: OS detection
  - -A: Aggressive scan (combines -sV -sC -O --traceroute)
  - -sS/-sT/-sU: TCP SYN/Connect and UDP scanning modes
  - -sC: Default script set (safe, discovery)
  - --version-intensity, --version-all, --version-light, --version-trace
  - --osscan-guess, --max-os-tries, --osscan-limit
  - -Pn, -n, -T4, -p/-p-, --top-ports, -F
  - -oN/-oG/-oX/-oA for output
  - --reason, --packet-trace (diagnostics)
- NSE scripts (examples):
  - banner, http-title, http-headers, ssl-cert, ssh2-enum-algos, ssh-hostkey, rdp-enum-encryption, smb-os-discovery, nbstat
- Manual banner grabbing:
  - nc (netcat), curl, openssl s_client, telnet
- Reference data:
  - Nmap probe DB path: /usr/share/nmap/nmap-service-probes (Linux)

## Typical command walkthrough (detailed, copy-paste friendly)
Tip: Run with sudo for SYN scans (-sS) and reliable OS detection (raw sockets). Replace TARGET as needed.

Setup
```bash
export TARGET=10.10.10.10
```

1) Quick service/version and basic enumeration on common TCP ports
```bash
sudo nmap -Pn -n -T4 -sS -sV -sC --top-ports 1000 -oN sv_quick.txt $TARGET
```

2) Full TCP sweep with version detection (slower but thorough)
```bash
sudo nmap -Pn -n -T4 -sS -p- -sV --version-intensity 7 -oN sv_full_tcp.txt $TARGET
```

3) OS detection (requires at least 1 open and 1 closed TCP port)
```bash
sudo nmap -Pn -n -T4 -sS -O --osscan-guess --max-os-tries 1 -oN os_detect.txt $TARGET
```

4) One-shot aggressive scan (quick triage: service, scripts, OS, traceroute)
```bash
sudo nmap -Pn -n -T4 -A -oN aggressive.txt $TARGET
```

5) UDP top ports with version detection (common services: DNS, NTP, SNMP)
```bash
sudo nmap -Pn -n -sU --top-ports 20 -sV -oN sv_udp_top.txt $TARGET
```

6) Increase/decrease version probing depending on time/noise
```bash
# Lighter/faster (less accurate)
sudo nmap -Pn -n -sS -sV --version-light -p 22,80,443 -oN sv_light.txt $TARGET

# Maximize probes (more accurate, slower)
sudo nmap -Pn -n -sS -sV --version-all -p 22,80,443 -oN sv_max.txt $TARGET
```

7) Debug version detection if a service won’t fingerprint
```bash
sudo nmap -Pn -n -sS -sV --version-trace -p 22,80,443 -oN sv_trace.txt $TARGET
```

8) Useful targeted NSE scripts (adjust ports to what’s open)
```bash
# Web
sudo nmap -Pn -n -p 80,443 --script http-title,http-headers,ssl-cert -oN web_enum.txt $TARGET

# SSH
sudo nmap -Pn -n -p 22 --script ssh2-enum-algos,ssh-hostkey -oN ssh_enum.txt $TARGET

# RDP
sudo nmap -Pn -n -p 3389 --script rdp-enum-encryption -oN rdp_enum.txt $TARGET

# SMB (if 139/445 open)
sudo nmap -Pn -n -p 139,445 --script smb-os-discovery,nbstat -oN smb_enum.txt $TARGET
```

9) Manual banner grabbing (quick confirms)
```bash
# HTTP banner/headers
curl -I http://$TARGET/
curl -kI https://$TARGET/

# Raw HTTP banner (sometimes shows different headers)
printf "HEAD / HTTP/1.0\r\n\r\n" | nc -nv $TARGET 80

# SSH banner
nc -nv $TARGET 22 < /dev/null

# SMTP banner (EHLO to elicit info)
{ sleep 1; echo "EHLO test"; sleep 1; } | nc -nv $TARGET 25

# TLS cert details (validates service type and hostname hints)
openssl s_client -connect $TARGET:443 -servername $TARGET -showcerts </dev/null 2>/dev/null \
| openssl x509 -noout -subject -issuer -dates
```

10) Save all formats for later parsing and reporting
```bash
sudo nmap -Pn -n -T4 -sS -sV -O -p- -oA full_enum $TARGET
# Produces: full_enum.nmap, full_enum.gnmap, full_enum.xml
```

Interpreting key Nmap output fields (generic example)
```
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
```

## Practical tips
- Privileges: -sS and reliable -O typically require sudo (raw sockets). On Windows, run as Administrator with Npcap.
- OS detection prerequisites: Nmap needs at least 1 open and 1 closed TCP port; if all filtered, try scanning more ports or identify a closed port with -p to improve chances.
- Firewalls/IDS: May block OS probes or mangle banners. Expect “Too many fingerprints match” or “No exact OS matches” when filtered.
- Speed vs accuracy:
  - Use --version-light or --top-ports for speed.
  - Use --version-all or --version-intensity 9 for accuracy.
- Be selective with -A: Great for single hosts; too noisy for entire subnets.
- When hosts drop ICMP: Use -Pn to skip ping discovery.
- Save time: -n disables reverse DNS lookups; -T4 is a good default for labs.
- Validate manually: Compare Nmap banners with curl/nc/openssl s_client to confirm.
- Output hygiene: Always use -oA to preserve results for parsing/reporting.
- Probe DB: Know where Nmap’s probes live (/usr/share/nmap/nmap-service-probes) to understand matching.
- UDP: Version detection on UDP is slower and less reliable—target likely services first (53, 123, 161, 500, 69).

## Minimal cheat sheet (one-screen flow)
```bash
export TARGET=10.10.10.10

# Quick triage (TCP common ports): versions + default scripts
sudo nmap -Pn -n -T4 -sS -sV -sC --top-ports 1000 -oN quick.txt $TARGET

# OS detection (guess if needed)
sudo nmap -Pn -n -T4 -sS -O --osscan-guess --max-os-tries 1 -oN os.txt $TARGET

# Full TCP with versions (thorough)
sudo nmap -Pn -n -T4 -sS -p- -sV -oN full_tcp.txt $TARGET

# Targeted NSE by service
sudo nmap -Pn -n -p 80,443 --script http-title,http-headers,ssl-cert -oN web.txt $TARGET
sudo nmap -Pn -n -p 22 --script ssh2-enum-algos,ssh-hostkey -oN ssh.txt $TARGET

# UDP top ports
sudo nmap -Pn -n -sU --top-ports 20 -sV -oN udp.txt $TARGET

# Manual banners
curl -I http://$TARGET/ ; curl -kI https://$TARGET/
printf "HEAD / HTTP/1.0\r\n\r\n" | nc -nv $TARGET 80
nc -nv $TARGET 22 < /dev/null
```

## Summary
This session focuses on converting open ports into actionable intel: exact service names, versions, and probable OS. Start with -sV to fingerprint services, enrich with -sC and targeted NSE scripts, then run -O for OS fingerprinting; use --osscan-guess if necessary. Tune --version-intensity for speed vs accuracy, and use -Pn/-n/-T4 as practical defaults in lab environments. Confirm critical findings with quick manual banner grabs, and always save outputs for later analysis.