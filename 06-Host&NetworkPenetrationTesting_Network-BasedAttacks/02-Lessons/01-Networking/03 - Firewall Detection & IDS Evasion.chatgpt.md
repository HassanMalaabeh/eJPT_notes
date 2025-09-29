# 03 - Firewall Detection & IDS Evasion (eJPT)

Note: No transcript was provided. The notes below are inferred from the filename and typical eJPT curriculum for “Firewall Detection & IDS Evasion” in a Networking module. Commands and tactics are conservative, exam-appropriate, and intended for authorized testing only.

## What the video covers (Introduction / big picture)
- Differentiating firewalls, IDS, and IPS at a network level (stateless vs stateful filtering; IDS detect-only vs IPS blocking).
- Detecting the presence and behavior of filtering devices using scan responses and traceroute/TTL behavior.
- Choosing scanning techniques that minimize alarms and avoid common defensive controls.
- Using Nmap, hping3, traceroute/nping, and packet capture to:
  - Identify filtered vs open|filtered ports.
  - Confirm stateful inspection vs ACLs.
  - Tune scan timing, fragmentation, decoys, and source-port to reduce detection.
- Building a practical workflow: baseline discovery → firewall/IDS detection → evasive scanning → validate with packet capture.

## Flow (ordered)
1. Baseline discovery: host discovery (ping sweep), basic SYN or Connect scan on targets.
2. If host discovery is blocked, switch to -Pn and TCP-based discovery probes.
3. Detect filtering/firewall type:
   - Nmap ACK scan (-sA) across ports to infer stateful inspection.
   - Traceroute/TTL-based probes to locate filtering hop.
4. Adapt scanning strategy:
   - Slow down, avoid ping, restrict ports, and use stealthy techniques.
   - Consider TCP source-port tricks, probe types, and UDP specifics.
5. Evasion options to try cautiously:
   - Timing (-T0–T2), --max-rate, --scan-delay.
   - Fragmentation (-f/--mtu), data padding, decoys (-D).
   - Source port spoofing (--source-port/-g).
6. Validate and interpret:
   - Use tcpdump/Wireshark.
   - Read Nmap “filtered”/“unfiltered”/“open|filtered” correctly.
7. Move to targeted service enumeration (sV, banner grabbing) with conservative rates.

## Tools highlighted
- nmap and nping (host discovery, port scanning, ACK/NULL/FIN/Xmas scans, traceroute, TTL control, decoys, fragmentation).
- hping3 (craft TCP/UDP/ICMP with flags/TTL; traceroute-like probing).
- traceroute/tcptraceroute (ICMP/TCP/UDP path discovery).
- tcpdump / Wireshark (packet capture to confirm filtering/IPS resets).
- fping (fast ICMP sweep; often blocked, useful in permissive networks).

## Typical command walkthrough (detailed, copy-paste friendly)
Only test on systems you own or have explicit authorization to assess.

```bash
# Set handy variables
export SUBNET="10.10.10.0/24"
export TARGET="10.10.10.10"

# 1) Baseline discovery (expect ICMP to be blocked in many environments)
nmap -sn -n $SUBNET

# If host discovery is blocked, skip ping and probe TCP directly
nmap -Pn -sn -n --top-ports 10 $SUBNET

# 2) Quick low-noise TCP SYN probe of common ports (slow timing)
sudo nmap -sS -Pn -n --top-ports 100 -T2 --max-rate 50 --defeat-rst-ratelimit $TARGET

# 3) Firewall presence/type detection with ACK scan
# - Statefully filtered ports ⇒ "filtered" (no RST returned)
# - Not filtered (no stateful FW) ⇒ "unfiltered" (RST returned)
sudo nmap -sA -Pn -n -p 1-1000 --reason -vv $TARGET

# 4) Traceroute/TTL-based hints about filtering hop
# TCP-based traceroute to a likely-allowed port (e.g., 80/443)
sudo traceroute -T -p 80 -n $TARGET
# Or with nmap’s traceroute
sudo nmap -Pn -n -p 80 --traceroute $TARGET
# Or precise probes with hping3
sudo hping3 -S -p 80 --traceroute -V $TARGET

# 5) Evasive SYN scan (stealthy timing, no ping, avoid DNS)
sudo nmap -sS -Pn -n -p- -T2 --max-rate 50 --scan-delay 50ms $TARGET

# 6) Try source-port trick (sometimes bypasses poor ACLs; validate legality)
# Using DNS (53) as spoofed source port
sudo nmap -sS -Pn -n -p 22,80,443 --source-port 53 --reason $TARGET
# Cross-check with hping3
sudo hping3 -S -s 53 -p 22 -c 3 $TARGET

# 7) Decoys to obfuscate origin in logs (ensure it’s permitted; can cause collateral alerts)
sudo nmap -sS -Pn -n -p- -D RND:5,ME --reason -T2 $TARGET
# Or specify decoy IPs (replace with routable IPs you control/are allowed to use)
# sudo nmap -sS -Pn -n -p- -D 198.51.100.10,203.0.113.5,ME $TARGET

# 8) Fragmentation (often dropped by modern networks; use cautiously)
sudo nmap -sS -Pn -n -p- -f --mtu 8 --data-length 24 -T2 $TARGET

# 9) UDP with care (slow, many "open|filtered"; prefer top ports)
sudo nmap -sU -Pn -n --top-ports 20 --max-retries 1 --max-rate 20 --defeat-icmp-ratelimit $TARGET
# Source-port 53 sometimes helps with DNS-related allowances
sudo nmap -sU -Pn -n -p 53,67,68,123,161 --source-port 53 --max-retries 1 $TARGET

# 10) Validate behavior with packet capture (on your interface)
# Watch for ICMP type/code (e.g., 3/13 admin prohibited), TCP RSTs, IPS-injected RSTs
sudo tcpdump -ni any 'icmp or (tcp and (port 22 or port 80 or port 443))'

# 11) When you identify services, enumerate gently
sudo nmap -sV -sS -Pn -n -p 22,80,443 --version-light -T2 $TARGET
# Banner grabs (rate-limit yourself)
printf "" | timeout 3 bash -c "exec 3<>/dev/tcp/$TARGET/80; echo -e 'HEAD / HTTP/1.0\r\n\r\n' >&3; cat <&3"
openssl s_client -connect $TARGET:443 -servername $TARGET -brief </dev/null
```

Interpretation quick reference:
- Nmap “filtered”: No response; likely a firewall dropped the probe.
- “open|filtered”: Indistinguishable (e.g., UDP no reply); needs corroboration.
- ACK scan “unfiltered”: RST came back ⇒ no stateful filter blocking that port.
- ICMP dest unreachable admin-prohibited (Type 3, Code 13): Filter encountered.
- IPS behavior may inject TCP RSTs or temporarily block your source.

Advanced (optional, exam-dependent):
```bash
# Idle/Zombie scan to avoid direct attribution (requires a suitable zombie host)
# Verify potential zombie has predictable IP ID and is idle before use.
sudo nmap -sI 10.10.10.20 $TARGET -p 80
```

## Practical tips
- Always get written authorization; many evasion techniques can trigger alerts or blocks.
- Prefer correctness over cleverness: first get reliable baselines, then add evasion if needed.
- Use -n to avoid DNS noise; -Pn when ICMP is filtered.
- Lower rates and add delays to reduce IDS signature hits: -T2, --max-rate, --scan-delay.
- ACK scans (-sA) are for filtering detection, not for finding open ports; follow up with SYN scans.
- Decoys and fragmentation can distort results; validate with packet capture.
- Source-port tricks only help against naïve ACLs; stateful devices usually ignore them.
- UDP is noisy and slow; target a shortlist of likely services first (53, 67/68, 123, 161).
- Save results: -oA baseline; compare deltas when changing techniques.
- Watch for rate limiting: --defeat-icmp-ratelimit and --defeat-rst-ratelimit help interpret, not magically bypass.

## Minimal cheat sheet (one-screen flow)
```bash
# Discovery
nmap -sn -n 10.10.10.0/24 || nmap -Pn -sn -n --top-ports 10 10.10.10.0/24

# Detect filtering (stateful?)
sudo nmap -sA -Pn -n -p 1-1000 --reason -vv 10.10.10.10

# Traceroute to confirm where filtering happens
sudo traceroute -T -p 80 -n 10.10.10.10

# Stealthy SYN scan
sudo nmap -sS -Pn -n -p- -T2 --max-rate 50 --scan-delay 50ms 10.10.10.10

# Source-port trick
sudo nmap -sS -Pn -n -p 22,80,443 --source-port 53 --reason 10.10.10.10

# Decoys (if allowed)
sudo nmap -sS -Pn -n -p- -D RND:5,ME -T2 10.10.10.10

# Fragmentation (use cautiously)
sudo nmap -sS -Pn -n -p- -f --mtu 8 --data-length 24 -T2 10.10.10.10

# UDP shortlist
sudo nmap -sU -Pn -n --top-ports 20 --max-retries 1 --max-rate 20 10.10.10.10

# Validate with capture
sudo tcpdump -ni any 'icmp or tcp port 22 or tcp port 80 or tcp port 443'
```

## Summary
- Detecting firewalls/IDS relies on how probes are handled: ACK scans for stateful filtering, traceroute/TTL to locate filtering hops, and Nmap response states (“filtered”, “open|filtered”) to guide next steps.
- IDS evasion is about reducing signatures and noise: slower timing, fewer probes, avoiding DNS/ICMP where blocked, and selectively using decoys, fragmentation, and source-port tricks.
- Always validate changes with packet capture and keep results reproducible. Use evasion only as needed and within scope.