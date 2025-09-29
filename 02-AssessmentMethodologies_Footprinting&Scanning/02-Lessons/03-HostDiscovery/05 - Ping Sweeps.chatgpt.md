# 05 - Ping Sweeps

Note: No transcript was provided. The following summary is inferred conservatively from the filename and folder (03-HostDiscovery) and reflects common eJPT techniques and commands for ICMP-based host discovery.

## What the video covers (Introduction / big picture)
- How to quickly find live hosts on a target subnet using ping sweeps (ICMP Echo Requests).
- When and why to use ping sweeps during host discovery.
- Fast, scriptable approaches on Linux and Windows.
- Handling cases where ICMP is filtered, and using Nmap’s host discovery probes.
- Saving and reusing results for later enumeration.

## Flow (ordered)
1. Identify the target subnet/range (e.g., 10.10.10.0/24).
2. Prefer fast tools for local networks (fping, Nmap ARP ping).
3. For remote networks or when ICMP is filtered, use Nmap host discovery with TCP/ARP probes.
4. Fallback: simple Bash/Windows loops using ping.
5. Extract, save, and reuse the list of live IPs.
6. Validate results and adjust timeouts/rates based on latency and filtering.

## Tools highlighted
- fping
  - Key flags: -g (generate IPs from CIDR), -a (alive only), -q (quiet), -r (retries), -t (timeout ms), -p (per-target interval ms)
- Nmap (host discovery)
  - -sn (ping scan/host discovery only)
  - -PR (ARP on local Ethernet), -PE (ICMP Echo), -PP (ICMP Timestamp), -PM (ICMP Address Mask)
  - -PS/-PA (TCP SYN/ACK ping to ports), -oG - (grepable output to stdout)
- ping (system ping)
  - Linux: -c (count), -W (per-probe timeout seconds), -n (no DNS)
  - Windows: -n (count), -w (timeout ms)
- PowerShell
  - Test-Connection -Count 1 -Quiet -TimeoutSeconds

## Typical command walkthrough (detailed, copy-paste friendly)

Assume target range is 10.10.10.0/24. Replace as needed.

Identify your local interface/network (Linux):
```
ip -4 addr show
# Or pull the first global IPv4/CIDR:
ip -o -4 addr show scope global | awk '{print $4}' | head -n1
```

1) Fast local sweep with fping (Linux/Kali)
```
# Alive only, quiet output, no retries, 100ms timeout per host
fping -a -q -g -r 0 -t 100 10.10.10.0/24
# Save results
fping -a -q -g -r 0 -t 100 10.10.10.0/24 > live-hosts.txt
```

2) Nmap host discovery (preferred when ICMP may be filtered or for remote subnets)
- Local Ethernet (uses ARP, very reliable/fast on same LAN):
```
sudo nmap -sn -PR 10.10.10.0/24 -oG - | awk '/Up$/{print $2}' | tee live-hosts.txt
```
- Remote networks or ICMP-restricted (combine ICMP and TCP probes):
```
sudo nmap -sn -PE -PS80,443 -PA80,443 10.10.10.0/24 -oG - | awk '/Up$/{print $2}' | tee live-hosts.txt
```
- ICMP only (if you specifically want only echo requests):
```
sudo nmap -sn -PE 10.10.10.0/24 -oG - | awk '/Up$/{print $2}'
```

3) Bash one-liners (portable, no extra tools)
```
# Simple sequential sweep (omit .0 and .255)
for i in $(seq 1 254); do ip="10.10.10.$i"; ping -c 1 -W 1 -n "$ip" >/dev/null && echo "$ip"; done | tee live-hosts.txt
```
Optional: modest parallelism to speed up (GNU xargs):
```
seq 1 254 | xargs -I{} -P 50 sh -c 'ip="10.10.10.{}"; ping -c1 -W1 -n "$ip" >/dev/null && echo "$ip"' | tee live-hosts.txt
```

4) Windows CMD one-liner
```
for /L %i in (1,1,254) do @ping -n 1 -w 200 10.10.10.%i | find "TTL=" >nul && echo 10.10.10.%i
```
Save to file:
```
(for /L %i in (1,1,254) do @ping -n 1 -w 200 10.10.10.%i | find "TTL=" >nul && echo 10.10.10.%i) > live-hosts.txt
```
Note: Use %%i instead of %i if placing the loop in a .bat/.cmd file.

5) PowerShell (clean and readable)
```
1..254 | ForEach-Object {
  $ip = "10.10.10.$_"
  if (Test-Connection -Count 1 -Quiet -TimeoutSeconds 1 $ip) { $ip }
} | Tee-Object -FilePath live-hosts.txt
```

6) Optional: quick hostname resolution (Linux)
```
for ip in $(cat live-hosts.txt); do getent hosts "$ip" | awk '{print $1, $2}'; done
```

## Practical tips
- Prefer ARP-based discovery on local networks (Nmap -PR) for speed and accuracy; ICMP can be blocked.
- Tune timeouts and retries for environment latency:
  - fping: increase -t or -r for high-latency links; decrease to go faster on LANs.
  - Nmap: reduce false negatives by allowing default retries on remote links; speed up with smaller scopes.
- Save outputs in machine-friendly form for later steps (e.g., -oG with awk, or plain IP lists).
- Watch TTL in ping responses: rough OS hints (Linux ~64, Windows ~128, network gear ~255), but not definitive.
- Avoid broadcast pings (-b) and sweeping huge ranges aggressively; many networks filter or log ICMP.
- If ICMP is heavily filtered, use Nmap TCP SYN/ACK pings (-PS/-PA) to common ports (80,443), or skip discovery and scan known targets directly.

## Minimal cheat sheet (one-screen flow)
```
# Local fast sweep (Linux)
fping -aqg -r 0 -t 100 10.10.10.0/24 > live-hosts.txt

# Nmap ARP (local LAN)
sudo nmap -sn -PR 10.10.10.0/24 -oG - | awk '/Up$/{print $2}' > live-hosts.txt

# Nmap mixed probes (remote/ICMP filtered)
sudo nmap -sn -PE -PS80,443 -PA80,443 10.10.10.0/24 -oG - | awk '/Up$/{print $2}' > live-hosts.txt

# Bash loop
for i in $(seq 1 254); do ip="10.10.10.$i"; ping -c1 -W1 -n "$ip" >/dev/null && echo "$ip"; done > live-hosts.txt

# Windows CMD
(for /L %i in (1,1,254) do @ping -n 1 -w 200 10.10.10.%i | find "TTL=" >nul && echo 10.10.10.%i) > live-hosts.txt

# PowerShell
1..254 | % { $ip="10.10.10.$_"; if (Test-Connection -Count 1 -Quiet -TimeoutSeconds 1 $ip){$ip} } > live-hosts.txt
```

## Summary
- Ping sweeps are a foundational host discovery technique to enumerate live systems on a subnet.
- Use fping or Nmap ARP for fast local results; use Nmap’s flexible probes when ICMP is filtered or for remote targets.
- Have reliable fallbacks (Bash/Windows loops) and always save outputs for subsequent enumeration.
- Tune timeouts/retries based on network conditions and be mindful of filtering and logging on target networks.