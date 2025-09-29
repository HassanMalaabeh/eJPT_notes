# 06 - Transport Layer - Part 2 (eJPT Networking Primer)

Note: No transcript was provided. The following is a careful, conservative summary inferred from the title and module context (Networking Primer). It focuses on typical eJPT-relevant Transport Layer topics and practical workflows.

## What the video covers (Introduction / big picture)
- Deep dive into the Transport Layer (TCP/UDP) with a pentesting lens.
- TCP connection management: three-way handshake, teardown, RST, states, flags.
- UDP’s connectionless behavior and implications for scanning.
- Ports: well-known vs. registered vs. ephemeral; mapping services to ports.
- Practical packet analysis with Wireshark/tcpdump (seeing SYN/SYN-ACK/ACK/FIN/RST).
- Using tools (nmap, netcat, hping3, ss/netstat) to enumerate and understand transport behavior.
- How scan results map to TCP/UDP responses (open, closed, filtered).

## Flow (ordered)
1. Recap: Transport Layer responsibilities (multiplexing via ports, reliability with TCP, best-effort with UDP).
2. TCP header fields and flags: SYN, ACK, FIN, RST, PSH, URG; seq/ack numbers; window size.
3. TCP handshake and teardown:
   - 3-way handshake (SYN → SYN/ACK → ACK).
   - Normal close (FIN/ACK) vs. abort (RST).
4. UDP behavior: no handshake, no reliability; how this affects scanning and service discovery.
5. Port taxonomy:
   - Well-known (0–1023), Registered (1024–49151), Ephemeral (49152–65535 typical, OS-dependent).
   - Mapping: /etc/services and common pentest ports (22, 80, 443, 445, 3389, 53, etc.).
6. On-wire analysis:
   - Observe handshake and flags in Wireshark and tcpdump.
   - Recognize responses indicating open/closed/filtered.
7. Tooling and demos:
   - Enumerate local listeners (ss/netstat/lsof).
   - netcat TCP/UDP listeners and clients.
   - nmap TCP SYN/connect and UDP scans; service/version detection.
   - hping3 to craft packets with specific flags.
8. Pentest implications:
   - Choosing scan types, reading results, reducing noise, and understanding firewall behavior.

## Tools highlighted
- Wireshark: GUI packet capture/analysis; display filters for TCP flags.
- tcpdump: CLI packet capture; flag bitmask filters.
- nmap: TCP SYN (-sS), connect (-sT), UDP (-sU), service/version detection (-sV), reasons.
- netcat (nc): Quick TCP/UDP listeners/clients for testing connectivity.
- hping3: Craft TCP/UDP packets and observe host responses to flags.
- ss/netstat: Show local listening sockets and connection states.
- lsof: Map sockets to processes.
- Windows PowerShell Test-NetConnection: Quick TCP port testing.

## Typical command walkthrough (detailed, copy-paste friendly)

### 1) Inspect local ports and states
Linux:
```bash
# Show listening TCP/UDP sockets
ss -tuln

# Show listening sockets with processes (sudo often required)
sudo ss -tulpen

# Which process is bound to which port
sudo lsof -i -nP | grep LISTEN

# Check ephemeral port range
sysctl net.ipv4.ip_local_port_range
cat /proc/sys/net/ipv4/ip_local_port_range
```

Windows:
```powershell
# Show TCP connections/listeners and PIDs
netstat -ano

# Filter for LISTENING lines
netstat -ano | findstr LISTEN

# Quick TCP port test
Test-NetConnection -ComputerName 10.10.10.10 -Port 445
```

### 2) Map ports to services
Linux:
```bash
# Look up common services
grep -E '^(ssh|http|https|smb|rdp|dns|smtp|pop3|imap)\b' /etc/services

# Example: find 445 in services
grep -E '(^|[^0-9])445(/|[[:space:]])' /etc/services
```

### 3) Observe a TCP handshake end-to-end
Terminal A (server), Linux:
```bash
# Start a TCP listener on port 4444
nc -lvnp 4444
```

Terminal B (client), Linux:
```bash
# Connect to the listener
nc -vn 127.0.0.1 4444

# Type some text and press Enter; observe it on the server side.
```

Capture the handshake with tcpdump (Linux):
```bash
# Capture all TCP packets for port 4444 (any interface), no name resolution
sudo tcpdump -i any -nn 'tcp port 4444'

# Focus on SYNs
sudo tcpdump -i any -nn 'tcp port 4444 and (tcp[13] & 2 != 0)'

# Focus on SYN/ACK or ACK
sudo tcpdump -i any -nn 'tcp port 4444 and (tcp[13] & 16 != 0)'

# FIN (normal close) and RST (abort)
sudo tcpdump -i any -nn 'tcp port 4444 and (tcp[13] & 1 != 0)'   # FIN
sudo tcpdump -i any -nn 'tcp port 4444 and (tcp[13] & 4 != 0)'   # RST
```

Wireshark display filters:
```
tcp.port == 4444
tcp.flags.syn == 1 && tcp.flags.ack == 0      # SYN
tcp.flags.syn == 1 && tcp.flags.ack == 1      # SYN-ACK
tcp.flags.ack == 1 && tcp.len == 0            # pure ACK
tcp.flags.fin == 1                            # FIN
tcp.flags.reset == 1                          # RST
```

### 4) UDP behavior with netcat
Server:
```bash
# UDP listener on 9999
nc -lvnu 9999
```
Client:
```bash
# UDP client sends a line to server
echo "hello" | nc -u 127.0.0.1 9999
```
Note: No handshake; packets may silently drop.

### 5) Nmap scans (TCP/UDP)
```bash
# Fast TCP SYN scan, all ports, no ping, no DNS resolution
sudo nmap -sS -p- -T4 -n -Pn 10.10.10.10

# TCP connect scan (no raw packets; useful without root)
nmap -sT -p 1-1024 -n 10.10.10.10

# UDP scan (specific common UDP ports), show reasons
sudo nmap -sU -p 53,67,123,161,500 --reason -n -Pn 10.10.10.10

# Service/version detection on discovered ports
sudo nmap -sS -sV -p 22,80,443 -n -Pn 10.10.10.10

# Save results
sudo nmap -sS -p- -oA tcp_full 10.10.10.10
```

Interpreting typical responses:
- TCP SYN scan: SYN/ACK = open; RST = closed; no response or ICMP admin-prohibited = filtered.
- UDP scan: ICMP Port Unreachable (type 3, code 3) = closed; no response = open|filtered; service responses (e.g., DNS) imply open.

### 6) Craft packets with hping3
```bash
# TCP SYN probe to port 80
sudo hping3 -S -p 80 -c 1 10.10.10.10

# FIN/NULL/XMAS style probes (behavior is OS-dependent)
sudo hping3 -F -P -U -p 80 -c 1 10.10.10.10

# UDP probe to port 53
sudo hping3 --udp -p 53 -c 1 10.10.10.10
```

### 7) See TCP states (Linux)
```bash
# Show common TCP states
ss -tan state established,syn-sent,syn-recv,fin-wait-1,fin-wait-2,time-wait,close-wait,last-ack,listen
```

## Practical tips
- SYN vs. Connect scans: -sS is stealthier (half-open), faster, but still detectable; -sT is noisier and relies on OS connect().
- Speed vs. accuracy: Use -n to skip DNS; limit ports or use --top-ports to reduce runtime; add -sV for service fingerprints after you find open ports.
- UDP is slow and noisy: Target specific UDP ports first (53/123/161/500/137). Expect many open|filtered results.
- Read the wire: In Wireshark, track the three-way handshake to confirm real connectivity before deeper enumeration.
- Ephemeral ports: Don’t mistake ephemeral client ports for listening services. Verify with ss/lsof or reuse netcat for controlled tests.
- Firewalls: No response or ICMP admin-prohibited often implies filtering. Combine nmap --reason and packet captures to confirm.
- Close vs. abort: Graceful close uses FIN/ACK; abrupt termination uses RST (common when services reject connections or during some scans).
- Always get authorization before scanning; throttle scans in shared environments.

## Minimal cheat sheet (one-screen flow)
```bash
# List listeners (Linux)
ss -tuln
sudo lsof -i -nP | grep LISTEN

# Quick TCP test (Linux)
nc -lvnp 4444            # server
nc -vn TARGET 4444       # client

# Observe handshake
sudo tcpdump -i any -nn 'tcp port 4444'
# Wireshark display: tcp.flags.syn==1 && tcp.flags.ack==0

# Fast TCP discovery
sudo nmap -sS -p- -T4 -n -Pn TARGET
sudo nmap -sS -sV -p 22,80,443 -n -Pn TARGET

# UDP spot-check
sudo nmap -sU -p 53,67,123 --reason -n -Pn TARGET

# Craft probes
sudo hping3 -S -p 80 -c 1 TARGET
sudo hping3 --udp -p 53 -c 1 TARGET

# Ephemeral range (Linux)
sysctl net.ipv4.ip_local_port_range
```

## Summary
Transport Layer - Part 2 focuses on how TCP and UDP actually behave on the wire and how that maps to pentesting tasks. You learn to:
- Identify and interpret TCP flags, handshakes, teardowns, and resets.
- Recognize UDP’s connectionless nature and its impact on scan interpretation.
- Use Wireshark/tcpdump to validate what nmap scans report.
- Operate practical tools (nmap, netcat, hping3, ss/netstat) to enumerate services precisely and safely.
The key outcome: confidently correlate tool output with transport-layer packet behavior to make accurate decisions during enumeration and early exploitation phases.