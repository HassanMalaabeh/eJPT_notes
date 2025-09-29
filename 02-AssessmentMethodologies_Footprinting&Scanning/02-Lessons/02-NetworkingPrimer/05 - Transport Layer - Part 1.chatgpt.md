## What the video covers (Introduction / big picture)
Note: Transcript isn’t provided. The following is a conservative summary inferred from the filename “05 - Transport Layer - Part 1.mp4” in the “02-NetworkingPrimer” folder. Part 1 likely focuses on TCP at the Transport Layer (Layer 4), with UDP and deeper topics possibly in Part 2.

- Transport Layer responsibilities: multiplexing/demultiplexing via ports, segmentation/reassembly, reliability, ordering, flow control, and basic congestion behavior
- TCP fundamentals: reliable, connection-oriented byte stream; 3-way handshake; flags; sequence/ack numbers; windows; teardown; common states
- Ports and sockets: well-known vs registered vs ephemeral ports; socket tuples (src IP:port → dst IP:port)
- Practical implications for pentesting: how TCP behavior maps to port scanning, service enumeration, and banner grabbing
- Packet inspection basics: seeing the handshake and flags in Wireshark/tcpdump

## Flow (ordered)
1. OSI vs TCP/IP recap; Layer 4 role
2. Ports and sockets
   - Port ranges: 0–1023 (well-known), 1024–49151 (registered), 49152–65535 (dynamic/ephemeral by IANA; OS may differ)
   - Socket identity: 4-tuple (src IP, src port, dst IP, dst port)
3. TCP overview
   - Reliable stream, ordered delivery, retransmissions, ACKs
   - 3-way handshake: SYN → SYN/ACK → ACK
   - Flags: SYN, ACK, FIN, RST, PSH, URG (ECE/CWR advanced)
   - Sequence and acknowledgment numbers; initial sequence number (ISN)
   - Flow control via window size; basic idea of sliding window
4. Connection teardown and states
   - FIN/ACK sequence; TIME_WAIT; RST for abrupt close
   - Common states: LISTEN, SYN-SENT, SYN-RECV, ESTABLISHED, FIN-WAIT, CLOSE-WAIT, LAST-ACK, TIME-WAIT, CLOSED
5. Pentest relevance
   - How TCP responses drive port states in scans (open/closed/filtered)
   - Basic banner grabbing and service verification
6. Packet inspection demo (likely)
   - Viewing 3WH via Wireshark/tcpdump filters
   - Recognizing SYN, SYN/ACK, ACK; FIN/RST

## Tools highlighted
- Wireshark (GUI) for packet inspection
- tcpdump (CLI) for packet capture and filters
- nc/netcat (TCP/UDP client/server testing, banner grabbing)
- ss or netstat (view sockets and states)
- nmap (port scanning; SYN scan vs connect scan)
- nping/hping3 (crafting TCP probes; optional)

## Typical command walkthrough (detailed, copy-paste friendly)

System/network introspection
```
# Show ephemeral port range (Linux)
cat /proc/sys/net/ipv4/ip_local_port_range

# Show listening TCP/UDP sockets with processes
ss -tulpen

# Show TCP connections by state
ss -tan state syn-sent,syn-recv,established,time-wait,listen
```

Spin up a simple TCP service and connect
```
# Terminal 1: start a TCP listener on port 8080
nc -lvnp 8080

# Terminal 2: connect to it (localhost example)
nc -nv 127.0.0.1 8080
```

Observe the TCP handshake with tcpdump
```
# Capture all TCP on port 8080 (any interface)
sudo tcpdump -nni any 'tcp port 8080'

# Show only initial SYNs (no ACK flag set)
sudo tcpdump -nni any 'tcp port 8080 and (tcp[13] & 0x12) == 0x02'

# Show SYN/ACKs
sudo tcpdump -nni any 'tcp port 8080 and (tcp[13] & 0x12) == 0x12'

# Show RSTs (useful when connecting to a closed port)
sudo tcpdump -nni any 'tcp port 8080 and (tcp[13] & 0x04) != 0'
```

Wireshark display filters (apply in the filter bar)
```
tcp.flags.syn==1 && tcp.flags.ack==0     # SYN
tcp.flags.syn==1 && tcp.flags.ack==1     # SYN/ACK
tcp.flags.ack==1 && tcp.len==0           # Pure ACKs
tcp.flags.fin==1                         # FINs
tcp.flags.reset==1                       # RSTs
tcp.port == 8080                         # Traffic to/from port 8080
```

Quick HTTP banner grab / service check
```
# Connect and manually speak HTTP (type the two lines, then Enter twice)
nc -nv <target> 80
GET / HTTP/1.0
Host: <target>

# Or use curl for verbose TCP/TLS info
curl -v http://<target>/
```

Nmap: mapping L4 behavior to scan results
```
# SYN (half-open) scan across all TCP ports
sudo nmap -sS -p- -T4 -n <target>

# Full connect scan (completes TCP handshake)
nmap -sT -p 22,80,443 -n <target>

# Version detection (triggers app-layer probes after TCP connect)
sudo nmap -sS -sV -p 22,80,443 -n <target>
```

Craft a single SYN probe (optional)
```
# Using nping (from Nmap suite)
sudo nping --tcp -p 80 --flags SYN <target>

# Using hping3
sudo hping3 -S -p 80 -c 1 <target>
```

Teardown and TIME_WAIT demonstration
```
# Start listener
nc -lvnp 4444

# Connect, send data, then Ctrl+C on the client to close
nc -nv 127.0.0.1 4444

# See TIME_WAIT on the side that closed last
ss -tan | grep ':4444'
```

## Practical tips
- Interpreting scan states (TCP):
  - Open: SYN → SYN/ACK → scanner sends RST (for -sS), service likely present
  - Closed: SYN → RST; host reachable but no service
  - Filtered: no reply or ICMP unreachable; packet filtered/dropped
- Use SYN scan (-sS) when you have privileges; it’s faster and less noisy than full connect (-sT).
- Check ephemeral ranges; heavy connect/close cycles can exhaust ephemeral ports and lead to TIME_WAIT buildup.
- If a port looks filtered, try different source ports or timing (-T2/-T3); some ACLs are stateful or rate-limited.
- For quick validation of a TCP service, nc is your friend. For HTTP(S), curl -v gives protocol-level details quickly.
- In Wireshark, follow TCP stream to reconstruct application data and confirm request/response integrity.
- If you see many retransmissions or dup ACKs, suspect packet loss or filtering in-path.

## Minimal cheat sheet (one-screen flow)
```
# 1) What’s listening?
ss -tulpen

# 2) Scan target
sudo nmap -sS -p- -T4 -n <target>

# 3) Verify a port and grab a banner
nc -nv <target> 80
GET / HTTP/1.0
Host: <target>

# 4) Watch the handshake (tcpdump)
sudo tcpdump -nni any 'tcp port 80 and ((tcp[13] & 0x12) != 0)'

# 5) Wireshark filters
tcp.flags.syn==1 && tcp.flags.ack==0
tcp.flags.syn==1 && tcp.flags.ack==1
tcp.flags.reset==1

# 6) Check connection states
ss -tan state syn-sent,syn-recv,established,time-wait

# 7) Ephemeral port range
cat /proc/sys/net/ipv4/ip_local_port_range
```

## Summary
Part 1 of the Transport Layer primer (inferred) introduces TCP’s role at Layer 4: ports/sockets for multiplexing, reliable byte-stream delivery, and the 3-way handshake. You learn to recognize TCP flags and states, how connections are established and torn down, and how this behavior maps directly to pentesting activities like port scanning and banner grabbing. Practical tools include Wireshark and tcpdump for observing SYN/SYN-ACK/ACK sequences, netcat for quick service checks, and nmap for efficient discovery. These fundamentals underpin later modules where you’ll enumerate services and exploit application-layer weaknesses over TCP.