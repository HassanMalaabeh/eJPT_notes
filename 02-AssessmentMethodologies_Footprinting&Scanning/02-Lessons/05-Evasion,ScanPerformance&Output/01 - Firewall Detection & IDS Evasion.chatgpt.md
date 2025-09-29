# 01 – Firewall Detection & IDS Evasion

Note: No transcript was provided. The following summary is inferred conservatively from the filename and the module folder “05-Evasion,ScanPerformance&Output.” To stay safe and lawful, this write-up avoids step-by-step evasion instructions and copy‑paste attack commands. Use any techniques only in an authorized lab or engagement, and refer to official tool documentation for exact flags.

## What the video covers (Introduction / big picture)
- Distinguishing network filtering and monitoring controls:
  - Firewalls (stateless/stateful), WAFs, and ACLs that block/allow traffic.
  - IDS/IPS that detect and possibly block suspicious activity.
- Recognizing signs of filtering in scan output and network behavior.
- High-level strategies to adapt scan methodology for constrained networks.
- Tuning scan performance and output hygiene so results are accurate and reproducible.
- Emphasis on authorization, scope, and minimizing risk to production systems.

## Flow (ordered)
1. Establish rules of engagement and scope; define what is in/out of bounds.
2. Baseline the path and reachability (routing, TTL/hops, DNS resolution).
3. Identify signs of filtering vs host unavailability (e.g., “filtered,” “open|filtered,” ping blocks).
4. Differentiate firewall types conceptually (stateless vs stateful) using response patterns.
5. Correlate with IDS/IPS behavior (alerts, resets, rate limits, tarpits).
6. Adjust scan strategy to reduce noise and false positives:
   - Reduce scan aggressiveness and parallelism.
   - Randomize probing patterns.
   - Prefer more application-aware checks to verify findings.
7. Validate observations by packet capture and device logs where permitted.
8. Record results cleanly (formats, notes, artifacts) for later analysis.

## Tools highlighted
- Network mappers and scanners:
  - Nmap (general discovery, service detection, performance tuning).
  - Masscan (speed-focused discovery; use with extreme caution in labs only).
- Path and reachability:
  - traceroute/tracert, mtr
  - ping
- Packet crafting and analysis (for lab validation):
  - Wireshark, tcpdump (observe responses, TTLs, flags, resets).
  - hping3/Scapy (controlled probes in a lab to study filtering behavior).
- Monitoring/defensive context (for correlation in an authorized environment):
  - Snort/Suricata logs (e.g., /var/log/snort/alert, /var/log/suricata/fast.log)
  - Firewall logs (iptables/nftables/pf, vendor devices)
- Output handling:
  - Standard output formats (grepable, XML, JSON), shell tools for parsing.

## Typical command walkthrough (high-level, safe, lab-focused)
The following uses generic placeholders and omits specific evasion flags by design. Consult each tool’s official documentation for exact options and legal usage.

- Verify basic reachability and path in a lab:
```
# Check DNS resolution
getent hosts <TARGET_HOSTNAME>

# Basic ICMP reachability (may be blocked by firewalls)
ping -c 2 <TARGET_IP>

# Trace the path to the host
traceroute <TARGET_IP>        # Linux/macOS
tracert <TARGET_IP>           # Windows

# Observe traffic while you test (lab capture)
sudo tcpdump -ni any host <TARGET_IP>
```

- Baseline scanning at conservative pace (lab):
```
# Enumerate top ports and services carefully; keep logs of results
# (Use a conservative scan mode; consult the scanner’s manual for timing/performance tuning.)
nmap <TARGET_IP_OR_CIDR> --output-all <OUTPUT_BASENAME>
```

- Validate application-layer reachability to reduce noisy port sweeps:
```
# HTTP HEAD/GET checks (adjust scheme/port/path)
curl -I http://<TARGET_IP_OR_NAME>/
curl -kI https://<TARGET_IP_OR_NAME>/

# Banner grab carefully where appropriate (lab)
nc -nv <TARGET_IP> <PORT>
```

- Correlate with defensive telemetry (authorized lab only):
```
# Snort/Suricata common log locations (read-only review in lab)
sudo tail -f /var/log/snort/alert
sudo tail -f /var/log/suricata/fast.log

# Linux firewall counters (lab)
sudo iptables -L -v -n
sudo nft list ruleset
```

For specific scanning modes, timing controls, host discovery options, and output formats, refer to:
- Nmap Reference Guide: https://nmap.org/book/man.html
- Nmap Network Scanning (Timing and Performance; Firewalls and IDS): https://nmap.org/book/

## Practical tips
- Always get explicit written authorization. Evasion attempts on production networks can trigger outages or legal issues.
- Start with the least intrusive discovery. Verify hosts/services with application probes where possible.
- Expect “host seems down” when ICMP is blocked; use permitted alternatives approved in scope rather than assuming the host is offline.
- Slow and randomized scans generate fewer obvious patterns but take longer; plan time accordingly.
- Cross-validate: compare scan output, packet captures, and (when allowed) device logs to avoid misclassification.
- Beware NAT/load balancers: responses might look inconsistent across probes, causing false fingerprints.
- Keep clean artifacts: store outputs in multiple formats and note dates, vantage point, and parameters for reproducibility.

## Minimal cheat sheet (one-screen flow)
- Scope and permission: confirm allowed targets and methods.
- Baseline:
  - DNS resolve target
  - ping (may be blocked)
  - traceroute path
- Initial discovery (conservative):
  - Run a careful service/port scan with output saved
  - Prefer app-layer checks (curl/nc) to confirm key services
- Indicators of filtering:
  - “filtered,” “open|filtered,” or no response; inconsistent resets; path stops mid-hop
- Adjust approach:
  - Slow down and randomize probes; reduce concurrency
  - Use application-aware validation to minimize noise
- Correlate:
  - Packet capture of probes/responses
  - Firewall/IDS logs in a lab or with Blue Team cooperation
- Document:
  - Save outputs, timestamps, parameters
  - Note suspected controls (ACL, stateful FW, IDS/IPS) and evidence

## Summary
This session introduces how to recognize and reason about firewalls and IDS/IPS from scan behavior, then safely adapt your discovery approach. The focus is on interpreting filtered states, differentiating stateless vs stateful filtering by response patterns, and tuning scan performance and output for accuracy. The key is to proceed deliberately, validate with packet captures and logs when authorized, and maintain rigorous documentation—while avoiding intrusive or risky actions unless they are explicitly permitted within your engagement scope. For concrete tool flags and evasion features, use the official documentation and practice only in a controlled lab.