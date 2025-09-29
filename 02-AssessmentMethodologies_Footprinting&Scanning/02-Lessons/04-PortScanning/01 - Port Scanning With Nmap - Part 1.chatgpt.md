# What the video covers (Introduction / big picture)
Transcript not provided; summary inferred from the title and course module (04-PortScanning). This session introduces Nmap port scanning fundamentals used in eJPT-style internal assessments:
- Distinguishing host discovery vs. port scanning
- Core TCP scan types (SYN -sS, Connect -sT), and a quick intro to UDP (-sU)
- Common flags for speed, accuracy, and noise control (-T, -n, -Pn)
- Port selection (-p, -p-, --top-ports, -F)
- Output handling (-oN, -oG, -oX, -oA) and building a repeatable workflow

# Flow (ordered)
1. Define scope and targets (single IP, range, CIDR)
2. Host discovery (ping sweep) to find live hosts
   - Local LAN: ARP-based discovery
   - Remote networks: ICMP and TCP/UDP “ping” techniques; fall back to -Pn
3. Triage scan for quick wins (top ports or fast scan)
4. Full TCP scan across all ports (1–65535)
5. Optional version detection/basic scripts on discovered ports (-sV, -sC)
6. Quick UDP scan on top ports (optional; slower)
7. Save and parse results into lists for follow-up
8. Decide next steps based on open services

# Tools highlighted
- Nmap (primary)
- Shell helpers to parse Nmap output:
  - grep, awk, sed, paste

# Typical command walkthrough (detailed, copy-paste friendly)
Assume a lab network 10.10.10.0/24. Run as root for SYN/UDP scans.

Set variables
```
NET="10.10.10.0/24"
OUTDIR="./nmap_out"
mkdir -p "$OUTDIR"
```

1) Host discovery (ping sweep)
- Local/LAN ARP discovery (fast; -sn does ARP automatically on Ethernet LANs)
```
sudo nmap -sn -n "$NET" -oA "$OUTDIR/hosts_arp"
# Extract live IPs from greppable output
grep "Status: Up" "$OUTDIR/hosts_arp.gnmap" | awk '{print $2}' > "$OUTDIR/live.txt"
```
- Remote network (ICMP + TCP/UDP pings). If ICMP is blocked, this often still works:
```
sudo nmap -sn -n -PE -PS22,80,443 -PA80,443 -PU53 "$NET" -oA "$OUTDIR/hosts_mixed"
grep "Status: Up" "$OUTDIR/hosts_mixed.gnmap" | awk '{print $2}' > "$OUTDIR/live.txt"
```
- If discovery is failing but you know targets exist, skip host discovery:
```
# Use -Pn to treat all targets as online (slower, noisier)
sudo nmap -sn -n -Pn "$NET" -oA "$OUTDIR/hosts_pn"
grep "Status: Up" "$OUTDIR/hosts_pn.gnmap" | awk '{print $2}' > "$OUTDIR/live.txt"
```

2) Quick triage TCP scan on live hosts
- Top 100 ports (good for fast reconnaissance)
```
sudo nmap -sS -n -Pn --top-ports 100 -T3 --open -iL "$OUTDIR/live.txt" -oA "$OUTDIR/triage_top100_tcp"
```
- Fast built-in set (-F scans Nmap’s “fast” port list)
```
sudo nmap -sS -n -Pn -F -T3 --open -iL "$OUTDIR/live.txt" -oA "$OUTDIR/triage_fast_tcp"
```

3) Full TCP scan (all ports)
```
sudo nmap -sS -n -Pn -p- -T3 --open -iL "$OUTDIR/live.txt" -oA "$OUTDIR/full_tcp"
```

4) Optional: Add service/version detection and default scripts
- For a small host set you can combine in one pass (heavier):
```
sudo nmap -sS -sV -sC -n -Pn -p- -T3 --open -iL "$OUTDIR/live.txt" -oA "$OUTDIR/full_tcp_enum"
```
- Or do it per-host after a full TCP scan to limit to discovered ports
```
TARGET="10.10.10.10"
sudo nmap -sS -n -Pn -p- -T4 --open "$TARGET" -oA "$OUTDIR/${TARGET}_fulltcp"

# Build a comma-separated port list of open TCP ports from the .nmap output:
ports=$(grep -oP '^\d+(?=/tcp\s+open)' "$OUTDIR/${TARGET}_fulltcp.nmap" | paste -sd, -)

# Enumerate only those ports with version detection and default scripts:
sudo nmap -sV -sC -n -Pn -p"$ports" "$TARGET" -oA "$OUTDIR/${TARGET}_tcp_enum"
```

5) Quick UDP scan (targeted due to slowness)
```
# Triage UDP top 20 or 50 ports; increase as time permits
sudo nmap -sU -n -Pn --top-ports 20 -T3 --open -iL "$OUTDIR/live.txt" -oA "$OUTDIR/triage_topudp"

# Per-host UDP (slower). Enumerate only if you need it:
TARGET="10.10.10.10"
sudo nmap -sU -n -Pn --top-ports 50 -T3 --open "$TARGET" -oA "$OUTDIR/${TARGET}_udp_top50"
```

6) Output formats and tips
```
# All formats with one basename (.nmap, .gnmap, .xml)
sudo nmap -sS -n -Pn -p- -oA "$OUTDIR/project_fulltcp" "$NET"

# Human-readable
-oN "$OUTDIR/readable.nmap"

# Greppable for command-line parsing
-oG "$OUTDIR/greppable.gnmap"

# XML for tooling
-oX "$OUTDIR/output.xml"
```

7) Useful speed/clarity flags
```
# Increase verbosity and show reasons
-vv --reason

# Don’t resolve DNS (speeds scans, avoids noise)
-n

# Timing template: T0..T5 (paranoid..insane). T3 (default), T4 is faster but noisier.
-T4

# Show progress during long scans
--stats-every 10s
```

8) Connect scan fallback (non-root)
```
# If you can’t use sudo/root, Nmap uses TCP connect scans by default (-sT)
nmap -sT -n -Pn -p- "$TARGET" -oA "$OUTDIR/${TARGET}_fulltcp_sT"
```

# Practical tips
- Run as root for SYN (-sS) and UDP (-sU) scans; otherwise Nmap falls back to -sT (slower, more noisy).
- Use -n to skip DNS lookups; it’s faster and avoids alerting DNS infrastructure.
- If ping sweep finds nothing on a remote network, try mixed ping types (-PE -PS -PA -PU). If still nothing but you expect live hosts, use -Pn.
- Start with triage scans (--top-ports 100 or -F) to get early signal before committing to -p-.
- Save everything with -oA and keep the .gnmap files; they’re easy to parse with grep/awk.
- For UDP, keep it targeted (top ports like 53, 67/68, 69, 123, 137, 161, 500); UDP is slow and many ports appear open|filtered.
- Use --open to reduce output noise to only open ports during triage.
- Adjust -T carefully; T4 is fine in lab/internal contexts, but may increase dropped packets on congested links.
- Rerun against specific hosts/ports with -sV -sC once you know what’s open; it’s more efficient than blanket service detection.

# Minimal cheat sheet (one-screen flow)
```
# Define scope
NET="10.10.10.0/24"; OUT="./nmap_out"; mkdir -p "$OUT"

# 1) Host discovery (LAN)
sudo nmap -sn -n "$NET" -oA "$OUT/hosts_arp"
grep "Status: Up" "$OUT/hosts_arp.gnmap" | awk '{print $2}' > "$OUT/live.txt"

# 2) Quick TCP triage
sudo nmap -sS -n -Pn --top-ports 100 -T3 --open -iL "$OUT/live.txt" -oA "$OUT/triage_top100_tcp"

# 3) Full TCP scan
sudo nmap -sS -n -Pn -p- -T3 --open -iL "$OUT/live.txt" -oA "$OUT/full_tcp"

# 4) Optional: Version + default scripts (small sets)
sudo nmap -sS -sV -sC -n -Pn -p- -T3 --open -iL "$OUT/live.txt" -oA "$OUT/full_tcp_enum"

# 5) Quick UDP triage
sudo nmap -sU -n -Pn --top-ports 20 -T3 --open -iL "$OUT/live.txt" -oA "$OUT/triage_topudp"
```

# Summary
This session (inferred) lays out a reliable Nmap workflow for eJPT labs: discover live hosts, triage with fast/top-port scans, perform full TCP scans, optionally enumerate with -sV/-sC, and selectively probe UDP. It emphasizes practical flag choices (-n, -Pn, -T, --top-ports, -p-, --open) and saving parse-friendly output (-oA), enabling you to iterate quickly and focus follow-up enumeration where it matters.