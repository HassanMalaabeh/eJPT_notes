# 04 - Nmap Output Formats

Note: No transcript was provided. The following summary and commands are inferred conservatively from the filename and module context (“05-Evasion, Scan Performance & Output”). The topic is well-scoped: how to save, parse, and present Nmap results using its output formats.

## What the video covers (Introduction / big picture)
- Why you should always save Nmap results in structured, reproducible formats.
- The three main Nmap output formats and their use-cases:
  - Normal (-oN): human-readable log (same as screen output).
  - Grepable (-oG): quick-and-dirty parsing with grep/awk/sed.
  - XML (-oX): machine-readable for reliable parsing and reporting.
- The convenience flag -oA to produce all three formats at once.
- Streaming output to stdout with “-” and piping into other tools.
- Converting XML to HTML, comparing scans over time, resuming scans, and appending.
- Practical text processing one-liners to extract hosts/ports for follow-up scans.

## Flow (ordered)
1. Decide targets and create a scans directory.
2. Run an initial discovery scan and save outputs using -oA (normal, grepable, XML).
3. Quickly extract “interesting” artifacts (e.g., IPs with open ports, open port lists) from .gnmap or XML for follow-up.
4. Run focused, detailed scans against discovered hosts/ports; save outputs again.
5. Optionally convert XML to HTML for reporting.
6. If scans are interrupted, resume with --resume (using the .nmap or .gnmap log).
7. Use ndiff to compare before/after XML results.
8. Keep filenames timestamped and consistent for repeatability.

## Tools highlighted
- Core: nmap
- Nmap output flags: -oN, -oG, -oX, -oA, --append-output, --resume
- Helpful scan flags often seen with output: --open, -sS, -sC, -sV, -p, -Pn, -n, -T4
- Text processing: grep, awk, sed, cut, sort, tr
- XML handling/reporting: xsltproc (/usr/share/nmap/nmap.xsl), xmlstarlet
- Diffing scans: ndiff (bundled with Nmap)
- Optional: tee for simultaneous screen + file logging

## Typical command walkthrough (detailed, copy-paste friendly)
Set a target scope and workspace:
```bash
# Set your target(s)
TARGETS="10.10.10.0/24"

# Create a workspace for logs
mkdir -p scans
```

Initial discovery scan with all output types:
```bash
# SYN scan, discover TCP ports, print only hosts with open ports and save all outputs
nmap -sS --open -T4 -p- -n -Pn -oA scans/initial "$TARGETS"
# Produces: scans/initial.nmap (normal), scans/initial.gnmap (grepable), scans/initial.xml (XML)
```

Quickly list hosts that have at least one open port (from grepable output):
```bash
grep "/open/" scans/initial.gnmap | cut -d ' ' -f 2 | sort -u > scans/hosts_with_open.txt
cat scans/hosts_with_open.txt
```

Extract open TCP ports per host (from grepable output):
```bash
# For one host
IP="10.10.10.5"
grep "Host: $IP" scans/initial.gnmap \
  | awk -F'Ports: ' 'NF>1{print $2}' \
  | tr ',' '\n' \
  | awk -F'/' '$2=="open"{print $1}' \
  | sort -n | tr '\n' ',' | sed 's/,$//' > scans/"$IP"_open_tcp.txt
cat scans/"$IP"_open_tcp.txt
```

Automate detailed follow-up scans on discovered hosts/ports:
```bash
# For each host with open ports, grab open port list and do a version+scripts scan
while read -r ip; do
  ports=$(grep "Host: $ip" scans/initial.gnmap \
    | awk -F'Ports: ' 'NF>1{print $2}' \
    | tr ',' '\n' \
    | awk -F'/' '$2=="open"{print $1}' \
    | sort -n | paste -sd, -)
  if [ -n "$ports" ]; then
    echo "[*] Scanning $ip ports: $ports"
    nmap -sC -sV -p "$ports" -n -oA "scans/${ip}-detail" "$ip"
  fi
done < scans/hosts_with_open.txt
```

Stream output to stdout and pipe (useful in one-liners):
```bash
# Grepable to stdout and parse immediately
nmap -p 80,443 --open -oG - "$TARGETS" | awk '/open/{print $2}' | sort -u
```

XML to HTML reporting (pretty report):
```bash
# Install xsltproc if missing (Debian/Ubuntu/Kali)
# sudo apt-get update && sudo apt-get install -y xsltproc

# Convert XML to HTML (path may vary by distro)
xsltproc /usr/share/nmap/nmap.xsl scans/initial.xml -o scans/initial.html
```

XML querying example (robust parsing):
```bash
# Install xmlstarlet if missing:
# sudo apt-get install -y xmlstarlet

# Print "IP openport1,openport2,..." for each host
xmlstarlet sel -t \
  -m '//host[status/@state="up"]' \
  -v 'address/@addr' -o ' ' \
  -m 'ports/port[state/@state="open"]' -v '@portid' -o ',' -b \
  -n scans/initial.xml \
| sed 's/,\s*$//'
```

Resume an interrupted scan:
```bash
# Use a .nmap or .gnmap file created by -oN/-oG or by -oA
nmap --resume scans/initial.nmap
```

Append to existing logs (use with care, especially for XML):
```bash
# Appends to existing log files rather than overwriting
nmap -sS -p 22,80 --open --append-output -oA scans/initial "$TARGETS"
# Note: Appended XML will be multiple XML documents in one file; not ideal for XML parsers.
```

Compare scans over time:
```bash
# Run a later scan and compare with ndiff (XML is recommended for ndiff)
nmap -sS --open -T4 -p- -n -Pn -oX scans/initial_later.xml "$TARGETS"
ndiff scans/initial.xml scans/initial_later.xml > scans/initial_changes.txt
cat scans/initial_changes.txt
```

Timestamped filenames to avoid overwrites:
```bash
TS=$(date +%F-%H%M%S)
nmap -sS --open -T4 -p- -n -Pn -oA "scans/initial-$TS" "$TARGETS"
```

Optional “fun” output:
```bash
# sCrIpT kIddY output (novelty; not useful for parsing)
nmap -sS -p 22,80 -oS scans/skiddy.txt "$TARGETS"
```

## Practical tips
- Prefer -oA for every significant run; you’ll have human-readable, grepable, and XML simultaneously.
- -oG is convenient for quick shell parsing but is legacy; for robust automation use -oX and XML tools.
- Use --open to reduce noise and only log hosts that have at least one open port.
- Use -n to disable DNS lookups for faster, cleaner outputs that are easier to parse.
- Be careful with --append-output for XML; appended XML is not a single well-formed document.
- Use --resume with the .nmap or .gnmap file to continue interrupted scans without restarting.
- Keep scans organized by target and timestamp; consistent names help with ndiff and reporting.
- Convert XML to HTML with xsltproc for easy sharing with teammates/stakeholders.
- For follow-up scans, extract open port lists to avoid re-probing closed/filtered ports.
- Store your parsing one-liners (grep/awk/sed or xmlstarlet) in a notes file for reuse during exams.

## Minimal cheat sheet (one-screen flow)
```bash
# Workspace
TARGETS="10.10.10.0/24"; mkdir -p scans

# Initial scan (save all formats)
nmap -sS --open -T4 -p- -n -Pn -oA scans/initial "$TARGETS"

# Hosts with open ports
grep "/open/" scans/initial.gnmap | cut -d ' ' -f 2 | sort -u > scans/hosts_with_open.txt

# Per-host open port list
IP="10.10.10.5"
grep "Host: $IP" scans/initial.gnmap | awk -F'Ports: ' 'NF>1{print $2}' \
| tr ',' '\n' | awk -F'/' '$2=="open"{print $1}' | paste -sd, - > scans/"$IP"_open_tcp.txt

# Detailed follow-up for all hosts
while read -r ip; do ports=$(grep "Host: $ip" scans/initial.gnmap | awk -F'Ports: ' 'NF>1{print $2}' \
| tr ',' '\n' | awk -F'/' '$2=="open"{print $1}' | paste -sd, -); \
[ -n "$ports" ] && nmap -sC -sV -p "$ports" -n -oA "scans/${ip}-detail" "$ip"; \
done < scans/hosts_with_open.txt

# Pretty report
xsltproc /usr/share/nmap/nmap.xsl scans/initial.xml -o scans/initial.html

# Diff later
ndiff scans/initial.xml scans/initial_later.xml > scans/initial_changes.txt
```

## Summary
This video focuses on capturing, parsing, and presenting Nmap results using its output formats. The key flags are -oN (normal), -oG (grepable), -oX (XML), and -oA (all three). Use -oA for every substantial scan, then extract data quickly with .gnmap for one-liners or parse reliably with XML tools. Convert XML to HTML for readable reports; use ndiff to track changes across scans. Resume interrupted scans with --resume and consider naming outputs with timestamps for clean, repeatable workflows.