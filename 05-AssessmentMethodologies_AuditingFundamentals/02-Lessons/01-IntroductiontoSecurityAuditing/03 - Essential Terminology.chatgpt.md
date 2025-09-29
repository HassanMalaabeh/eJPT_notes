# 03 - Essential Terminology (eJPT) — Study Notes

Note: No transcript was provided. The content below is inferred conservatively from the filename and course context (01-Introduction to Security Auditing).

## What the video covers (Introduction / big picture)
- Establishes the core vocabulary you’ll use throughout security auditing and the eJPT exam.
- Clarifies often-confused terms (asset vs threat vs vulnerability vs risk; exposure vs exploit; likelihood vs impact).
- Frames testing taxonomy (vulnerability assessment vs penetration test; black/gray/white box; scope and rules of engagement).
- Introduces foundational security goals (CIA triad, AAA) and control types.
- Maps terminology to the attack lifecycle (reconnaissance, scanning, enumeration, exploitation, privilege escalation, lateral movement, persistence, exfiltration, reporting).
- Grounds terms in basic networking/protocols and common ports/services you'll encounter.

## Flow (ordered)
1. Why terminology matters: precision in scoping, testing, reporting.
2. Security goals: CIA triad (Confidentiality, Integrity, Availability) and AAA (Authentication, Authorization, Accounting).
3. Assets and data classification: public/internal/confidential/restricted; PII/PHI/PCI.
4. Risk language:
   - Asset, Threat, Vulnerability, Exposure, Exploit, Risk (likelihood × impact).
   - CVE (vulnerability IDs), CWE (weakness classes), CVSS (severity scoring).
5. Controls and defense:
   - Types: administrative, technical, physical.
   - Functions: preventive, detective, corrective.
6. Testing taxonomy:
   - Vulnerability assessment vs penetration test (depth vs breadth).
   - Black/gray/white box; internal vs external; assumptions.
   - Scope, in-scope assets, out-of-scope, Rules of Engagement (ROE), reporting expectations.
   - False positives vs false negatives; limitations.
7. Attack lifecycle terms:
   - Reconnaissance (passive vs active), scanning, enumeration, exploitation.
   - Post-exploitation: privilege escalation, pivoting, lateral movement, persistence, exfiltration, cleanup, reporting.
8. Networking basics for assessors:
   - TCP vs UDP; ports/services; banner grabbing; common protocols (HTTP(S), SSH, FTP, SMB, DNS, SMTP, RDP).
9. Evidence and frameworks:
   - Indicators of Compromise (IoCs), Tactics-Techniques-Procedures (TTPs), kill chain/MITRE ATT&CK (high level).

## Tools highlighted
- Concept-focused video; to anchor terms you’ll typically use:
  - nmap: discovery, scanning, service detection, OS detection, NSE scripts.
  - dig / whois / nslookup: DNS/ownership OSINT; zone transfer checks.
  - curl / openssl s_client: HTTP methods/headers; TLS certificate details.
  - netcat (nc): banner grabbing, basic protocol interaction.
  - traceroute: network path awareness.
  - searchsploit: tie service versions to public CVEs/CWEs.
  - Optional: jq for JSON parsing (if using web APIs like crt.sh or CVE).

Use only on systems you own or are explicitly authorized to test.

## Typical command walkthrough (detailed, copy-paste friendly)
The following shows how key terms map to practical steps. Replace example.com and 10.10.10.10 with authorized targets.

```bash
# --- Setup variables for clarity
export TARGET_DOMAIN="example.com"
export TARGET="10.10.10.10"

# --- Passive reconnaissance (no touching target systems directly)
whois "$TARGET_DOMAIN"                              # Ownership, contacts (asset & scope context)
dig +short NS "$TARGET_DOMAIN"                      # Nameservers
dig +short MX "$TARGET_DOMAIN"                      # Mail exchangers (potential targets)
dig TXT "$TARGET_DOMAIN" +short                     # TXT/SPF/DMARC: org posture hints

# Subdomain inventory via certificate transparency (public OSINT)
# Requires 'jq' for pretty output; remove | jq ... if jq is unavailable.
curl -s "https://crt.sh/?q=${TARGET_DOMAIN}&output=json" | jq -r '.[].name_value' | sort -u

# --- Active reconnaissance / discovery
# Host discovery (only with authorization)
nmap -sn -n 10.10.10.0/24 -oA discovery             # "Discovery" vs "Scanning" terminology

# --- Scanning (attack surface mapping)
# Full TCP port sweep (likely to find services = potential vulnerabilities)
nmap -Pn -n -sS -p- --min-rate 2000 -oG allports.gnmap "$TARGET"

# Extract open TCP ports for focused enumeration
export TCP_PORTS=$(grep -oE '[0-9]+/open/tcp' allports.gnmap | cut -d/ -f1 | sort -n | tr '\n' ',' | sed 's/,$//')
echo "Open TCP ports: $TCP_PORTS"

# Service/version detection + default scripts (enumeration)
nmap -Pn -n -sV -sC -p "$TCP_PORTS" -oN services.txt "$TARGET"

# UDP high-signal probe (DNS, SNMP, etc.) — slower and noisier
nmap -Pn -n -sU --top-ports 20 -oN udp-top20.txt "$TARGET"

# OS detection (best-effort; needs privileges)
sudo nmap -Pn -n -O -p "$TCP_PORTS" -oN os.txt "$TARGET"

# --- Enumeration examples (banner grabbing = identify software to map to CVEs)
# HTTP/HTTPS
curl -i "http://$TARGET/"                            # Headers, server banner
curl -I "http://$TARGET:80/"                         # HEAD request (quick headers)
curl -i -X OPTIONS "http://$TARGET/"                 # Allowed HTTP methods (attack surface)
# TLS certificate info (CN, validity) — passive intel on services
echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET_DOMAIN" 2>/dev/null | openssl x509 -noout -subject -issuer -dates

# Generic banner grabbing
nc -nv "$TARGET" 22 <<< $''                          # SSH banner
nc -nv "$TARGET" 21 <<< $''                          # FTP banner

# SMB enumeration (null session check; may fail if not allowed)
smbclient -L "//$TARGET/" -N                         # Lists shares without creds (exposure)

# DNS zone transfer check (misconfiguration = high-risk exposure)
for ns in $(dig +short NS "$TARGET_DOMAIN"); do
  echo "[*] Trying AXFR against $ns"
  dig AXFR "$TARGET_DOMAIN" @"$ns"
done

# --- Map discovered versions to known vulnerabilities (CVE/CWE/CVSS)
# Use versions from services.txt; example with OpenSSH version string
searchsploit -w -t "OpenSSH 7.2p2"                   # Replace with actual service/version
# Query CVEs via CIRCL (optional)
# curl -s "https://cve.circl.lu/api/search/OpenSSH/7.2p2" | jq -r '.[] | "\(.id) - \(.summary)"' | head

# --- Notes on terminology while you work:
# - Reconnaissance (passive vs active) above.
# - Scanning (nmap) vs Enumeration (service banners, SMB list).
# - Vulnerability: software flaw/version issue discovered.
# - Threat: actor/capability that could exploit the vulnerability.
# - Risk: likelihood * impact for a given asset if exploited.
# - Control: patching, disabling methods, auth hardening (preventive/detective/corrective).
```

## Practical tips
- Keep terms straight:
  - Vulnerability = a flaw/weakness; Threat = potential cause of unwanted incident; Exploit = method/code to trigger a vulnerability; Exposure = condition increasing likelihood/impact; Risk = likelihood × impact to an asset.
- Use consistent scope language in notes: in-scope assets, out-of-scope, testing windows, prohibited techniques.
- Label your steps with lifecycle terms (Recon, Scan, Enum, Exploit, Post-Ex) to structure reports.
- Tie findings to CVE/CWE where possible and provide CVSS base scores or a clear severity rationale.
- Map services to business impact (asset context) to prioritize (e.g., exposed SMB on DC > low-risk dev box).
- Remember false positives vs false negatives; validate with multiple methods when possible.
- Memorize the common ports/services you’ll see constantly: 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80/443 (HTTP/HTTPS), 110 (POP3), 143 (IMAP), 3306 (MySQL), 3389 (RDP), 445 (SMB), 139 (NetBIOS), 135 (MS-RPC), 8080 (Alt HTTP), 5900 (VNC), 53/udp (DNS), 161/udp (SNMP).

## Minimal cheat sheet (one-screen flow)
- Goals: CIA triad; AAA.
- Risk stack:
  - Asset → Vulnerability ↔ Exposure → Threat → Exploit → Risk (likelihood × impact).
  - CVE = specific vuln; CWE = class; CVSS = severity score.
- Controls: administrative/technical/physical; preventive/detective/corrective.
- Test types: vuln assessment vs pentest; black/gray/white box; scope & ROE; false pos/neg.
- Lifecycle: Recon (passive/active) → Scanning → Enumeration → Exploitation → Post-Ex (priv esc, lateral, persistence, exfil) → Reporting.
- Quick commands:
  - whois domain; dig NS/MX/TXT domain; curl "https://crt.sh/?q=domain&output=json"
  - nmap -sn -n CIDR
  - nmap -Pn -n -sS -p- --min-rate 2000 -oG allports.gnmap TARGET
  - TCP_PORTS=$(grep -oE '[0-9]+/open/tcp' allports.gnmap | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
  - nmap -Pn -n -sV -sC -p $TCP_PORTS TARGET
  - curl -i http://TARGET/ ; nc -nv TARGET 22
  - smbclient -L //TARGET/ -N
  - searchsploit -w -t "Service Version"
- Ports to recall: 21,22,23,25,53,80,110,143,139,445,135,443,3306,3389,5432,5900,8080; UDP 53,161.

## Summary
This lesson defines the essential language of security auditing so your assessments and reports are precise and defensible. Know the security goals (CIA/AAA), differentiate asset/threat/vulnerability/risk, understand control categories, and use the attack lifecycle to organize your work. Tie services and versions discovered during scanning/enumeration to public vulnerabilities (CVE/CWE) and express impact using CVSS or a clear severity model. The included commands show how terminology maps to practice—use them as a starter flow in authorized labs and on the eJPT.