# 06 - Nmap Scripting Engine (NSE)

Note: The transcript isn’t provided; details are inferred conservatively from the filename/context and common eJPT NSE usage.

## What the video covers (Introduction / big picture)
- What Nmap Scripting Engine (NSE) is and why it matters for post-port-scan enumeration.
- Script categories (default, safe, vuln, intrusive, brute, discovery, etc.) and when to use them.
- How to select scripts by name, wildcard, or category; how to exclude risky categories.
- Core flags: -sC (default scripts), --script, --script-args, --script-help, --script-trace.
- Service-focused enumeration examples (HTTP, SMB, FTP, DNS, SNMP, SMTP, RDP, SSL/TLS).
- Practical workflow: run default scripts, then targeted scripts, then optional vuln checks.
- Tips for safety, speed, and saving output.

## Flow (ordered)
1. Start with a basic port scan to find open ports.
2. Run default scripts and version detection to enrich findings.
3. Inspect available scripts and their help/args.
4. Run targeted service-specific NSE scripts on relevant ports.
5. Optionally run vuln category scripts (understood as potentially intrusive/noisy).
6. Use script arguments to fine-tune behavior (paths, credentials, limits).
7. Save outputs and iterate based on findings.

## Tools highlighted
- nmap (NSE)
- NSE script database: /usr/share/nmap/scripts and libraries in /usr/share/nmap/nselib
- SecLists (optional) for username/password lists: /usr/share/seclists
- Standard Linux utilities: less, grep, ls for browsing/help

## Typical command walkthrough (detailed, copy-paste friendly)

Set a target variable you can reuse:
```bash
TARGET=10.10.10.10
```

0) Locate scripts and update the script DB (optional but useful if you add custom scripts):
```bash
ls -1 /usr/share/nmap/scripts | wc -l
sudo nmap --script-updatedb
```

1) Default scripts + version detection (safe starting point):
```bash
sudo nmap -sC -sV -oN nmap_default_${TARGET}.nmap $TARGET
```

2) List script help, categories, and arguments:
```bash
# Help for a specific script
nmap --script-help http-enum

# Help by wildcard (lists all matching scripts)
nmap --script-help 'http-*'

# List by category (e.g., default, safe, vuln, intrusive)
nmap --script-help default
nmap --script-help vuln
```

3) Service-focused enumeration

HTTP/HTTPS:
```bash
sudo nmap -p 80,443 --script http-title,http-headers,http-methods,http-robots.txt,http-enum $TARGET

# Run many HTTP scripts safely by excluding risky categories
sudo nmap -p 80,443 --script 'http-* and not (intrusive or dos)' $TARGET

# Example with script args (custom User-Agent)
sudo nmap -p 80 --script http-title --script-args 'http.useragent=Mozilla/5.0' $TARGET
```

SMB:
```bash
sudo nmap -p 139,445 --script smb-os-discovery,smb-enum-shares,smb-enum-users,smb2-time,smb2-capabilities $TARGET

# Check specific vulns (can be intrusive; use with caution in labs)
sudo nmap -p 445 --script smb-vuln-ms17-010 $TARGET
```

FTP:
```bash
sudo nmap -p 21 --script ftp-anon,ftp-syst,ftp-libopie,ftp-brute $TARGET

# Classic check for backdoor (older targets/labs)
sudo nmap -p 21 --script ftp-vsftpd-backdoor $TARGET
```

DNS:
```bash
# Recursion and basic info
sudo nmap -sU -p 53 --script dns-recursion,dns-nsid $TARGET

# Brute-force subdomains (noisy; adjust threads)
sudo nmap -sU -p 53 --script dns-brute --script-args 'dns-brute.threads=10' $TARGET
```

SNMP:
```bash
# If community is known/suspected (e.g., public)
sudo nmap -sU -p 161 --script snmp-info --script-args 'snmpcommunity=public' $TARGET

# More detailed SNMP enumeration
sudo nmap -sU -p 161 --script snmp-interfaces,snmp-processes --script-args 'snmpcommunity=public' $TARGET
```

SMTP:
```bash
sudo nmap -p 25,465,587 --script smtp-commands,smtp-enum-users $TARGET
# smtp-open-relay can be intrusive (may send mails); use with caution:
sudo nmap -p 25 --script smtp-open-relay $TARGET
```

RDP:
```bash
sudo nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info $TARGET
```

SSL/TLS:
```bash
sudo nmap -p 443,465,993,995,8443 --script ssl-enum-ciphers,ssl-cert $TARGET
```

4) Vulnerability sweep (noisy; expect false positives/negatives; confirms require follow-up):
```bash
sudo nmap -sV --script vuln -oN nmap_vuln_${TARGET}.nmap $TARGET
```

5) Brute-force examples (intrusive; tighten args; only with authorization)
```bash
# Ensure SecLists is available: sudo apt-get install -y seclists
USERDB=/usr/share/seclists/Usernames/top-usernames-shortlist.txt
PASSDB=/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt

# SSH brute (limit time and stop after first hit)
sudo nmap -p 22 --script ssh-brute --script-args "userdb=$USERDB,passdb=$PASSDB,unpwdb.timelimit=5m,brute.firstOnly=true" $TARGET

# HTTP form brute (example; set real path)
sudo nmap -p 80 --script http-form-brute --script-args "http-form-brute.path=/admin/login,userdb=$USERDB,passdb=$PASSDB,brute.firstOnly=true" $TARGET
```

6) Script debugging and tracing (to understand what a script is doing):
```bash
# Increase verbosity and see script I/O
sudo nmap -sV --script http-title --script-trace -vv $TARGET

# Limit long-running scripts
sudo nmap -sV --script 'http-*' --script-timeout 30s $TARGET
```

7) Save all outputs with a common prefix:
```bash
sudo nmap -sC -sV -oA nmap_baseline $TARGET
sudo nmap -sV --script vuln -oA nmap_vuln $TARGET
```

8) Run a local/custom NSE script:
```bash
# Place custom.nse somewhere and run it directly
sudo nmap --script /path/to/custom.nse -p TARGET_PORT $TARGET
```

## Practical tips
- -sC equals --script=default and is generally safe; combine with -sV for best results early.
- Prefer targeted scripts based on detected services instead of running huge wildcards.
- Exclude risky categories when using wildcards: --script 'http-* and not (intrusive or dos)'
- Many scripts produce better output with -sV because service fingerprints guide script logic.
- Some scripts require UDP (-sU) or specific ports; match the transport correctly.
- Use --script-help to learn required/optional arguments before running.
- Use --script-timeout to avoid hangs, and --script-trace/-vv for troubleshooting.
- Save outputs (-oN/-oA) to keep evidence and iterate without losing context.
- In exam/lab contexts, avoid dos/intrusive unless explicitly allowed; start with default/safe.
- Update scripts database if you add custom scripts: sudo nmap --script-updatedb

## Minimal cheat sheet (one-screen flow)
```bash
# Baseline
sudo nmap -sC -sV -oA nmap_baseline 10.10.10.10

# List script info
nmap --script-help default
nmap --script-help 'http-*'

# HTTP quick enum
sudo nmap -p 80,443 --script http-title,http-headers,http-methods,http-robots.txt,http-enum 10.10.10.10

# SMB quick enum
sudo nmap -p 139,445 --script smb-os-discovery,smb-enum-shares,smb-enum-users 10.10.10.10

# FTP quick enum
sudo nmap -p 21 --script ftp-anon,ftp-syst,ftp-vsftpd-backdoor 10.10.10.10

# DNS (UDP)
sudo nmap -sU -p 53 --script dns-recursion,dns-nsid 10.10.10.10

# SNMP (UDP, known community)
sudo nmap -sU -p 161 --script snmp-info --script-args 'snmpcommunity=public' 10.10.10.10

# TLS info
sudo nmap -p 443,465,993,995 --script ssl-enum-ciphers,ssl-cert 10.10.10.10

# Vuln sweep (noisy)
sudo nmap -sV --script vuln -oA nmap_vuln 10.10.10.10

# Wildcard but safe-ish
sudo nmap -p 80,443 --script 'http-* and not (intrusive or dos)' 10.10.10.10
```

## Summary
This module focuses on using Nmap’s Scripting Engine to move from “ports are open” to “actionable service intelligence.” Start with -sC -sV, then selectively apply service-specific scripts. Learn script categories, call scripts by name/wildcard/category, and supply script arguments when needed. Favor safe/default categories first, exclude intrusive/dos unless allowed, and use debugging and timeouts to control behavior. Save outputs and iterate based on findings.