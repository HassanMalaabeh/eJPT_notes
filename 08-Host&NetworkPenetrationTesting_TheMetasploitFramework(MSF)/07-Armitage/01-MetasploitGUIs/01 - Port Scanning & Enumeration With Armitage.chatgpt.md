# Port Scanning & Enumeration With Armitage (Metasploit GUI)

Note: The transcript was not provided. The following summary and commands are based on the filename and typical eJPT lab workflows using Armitage within Metasploit. I infer conservatively and stick to standard Armitage/Metasploit usage for port scanning and service enumeration.

## What the video covers (Introduction / big picture)
- How to perform host discovery, port scanning, and service enumeration using Armitage, the GUI for Metasploit Framework.
- Leveraging Armitage’s integration with Nmap and Metasploit’s database so your scan results are searchable and reusable.
- Viewing Hosts/Services/Vulns in the Metasploit database and enriching results with Metasploit auxiliary scanners.
- A quick path from scan → enumerate → prioritize likely attack paths (without focusing on exploitation).

Use only on systems and networks you are authorized to test.

## Flow (ordered)
1. Prepare environment:
   - Start PostgreSQL and Metasploit DB.
   - Launch Armitage and connect to the local Metasploit RPC server.
   - Create/select a workspace.
2. Add targets:
   - Manually add hosts or discover with Nmap via Armitage.
3. Run scans from Armitage:
   - Hosts > Nmap Scan > Quick Scan / Quick Scan (OS detect) for initial sweep.
   - Optional: Intense or targeted scans on specific hosts.
   - Import existing Nmap XML if you scanned externally.
4. Review results:
   - Hosts view (IP, OS guess, notes).
   - Services tab (open ports, service banners/versions).
5. Enrich with Metasploit scanners:
   - Run auxiliary scanners (e.g., smb_version, http_version, ssh_version).
6. Auto-correlation:
   - Optionally run Attacks > Find Attacks to map known exploit candidates.
7. Export/save:
   - Save workspace, export hosts/services/vulns for reporting.

## Tools highlighted
- Armitage (GUI front-end for Metasploit)
- Metasploit Framework (msfconsole, database, auxiliary scanners)
- Metasploit RPC Server (msfrpcd) – used by Armitage
- PostgreSQL (Metasploit’s database backend)
- Nmap (port scanning, service/OS detection)
- Metasploit database commands (db_nmap, db_import, hosts, services, vulns, creds)

## Typical command walkthrough (detailed, copy-paste friendly)

Replace example targets with your authorized lab scope (e.g., 192.168.56.0/24 or 10.10.10.0/24). Some commands require sudo/root for SYN and OS detection scans.

- Start database and Metasploit (one-time init)
```
sudo systemctl enable --now postgresql
msfdb init
```

- Start Metasploit and verify DB
```
msfconsole -q
db_status
```

- Set up a workspace for the engagement
```
workspace -a ejpt-armitage
workspace ejpt-armitage
```

- Option A: Scan directly into the DB via Metasploit (CLI; equivalent to Armitage’s Nmap scans)
```
# Fast TCP sweep with service/OS detection (adjust speed for reliability)
db_nmap -sS -sV -O -T4 192.168.56.0/24

# Full TCP port range on a discovered host
db_nmap -sS -sV -O -p- -T4 192.168.56.101

# Targeted UDP discovery on common ports
db_nmap -sU -sV -T3 --top-ports 50 192.168.56.0/24
# or a focused list:
db_nmap -sU -sV -T3 -p 53,67,69,123,137,161,500,1434 192.168.56.0/24
```

- Option B: Use external Nmap then import into MSF/Armitage
```
# Initial network sweep
sudo nmap -Pn -T4 -sS -sV -O -oA scans/ejpt_net 192.168.56.0/24

# Deep scan a single host
sudo nmap -Pn -T4 -sS -sV -O -p- -oA scans/host-192.168.56.101 192.168.56.101

# In msfconsole, import XML
db_import scans/ejpt_net.xml
db_import scans/host-192.168.56.101.xml
```

- Query results in Metasploit (Armitage reads the same DB)
```
hosts
services
services -p 21,22,80,135,139,443,445,3389
vulns
creds
```

- Enrich enumeration with common Metasploit auxiliary scanners
```
# SMB versioning (Windows targets)
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.56.0/24
set THREADS 50
run

# HTTP banner/version (web services)
use auxiliary/scanner/http/http_version
set RHOSTS 192.168.56.0/24
set RPORTS 80,8080,8000,443,8443
set THREADS 50
run

# SSH version enumeration
use auxiliary/scanner/ssh/ssh_version
set RHOSTS 192.168.56.0/24
set THREADS 50
run

# RDP scanner
use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS 192.168.56.0/24
set THREADS 50
run

# MySQL version
use auxiliary/scanner/mysql/mysql_version
set RHOSTS 192.168.56.0/24
run

# MSF TCP port scanner (fallback/minimal)
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.56.0/24
set PORTS 1-1000
set THREADS 100
run
```

- Export results (formats vary by Metasploit version; check help)
```
# See supported formats
help db_export

# Example export (XML or JSON depending on version)
db_export -f xml -a /tmp/ejpt-armitage.xml
# or
db_export -f json -a /tmp/ejpt-armitage.json
```

- Launch Armitage and connect (local, single-user)
```
# If needed:
sudo apt update && sudo apt install armitage

# Start Armitage GUI
armitage &
```
In Armitage:
- When prompted, choose to “Start MSF” (starts msfrpcd) and connect to 127.0.0.1 (default port 55553). If it asks for credentials, use the ones it created (commonly user msf, a generated password) or start msfrpcd manually:
```
msfrpcd -U msf -P letmein -a 127.0.0.1 -p 55553 -S -f
```
Then connect from Armitage with:
- Host: 127.0.0.1
- Port: 55553
- User: msf
- Pass: letmein
- SSL: enabled

- Inside Armitage (GUI actions)
  - Set workspace: Armitage > Workspaces > [select ejpt-armitage]
  - Add hosts: Hosts > Add Hosts (CIDR or list)
  - Nmap scans: Hosts > Nmap Scan > Quick Scan / Quick Scan (OS detect) / Intense Scan / UDP Scan
  - Import Nmap XML: File > Import Hosts (choose your .xml)
  - View results: Click Hosts (graph/table), Services tab, Notes
  - Run MSF scanners: Right-click host > Scan > [HTTP version, SMB version, etc.] or use Modules pane
  - Auto-map exploits: Attacks > Find Attacks (for context; enumeration focus remains)

## Practical tips
- Use the database: Run scans via db_nmap or import XML so all results are searchable in hosts/services/vulns.
- Start broad, then go deep: Quick TCP scan across the subnet, then deep/full scans per host of interest.
- UDP is slow: Prefer a focused UDP port list (53, 67/68, 69, 123, 137/138, 161, 500, 1434, 1900, 5353) unless you must sweep widely.
- Tune performance: -T4 is usually fine in labs; if missing hosts/ports, slow down (-T3) or adjust retries/timeouts.
- OS detection requires privileges: Use sudo for -O and SYN scans.
- Validate service fingerprints: Service versions can be misidentified; corroborate with banner grabs and HTTP enumeration.
- Keep workspaces separate: One workspace per lab or target range reduces confusion.
- Use THREADS responsibly: In auxiliary scanners, too many threads can drop accuracy or trip defenses.
- Save/export often: Armitage sessions can be saved; also export DB data for notes and reporting.

## Minimal cheat sheet (one-screen flow)
- Start DB and Metasploit
```
sudo systemctl start postgresql
msfdb init
msfconsole -q
workspace -a ejpt-armitage
```
- Scan and import
```
db_nmap -sS -sV -O -T4 192.168.56.0/24
db_nmap -sS -sV -O -p- -T4 192.168.56.101
```
- Enumerate services
```
hosts
services
use auxiliary/scanner/smb/smb_version; set RHOSTS 192.168.56.0/24; run
use auxiliary/scanner/http/http_version; set RHOSTS 192.168.56.0/24; set RPORTS 80,443,8080; run
use auxiliary/scanner/ssh/ssh_version; set RHOSTS 192.168.56.0/24; run
```
- Armitage GUI equivalents
  - Hosts > Add Hosts (or Nmap Scan)
  - Hosts > Nmap Scan > Quick Scan (OS detect)
  - Right-click host > Scan > SMB/HTTP/SSH version
  - View Hosts/Services tabs; Attacks > Find Attacks (optional)

## Summary
This session shows how to use Armitage to drive Nmap scans and Metasploit enumeration in a database-backed workflow. The key is to get high-quality host/port/service data into the Metasploit DB (via db_nmap or XML import), review Hosts/Services/Vulns, and enrich with targeted auxiliary scanners (SMB/HTTP/SSH/RDP/etc.). Armitage provides a visual way to manage this flow, while msfconsole offers copy-pasteable, scriptable equivalents. Use the workspace to keep engagements clean, tune scan speed for reliability, and only scan systems you’re authorized to test.