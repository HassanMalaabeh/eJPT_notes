# 03 - Importing Nmap Scan Results Into MSF (eJPT Study Notes)

Note: No transcript was provided. The following summary is inferred from the filename and typical eJPT workflow for importing Nmap results into Metasploit Framework. Commands and flags are conservative and widely compatible with current Kali/Metasploit versions.

## What the video covers (Introduction / big picture)
- How to take Nmap scan results and import them into Metasploit Framework (MSF) so you can:
  - Centralize hosts/services info in MSF’s database
  - Quickly filter targets by service/port
  - Set RHOSTS automatically for modules
- Recommended Nmap output formats for import (XML)
- Using MSF workspaces to keep assessments organized
- Verifying the import and pivoting into exploitation modules

## Flow (ordered)
1. Run Nmap with XML output enabled (-oX or -oA) against your target(s)
2. Ensure MSF’s database (PostgreSQL) is running
3. Launch msfconsole and confirm db_status
4. Create/select a workspace for the engagement
5. Import the Nmap XML file into the workspace
6. List hosts/services to verify parsed results
7. Build target lists (hosts -R or services -R) and run relevant MSF modules
8. Optionally export hosts/services lists for reporting or reuse

## Tools highlighted
- Nmap: network discovery and service enumeration
- Metasploit Framework (msfconsole): exploitation and auxiliary scanning
- MSF database (PostgreSQL): stores hosts, services, creds, loot
- MSF workspace feature: organizes data per engagement
- Optional: db_nmap (run Nmap from within msfconsole and auto-import)

## Typical command walkthrough (detailed, copy-paste friendly)

Prepare scan output (XML recommended):
```bash
# Create a scans directory (optional, for organization)
mkdir -p ~/scans/acme

# Quick TCP discovery + default scripts + service/version detection
nmap -sC -sV -T4 -oA ~/scans/acme/initial 192.168.56.0/24

# Focused scan against a discovered host (all TCP ports)
nmap -p- -sV -T4 -oA ~/scans/acme/host1 192.168.56.101

# If you only want a single XML file:
nmap -sC -sV -T4 -oX ~/scans/acme/host1.xml 192.168.56.101
```

Start MSF and ensure database is connected:
```bash
# Start PostgreSQL (Kali auto-starts, but this ensures it's running)
sudo systemctl enable --now postgresql

# Launch Metasploit
msfconsole -q
```

Inside msfconsole:
```text
# Check DB status
db_status
# Expected: "Connected to msf. Connection type: postgresql."

# Create/select a workspace for this engagement
workspace -a acme
workspace acme

# Import Nmap XML (prefer .xml; -oA generates .xml alongside .nmap/.gnmap)
db_import ~/scans/acme/initial.xml
db_import ~/scans/acme/host1.xml
# If you used -oA: the XML files are ~/scans/acme/initial.xml and host1.xml

# Verify imported data
hosts
services

# Examples: filter services
services -p 80,443
services -s open -p 22

# Set RHOSTS to everything in the current list (all hosts)
hosts -R

# Or only set RHOSTS based on services (e.g., only SMB targets)
services -p 445 -R

# Use a module and run against selected targets
use auxiliary/scanner/smb/smb_version
run

# Another example: enumerate HTTP titles on hosts with 80/443 open
services -p 80,443 -R
use auxiliary/scanner/http/title
run

# Optional: export hosts/services for reference or reporting
hosts -o ~/scans/acme/hosts.csv
services -o ~/scans/acme/services.csv
```

Alternative: run Nmap from inside Metasploit and auto-import:
```text
# Runs Nmap and imports results automatically into the current workspace
db_nmap -sC -sV -T4 192.168.56.0/24
```

If db_status is not connected:
```bash
# From a shell
sudo systemctl start postgresql
# If needed (older setups):
msfdb init
```

## Practical tips
- Always produce XML (-oX or -oA) when you intend to import scans; XML parsing is most reliable in MSF.
- Keep one MSF workspace per client/engagement to avoid mixing results.
- Use absolute paths when importing to avoid “file not found” errors in msfconsole.
- If an import fails, validate the XML file: xmllint --noout path/to/scan.xml
- Quickly target specific services: services -p 445 -R (SMB), services -p 21 -R (FTP), services -p 22 -R (SSH), services -p 80,443 -R (Web).
- Clear global RHOSTS if needed: unsetg RHOSTS
- db_import is idempotent on many entries; re-importing usually won’t break things, but be mindful of duplicates across workspaces.
- Use -oA for Nmap to keep .nmap (human-readable), .gnmap (grepable), and .xml (for import) together with the same base name.

## Minimal cheat sheet (one-screen flow)
```bash
# 1) Scan with XML output
nmap -sC -sV -T4 -oA ~/scans/acme/initial 192.168.56.0/24

# 2) Start MSF and ensure DB is connected
sudo systemctl enable --now postgresql
msfconsole -q
db_status

# 3) Workspace and import
workspace -a acme
workspace acme
db_import ~/scans/acme/initial.xml

# 4) Verify and build target lists
hosts
services
services -p 445 -R          # Example: SMB targets

# 5) Run a relevant module
use auxiliary/scanner/smb/smb_version
run

# Optional: export for notes
hosts -o ~/scans/acme/hosts.csv
services -o ~/scans/acme/services.csv
```

## Summary
- Generate Nmap results with XML output, then import them into Metasploit using db_import inside a dedicated workspace.
- Verify with hosts and services, then set RHOSTS directly from those lists to drive auxiliary/exploit modules.
- This workflow streamlines moving from discovery (Nmap) to enumeration/exploitation (MSF) during eJPT-style engagements.