# 04 - Importing Nmap Scan Results into MSF

Note: No transcript was provided; the following is a conservative, exam-focused summary inferred from the filename and typical eJPT workflow.

## What the video covers (Introduction / big picture)
- How to take Nmap scan output (including NSE results) and import it into Metasploit Framework’s database.
- Using Metasploit workspaces to organize targets.
- Viewing imported hosts, services, OS info, and script findings.
- Alternative: running Nmap from inside Metasploit with db_nmap to auto-import results.

## Flow (ordered)
1. Run Nmap against target(s) and save results in XML (or -oA) format.
2. Start Metasploit and ensure the database connection is active.
3. Create/select a workspace for the engagement.
4. Import the Nmap XML into Metasploit.
5. Enumerate imported hosts/services; filter and create target sets.
6. Optionally run Nmap from within Metasploit using db_nmap for direct import.
7. Use services/hosts filters to set RHOSTS and proceed with modules.

## Tools highlighted
- Nmap (with -sV, -sC, --script, -oX/-oA)
- Metasploit Framework (msfconsole)
  - Database integration (PostgreSQL via msfdb)
  - Commands: db_status, workspace, import/db_import, hosts, services, vulns, notes, db_nmap

## Typical command walkthrough (detailed, copy-paste friendly)

Prep a scan folder:
```
mkdir -p ~/scans
```

A. Run Nmap outside Metasploit and export XML
- Quick TCP service and default NSE scripts (recommended baseline):
```
nmap -sC -sV -T4 -oA ~/scans/acme_quick 10.10.10.0/24
# Produces ~/scans/acme_quick.xml (plus .nmap and .gnmap)
```
- Deeper enumeration with vulnerability NSE category (optional, heavier):
```
nmap -sS -sV -O --script default,vuln -T4 -oA ~/scans/acme_deep 10.10.10.0/24
```

B. Start Metasploit and ensure DB is connected
```
msfconsole
```
Inside msfconsole:
```
db_status
# If disconnected on Kali/Parrot:
# run this in a shell:   msfdb init
# or ensure Postgres is running: systemctl start postgresql
```

C. Use a workspace (keeps engagements separate)
```
workspace -a acme
workspace acme
```

D. Import Nmap results (XML from -oX or -oA)
```
import ~/scans/acme_quick.xml
# or
db_import ~/scans/acme_quick.xml
```

E. Review imported data
```
hosts
services
vulns
notes
```

F. Filter and create target sets for modules
- Common examples:
```
# All hosts with TCP 445 open (SMB)
services -p 445 -u
services -p 445 -R  # Add these hosts to RHOSTS

# All hosts with SSH
services -p 22 -u
services -p 22 -R

# Search for service name pattern (e.g., Apache)
services -S Apache -u
services -S Apache -R

# Confirm RHOSTS
show options
```

G. Optional: Run Nmap directly inside Metasploit (auto-import)
```
db_nmap -sC -sV -T4 10.10.10.0/24
hosts
services
```

H. Inspect NSE-derived findings (often stored as notes or vulns)
```
notes -h
notes
vulns
```

I. Proceed to module selection
```
# Examples:
search type:auxiliary smb
search type:auxiliary ftp
search type:exploit name:apache
```

J. Optional automation via resource file
Create ~/scans/import.rc:
```
workspace -a acme
workspace acme
db_import ~/scans/acme_quick.xml
hosts
services
vulns
```
Run:
```
msfconsole -r ~/scans/import.rc
```

## Practical tips
- Use -oX or -oA when scanning with Nmap; Metasploit imports best from XML.
- db_nmap is convenient but you lose the standalone Nmap artifacts unless you also save with -oA (not needed for import).
- Re-imports generally merge by host/port, but keep workspaces tidy to avoid confusion.
- Use services -R and hosts -R to build RHOSTS quickly from filters.
- NSE “vuln” results can be noisy; treat them as leads, not proof.
- If db_status shows disconnected, run msfdb init (Kali/Parrot) and ensure PostgreSQL is running.
- Keep separate workspaces per target network to avoid mixing data.

## Minimal cheat sheet (one-screen flow)
```
# Nmap outside MSF
nmap -sC -sV -T4 -oA ~/scans/lab 10.10.10.0/24

# Start MSF and connect DB
msfconsole
db_status

# Workspace + import
workspace -a lab
workspace lab
import ~/scans/lab.xml   # or: db_import ~/scans/lab.xml

# Review
hosts
services
vulns
notes

# Build target set (example: SMB)
services -p 445 -u
services -p 445 -R
show options

# Alternative: run Nmap inside MSF
db_nmap -sC -sV -T4 10.10.10.0/24
```

## Summary
- Export Nmap results to XML (-oX or -oA) and import them into Metasploit with import/db_import.
- Use workspaces to organize data and db_status to verify the DB connection.
- After import, leverage hosts/services/vulns/notes to triage and build RHOSTS via services -R.
- db_nmap offers an inside-MSF alternative that auto-ingests results.
- This workflow bridges discovery (Nmap/NSE) with exploitation (Metasploit) efficiently for eJPT-style engagements.