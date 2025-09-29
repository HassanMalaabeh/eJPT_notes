# 06 - SNMP Enumeration

Note: No transcript was provided for this video. The following is a careful, exam-oriented summary inferred from the filename and the eJPT Network Attacks context. Commands and OIDs are standard for SNMP enumeration and safe to use in lab/legal environments.

## What the video covers (Introduction / big picture)
- Understanding SNMP (Simple Network Management Protocol) and its role in network/device management.
- Identifying SNMP services on a target network (typically UDP/161).
- Discovering and validating SNMP community strings (v1/v2c), especially defaults like public/private.
- Enumerating valuable host and network information via SNMP:
  - System info, uptime, contact, location
  - Interfaces, IP addresses, routes, ARP cache
  - Running processes and installed software
  - Windows users and shares (when exposed)
- Using Kali tools and Nmap NSE scripts to automate and structure SNMP enumeration.
- Brief mention of SNMPv3 and why it’s harder to enumerate without credentials.

## Flow (ordered)
1. Discover SNMP on targets (UDP 161).
2. Brute/guess community strings.
3. Validate a found community string.
4. Enumerate systematically with snmpwalk/snmp-check and Nmap NSE.
5. Extract high-value data (users, processes, routes, ARP, interfaces).
6. Document findings and map potential pivots/attack paths.
7. If only SNMPv3 is present, note credential requirement and move on unless creds are available.

## Tools highlighted
- Nmap (UDP scan and NSE scripts: snmp-info, snmp-interfaces, snmp-netstat, snmp-processes, snmp-win32-*)
- onesixtyone (fast SNMP community string discovery)
- snmpwalk, snmpget, snmpbulkwalk (core enumeration)
- snmp-check (summary report of SNMP data)
- Optional: snmpset (read-write testing; use only in lab/with explicit permission)
- SecLists wordlist for SNMP communities (common-community-strings.txt)

## Typical command walkthrough (detailed, copy-paste friendly)

Set handy variables:
```bash
export TARGET=10.10.10.10
export NET=10.10.10.0/24
export COMMUNITY=public
```

1) Discover SNMP (UDP/161)
```bash
# Fast sweep of a subnet for UDP/161 (requires sudo for raw sockets)
sudo nmap -sU -p 161 --open -Pn -T4 $NET -oA snmp_sweep

# Against a single target with basic scripts and version detection
sudo nmap -sU -p 161 -sC -sV -Pn $TARGET -oA snmp_single
```

2) Brute/guess community strings
```bash
# Using onesixtyone with a community wordlist
# Wordlist path (SecLists) may vary; this is common on Kali
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-community-strings.txt $TARGET

# Nmap snmp-brute using a custom community list
sudo nmap -sU -p 161 --script snmp-brute \
  --script-args snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/common-community-strings.txt \
  -Pn $TARGET -oN snmp_brute.nmap
```

3) Validate a found community string
```bash
# Get system description (OS/hardware info)
snmpget -v2c -c $COMMUNITY $TARGET 1.3.6.1.2.1.1.1.0

# Get system name and uptime
snmpget -v2c -c $COMMUNITY $TARGET 1.3.6.1.2.1.1.5.0
snmpget -v2c -c $COMMUNITY $TARGET 1.3.6.1.2.1.1.3.0
```

4) Enumerate broadly with snmpwalk (v2c preferred)
```bash
# If MIB name translation is disabled on Kali, you can still use numeric OIDs.
# General system group (sysDescr, sysContact, sysName, sysLocation, etc.)
snmpwalk -v2c -c $COMMUNITY $TARGET 1.3.6.1.2.1.1

# Network interfaces (names, descriptions, MACs)
snmpwalk -v2c -c $COMMUNITY $TARGET 1.3.6.1.2.1.2.2.1.2      # ifDescr
snmpwalk -v2c -c $COMMUNITY $TARGET 1.3.6.1.2.1.31.1.1.1.1    # ifName (extended)

# IP addresses and netmasks
snmpwalk -v2c -c $COMMUNITY $TARGET 1.3.6.1.2.1.4.20

# Routing table
snmpwalk -v2c -c $COMMUNITY $TARGET 1.3.6.1.2.1.4.21

# ARP cache (IPv4 neighbor table)
snmpwalk -v2c -c $COMMUNITY $TARGET 1.3.6.1.2.1.4.22

# Host resources (processes, installed software)
snmpwalk -v2c -c $COMMUNITY $TARGET 1.3.6.1.2.1.25.1.6.0       # hrSystemProcesses
snmpwalk -v2c -c $COMMUNITY $TARGET 1.3.6.1.2.1.25.4.2.1.2     # hrSWRunName (running processes)
snmpwalk -v2c -c $COMMUNITY $TARGET 1.3.6.1.2.1.25.4.2.1.4     # hrSWRunPath (process paths)
snmpwalk -v2c -c $COMMUNITY $TARGET 1.3.6.1.2.1.25.6.3.1.2     # hrSWInstalledName (installed software)

# Windows accounts (LanManager MIB) if exposed
snmpwalk -v2c -c $COMMUNITY $TARGET 1.3.6.1.4.1.77.1.2.25
```

5) Nmap NSE for quick, structured reports
```bash
sudo nmap -sU -p 161 -Pn --script \
snmp-info,snmp-interfaces,snmp-netstat,snmp-processes,snmp-win32-services,snmp-win32-users,snmp-win32-shares \
$TARGET -oN snmp_enum.nmap
```

6) snmp-check (nice one-command summary)
```bash
snmp-check -v 2c -c $COMMUNITY $TARGET | tee snmp_check_$TARGET.txt
```

7) Optional: Bulk walk and performance flags
```bash
# Bulk walk (v2c) for speed; adjust -t (timeout) and -r (retries) for lossy networks
snmpbulkwalk -v2c -c $COMMUNITY -Cr100 -t 2 -r 1 $TARGET .1
```

8) Optional: SNMPv3 (requires valid creds; often not brute-forced in eJPT)
```bash
# Example with authPriv; replace with actual user and passwords
snmpwalk -v3 -l authPriv -u snmpuser -a SHA -A 'authpass' -x AES -X 'privpass' $TARGET 1.3.6.1.2.1.1
```

9) Optional: Test read-write community (lab only; non-destructive example)
```bash
# If you discovered a RW community (e.g., 'private'), change sysContact temporarily (lab only!)
snmpset -v2c -c private $TARGET 1.3.6.1.2.1.1.4.0 s "pentest-lab"
```

10) Enable MIB names on Kali (optional, for readability)
```bash
# Install MIBs and allow name resolution
sudo apt update && sudo apt install -y snmp snmp-mibs-downloader
# On many Kali builds, uncomment or remove the 'mibs :' line in /etc/snmp/snmp.conf
sudo sed -i 's/^mibs :/# mibs :/' /etc/snmp/snmp.conf
# Now you can use names, e.g., 'system' instead of numeric OIDs
snmpwalk -v2c -c $COMMUNITY $TARGET system
```

## Practical tips
- UDP is lossy and slow; expect timeouts. Use -T4 cautiously and increase retries/timeouts for distant targets.
- If enumeration seems empty, try -v1 as well as -v2c; some devices only speak one version.
- Always verify the community string with a quick snmpget (sysDescr.0) before heavy walks.
- Use numeric OIDs (-On) if MIBs aren’t installed; results are the same, just less readable.
- onesixtyone is very fast for scanning large ranges; use Nmap snmp-brute on smaller target sets.
- Focus on high-value OIDs: system (.1.3.6.1.2.1.1), interfaces (.2), IP (.4), host-resources (.25), and Windows LanManager (.1.3.6.1.4.1.77).
- If you find RW communities, treat them as high-risk findings; document, don’t change configs unless explicitly authorized.
- SNMPv3 without credentials is generally a dead end; pivot to credential discovery elsewhere.

## Minimal cheat sheet (one-screen flow)
```bash
# 1) Discover SNMP
sudo nmap -sU -p 161 --open -Pn -T4 10.10.10.0/24 -oA snmp_sweep

# 2) Guess communities
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-community-strings.txt 10.10.10.10

# 3) Validate (replace 'public' if needed)
snmpget -v2c -c public 10.10.10.10 1.3.6.1.2.1.1.1.0

# 4) Enumerate key data
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.1
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.2.2.1.2
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.4.20
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.4.21
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.25.6.3.1.2
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.4.1.77.1.2.25

# 5) NSE helpers
sudo nmap -sU -p 161 -Pn --script snmp-info,snmp-interfaces,snmp-netstat,snmp-processes,snmp-win32-services,snmp-win32-users,snmp-win32-shares 10.10.10.10 -oN snmp_enum.nmap

# 6) Quick report
snmp-check -v 2c -c public 10.10.10.10 | tee snmp_check_10.10.10.10.txt
```

## Summary
- SNMP enumeration is a high-yield network attack step in eJPT, especially when default or weak community strings are used.
- Start by identifying UDP/161, brute/guess community strings, confirm with snmpget, then enumerate with snmpwalk and NSE scripts.
- Prioritize system info, interfaces, IPs, routes, ARP, processes, installed software, and (on Windows) users and shares.
- SNMPv3 requires valid credentials; without them, enumeration is limited.
- Document all findings; treat read-write access as critical and avoid making changes without explicit authorization.