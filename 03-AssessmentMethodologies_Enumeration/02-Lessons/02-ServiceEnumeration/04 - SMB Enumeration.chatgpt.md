# 04 - SMB Enumeration (eJPT Study Notes)

Note: No transcript was provided. The content below is inferred conservatively from the filename and typical eJPT service-enumeration workflows for SMB on ports 139/445.

## What the video covers (Introduction / big picture)
- What SMB is and why it matters in internal/external assessments
- How to identify SMB services and versions (SMBv1/2/3), NetBIOS names, and domains
- Enumerating shares and permissions with and without credentials (null/guest)
- Pulling files from readable shares and automating downloads
- Enumerating users, groups, and password policies (RID cycling)
- Useful nmap SMB scripts and staple tools (smbclient, smbmap, enum4linux-ng, rpcclient)
- Preparing for potential exploitation paths (e.g., MS17-010) by checking version, signing, and access

## Flow (ordered)
1. Confirm SMB exposure: scan ports 139/445 and detect service/version.
2. Fingerprint SMB and host: protocols, OS, signing, NetBIOS names, domain/workgroup.
3. Test anonymous/null/guest access to list shares.
4. Enumerate shares and permissions (read/write); connect to readable shares.
5. Recursively pull content from readable shares; search for creds and host/domain hints.
6. Enumerate users/groups/RIDs and password policy (rpcclient/enum4linux-ng).
7. If creds are found, re-enumerate shares/permissions with auth; mount/download.
8. Check common SMB vulns (e.g., MS17-010) and SMBv1 presence to inform next steps.
9. Document findings (shares, users, interesting files, potential exploitability).

## Tools highlighted
- nmap with SMB NSE scripts (smb-os-discovery, smb-protocols, smb-enum-shares, smb-enum-users, smb-security-mode, smb2-security-mode, smb2-time, smb2-capabilities, smb-vuln-ms17-010)
- smbclient (list/connect/download; supports null/guest auth; recursive grabs)
- smbmap (quick share/perm overview; recursive listing; with/without creds)
- enum4linux-ng (modern enum for users/groups/shares/policies)
- rpcclient (RID cycling, password policy, server info via SAMR/RPC)
- nbtscan and nmblookup (NetBIOS names/workgroup/domain)
- impacket tools (lookupsid.py; optional)
- crackmapexec or netexec smb (optional credential validation/share enum)
- mount.cifs and smbget (mount/download entire shares)

## Typical command walkthrough (detailed, copy-paste friendly)

Set a target IP variable to speed things up:
```bash
export TARGET=10.10.10.10
```

1) Initial discovery and versioning
```bash
# Quick port and service/version detection
nmap -p 139,445 -sV -oN nmap_smb_$TARGET.txt $TARGET

# Broad service + default scripts on SMB ports
nmap -p 139,445 -sV -sC -oN nmap_smb_default_$TARGET.txt $TARGET
```

2) SMB fingerprinting (protocols, OS, signing)
```bash
# Protocols and OS info
nmap -p445 --script smb-protocols,smb-os-discovery $TARGET -oN nmap_smb_fp_$TARGET.txt

# SMB security mode (signing status) and SMB2 details
nmap -p445 --script smb-security-mode,smb2-security-mode,smb2-capabilities,smb2-time $TARGET -oN nmap_smb_sec_$TARGET.txt
```

3) NetBIOS names (optional but useful)
```bash
# Requires nbtscan; install if needed: sudo apt install nbtscan
nbtscan -v $TARGET
# Alternative
nmblookup -A $TARGET
```

4) Check anonymous/null/guest share enumeration
```bash
# List shares via smbclient (null auth)
smbclient -L //$TARGET -N

# Try guest explicitly if null fails
smbclient -L //$TARGET -U 'guest%'

# Quick overview of shares/permissions with smbmap (null auth)
smbmap -H $TARGET -u '' -p ''
smbmap -H $TARGET -u guest -p ''

# All-in-one enumeration (enum4linux-ng)
enum4linux-ng -A $TARGET -u '' -p '' | tee enum4linuxng_$TARGET.txt
```

5) Connect to a readable share and pull files
```bash
# Interactively connect (null auth)
smbclient //$TARGET/SHARE -N

# Inside smbclient prompt:
#   help
#   ls
#   cd subdir
#   get filename
#   recurse ON
#   prompt OFF
#   mget *
#   exit

# Non-interactive recursive download
smbclient //$TARGET/SHARE -N -c "recurse ON; prompt OFF; mget *"

# With guest
smbclient //$TARGET/SHARE -U 'guest%' -c "recurse ON; prompt OFF; mget *"
```

6) Enumerate users, groups, and password policy (RPC/SAMR)
```bash
# rpcclient null session (if allowed)
rpcclient -U "" -N $TARGET

# Inside rpcclient:
#   srvinfo
#   enumdomusers
#   enumdomgroups
#   getdompwinfo
#   queryuser 0x<rid>           # Inspect specific user by RID
#   querygroup 0x<rid>

# One-liners (if you prefer non-interactive):
rpcclient -U "" -N $TARGET -c 'srvinfo'
rpcclient -U "" -N $TARGET -c 'getdompwinfo'
rpcclient -U "" -N $TARGET -c 'enumdomusers'
```

7) If credentials are found or guessed, re-enumerate with auth
```bash
export USER='username'
export PASS='Password123!'
# Domain/workgroup if applicable (optional):
export DOMAIN='DOMAIN'

# smbmap with creds
smbmap -H $TARGET -u "$USER" -p "$PASS"
smbmap -H $TARGET -u "$USER" -p "$PASS" -d "$DOMAIN"
# Recursively list files within a share:
smbmap -H $TARGET -u "$USER" -p "$PASS" -r SHARE

# smbclient with creds
smbclient "//$TARGET/SHARE" -U "$USER%$PASS"
# Or with domain:
smbclient "//$TARGET/SHARE" -U "$DOMAIN/$USER%$PASS"

# Mount the share (read-only) for easy browsing
sudo mkdir -p /mnt/smb
sudo mount -t cifs "//$TARGET/SHARE" /mnt/smb -o "username=$USER,password=$PASS,ro,iocharset=utf8"
# When done
sudo umount /mnt/smb

# Bulk download via smbget (creds)
smbget -R "smb://$TARGET/SHARE" -u "$USER" -p "$PASS"
```

8) RID cycling and SID lookups (Impacket optional)
```bash
# If anonymous allows it (depends on target):
impacket-lookupsid $USER:$PASS@$TARGET
# Or with domain:
impacket-lookupsid $DOMAIN/$USER:$PASS@$TARGET
```

9) Vulnerability checks (inform next steps)
```bash
# MS17-010 (EternalBlue) and SMBv1 presence
nmap -p445 --script smb-vuln-ms17-010,smb-protocols $TARGET -oN nmap_ms17_$TARGET.txt

# Metasploit (optional)
msfconsole -q -x "use auxiliary/scanner/smb/smb_version; set RHOSTS $TARGET; run; use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS $TARGET; run; exit"
```

10) Validate credentials and shares at scale (optional)
```bash
# crackmapexec (AKA netexec). Install if needed.
crackmapexec smb $TARGET -u "$USER" -p "$PASS" --shares
# New name:
netexec smb $TARGET -u "$USER" -p "$PASS" --shares
```

## Practical tips
- Try null and guest access first; many environments still expose readable shares.
- Use nmap scripts early to learn SMB version and signing; SMB signing “required” often blocks relay-style attacks.
- Automate downloads carefully: recurse ON + prompt OFF in smbclient is fast but can be noisy; consider target scope and rules of engagement.
- Look for config files, passwords, backups, and scripts. Common hits: .txt, .ini, .config, .kdbx, unattended.xml, VNC, RDP, database connection strings.
- When specifying domain in smbclient, use DOMAIN/USER or -W DOMAIN. In smbmap, use -d DOMAIN.
- If anonymous RPC is denied, try with any low-priv user; rpcclient becomes very informative even with minimal creds.
- Enumerate password policy (getdompwinfo) to guide wordlists and spray strategies. Respect exam scope; avoid aggressive brute forcing.
- If SMBv1 is enabled and OS is legacy (e.g., Win7/2008), note potential MS17-010. Confirm carefully; NSE can be noisy/false-positive; cross-check with OS/version.
- Document everything: share names, permissions (READ/WRITE/NONE), notable file paths, discovered users, domain/workgroup, signing status.

## Minimal cheat sheet (one-screen flow)
```bash
# 1) Quick check
export TARGET=10.10.10.10
nmap -p 139,445 -sV -sC $TARGET -oN nmap_smb.txt

# 2) Fingerprint SMB
nmap -p445 --script smb-protocols,smb-os-discovery,smb-security-mode,smb2-security-mode $TARGET -oN nmap_smb_fp.txt
nbtscan -v $TARGET || nmblookup -A $TARGET

# 3) Null/guest shares
smbclient -L //$TARGET -N
smbclient -L //$TARGET -U 'guest%'
smbmap -H $TARGET -u '' -p ''

# 4) Connect + pull
smbclient "//$TARGET/SHARE" -N -c "recurse ON; prompt OFF; mget *"

# 5) Users/policy
rpcclient -U "" -N $TARGET -c 'srvinfo; getdompwinfo; enumdomusers'

# 6) With creds (if found)
export USER='user'; export PASS='pass'; export DOMAIN='DOMAIN'
smbmap -H $TARGET -u "$USER" -p "$PASS" -d "$DOMAIN"
smbclient "//$TARGET/SHARE" -U "$DOMAIN/$USER%$PASS" -c "recurse ON; prompt OFF; mget *"
sudo mount -t cifs "//$TARGET/SHARE" /mnt/smb -o "username=$USER,password=$PASS,ro"

# 7) Vuln check (careful)
nmap -p445 --script smb-vuln-ms17-010 $TARGET -oN nmap_ms17.txt
```

## Summary
This module focuses on a disciplined SMB enumeration workflow: identify SMB exposure and details, test anonymous access, enumerate shares/permissions, retrieve accessible data, enumerate users/groups and password policies via RPC, and re-run enumeration with any discovered credentials. Use nmap NSE for quick SMB fingerprinting, smbclient/smbmap for shares and downloads, enum4linux-ng/rpcclient for identity and policy information, and optional tools (Impacket, crackmapexec/netexec) for deeper checks. Findings from SMB enumeration frequently lead to credentials, sensitive files, or vulnerability paths such as MS17-010—capture them cleanly to inform the next phase.