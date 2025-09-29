# 07 - SMB Enumeration (eJPT)

Note: No transcript was provided. The following is a conservative, exam-focused summary inferred from the filename and eJPT enumeration context.

## What the video covers (Introduction / big picture)
- Understanding SMB (Server Message Block) on ports 139/445 and why it’s a high‑value enumeration target.
- Identifying SMB versions, security settings (e.g., signing), and potential vulnerabilities.
- Enumerating shares, users, groups, domains, and permissions.
- Testing anonymous/null and guest access; pivoting to credentialed enumeration when available.
- Practical file access and data exfiltration from SMB shares.

## Flow (ordered)
1. Confirm SMB exposure and service details with Nmap.
2. Fingerprint SMB protocol, dialects, signing, and time via NSE scripts.
3. Try anonymous/null and guest sessions to list shares and gather info.
4. Enumerate users/groups/shares via enum4linux / rpcclient.
5. List share permissions and recursively list/download content with smbmap/smbclient.
6. If you obtain usernames, do targeted password sprays and re-check shares.
7. Mount shares for faster loot if read access exists.
8. Keep notes of hostnames, domain, shares, permissions, and loot paths.

## Tools highlighted
- Nmap + NSE: smb-os-discovery, smb-protocols, smb2-security-mode, smb2-time, smb-enum-*, smb-vuln-ms17-010
- smbclient (Samba client)
- smbmap
- enum4linux / enum4linux-ng
- rpcclient (Samba RPC)
- CrackMapExec (CME) for quick share/user checks and sprays
- NetBIOS helpers: nmblookup, nbtscan
- Impacket: lookupsid.py (simple RID/user enumeration)

## Typical command walkthrough (detailed, copy-paste friendly)

Set a target environment variable:
```bash
TARGET=10.10.10.10
mkdir -p nmap loot/$TARGET
```

1) Quick SMB confirmation and service enumeration
```bash
# Basic scripts + versions (often enough to spot OS/name/signing)
nmap -Pn -p 139,445 -sC -sV $TARGET -oN nmap/smb_basic_$TARGET.nmap
```

2) Protocol, security mode, and time skew
```bash
nmap -Pn -p 445 --script "smb-protocols,smb2-security-mode,smb2-time,smb2-capabilities,smb-os-discovery" \
    $TARGET -oN nmap/smb_proto_$TARGET.nmap
```

3) Vulnerability probes (lightweight checks)
```bash
# EternalBlue check; treat results conservatively and confirm manually
nmap -Pn -p 139,445 --script "smb-vuln-ms17-010" $TARGET -oN nmap/smb_vuln_$TARGET.nmap
```

4) NetBIOS/hostname discovery (if available)
```bash
nmblookup -A $TARGET
# or network-wide
# nbtscan -r 10.10.10.0/24
```

5) Anonymous/null and guest checks
```bash
# List shares anonymously
smbclient -L "//$TARGET" -N

# Test anonymous IPC$ session
smbclient "//$TARGET/IPC$" -N -c 'q'

# Show share permissions (null)
smbmap -H $TARGET -u '' -p ''

# Quick share/user discovery with CME (null)
crackmapexec smb $TARGET -u '' -p '' --shares
```

6) Broad SMB enumeration with enum4linux
```bash
enum4linux -a $TARGET | tee enum4linux_$TARGET.txt
# or the newer fork
enum4linux-ng -A $TARGET | tee enum4linux-ng_$TARGET.txt
```

7) User/SID enumeration (works well when null or weak creds are allowed)
```bash
# RID cycling with Impacket (null)
lookupsid.py anonymous@$TARGET -no-pass | tee lookupsid_$TARGET.txt

# RPC enumeration (null). Some commands may require creds, but try:
rpcclient -N -U "" $TARGET -c "srvinfo; lsaquery; enumdomusers; enumdomgroups; querydominfo"
```

8) If you have credentials (examples)
```bash
USER='user'; PASS='Password123!'

# Enumerate shares with creds
smbclient -L "//$TARGET" -U "$USER%$PASS"
smbmap -H $TARGET -u "$USER" -p "$PASS"
crackmapexec smb $TARGET -u "$USER" -p "$PASS" --shares --users
```

9) Access and recursively download share contents
```bash
# Interactive approach
SHARE='public'
mkdir -p loot/$TARGET/$SHARE
smbclient "//$TARGET/$SHARE" -N
# At the smb:> prompt:
#   recurse ON
#   prompt OFF
#   lcd loot/$TARGET/$SHARE
#   mget *

# One-liner non-interactive recursive pull (anonymous)
smbclient "//$TARGET/$SHARE" -N -c "recurse ON; prompt OFF; lcd loot/$TARGET/$SHARE; mget *"

# With credentials
smbclient "//$TARGET/$SHARE" -U "$USER%$PASS" -c "recurse ON; prompt OFF; lcd loot/$TARGET/$SHARE; mget *"
```

10) Recursively list shares and search for interesting files
```bash
# Recursively list a share (null or creds)
smbmap -H $TARGET -u '' -p '' -R $SHARE
# With creds and file name patterns
smbmap -H $TARGET -u "$USER" -p "$PASS" -R $SHARE -A 'pass|cred|config|.kdbx|.pem|.ppk|id_rsa'
```

11) Mount a share for fast browsing/loot
```bash
SHARE='public'
MNT="/mnt/${TARGET}_${SHARE}"
sudo mkdir -p "$MNT"

# Anonymous mount; adjust SMB version if needed (try 3.0, then 2.1, then 1.0)
sudo mount -t cifs "//$TARGET/$SHARE" "$MNT" -o guest,ro,vers=3.0 || \
sudo mount -t cifs "//$TARGET/$SHARE" "$MNT" -o guest,ro,vers=2.1 || \
sudo mount -t cifs "//$TARGET/$SHARE" "$MNT" -o guest,ro,vers=1.0

# With creds (read-only)
# sudo mount -t cifs "//$TARGET/$SHARE" "$MNT" -o username=$USER,password=$PASS,ro,vers=3.0
# When done:
# sudo umount "$MNT"
```

12) Targeted password spray (if you have a user list)
```bash
# CME single password spray across a user list
crackmapexec smb $TARGET -u users.txt -p 'Summer2024!' --continue-on-success

# Re-check shares with any successful credentials found
# crackmapexec smb $TARGET -u 'foundUser' -p 'foundPass' --shares
```

13) Nmap share/user NSE as an alternative to above tools
```bash
nmap -Pn -p 139,445 --script "smb-enum-shares,smb-enum-users" $TARGET -oN nmap/smb_enum_$TARGET.nmap
```

Notes:
- Default administrative shares: C$, ADMIN$, IPC$. Read access is uncommon; IPC$ is used for null sessions.
- Useful smbclient dialect switches if connection fails: -m SMB3 | -m SMB2 | -m NT1

## Practical tips
- Always try null/guest access first; many labs allow it for practice.
- Read the Nmap smb2-security-mode result. “Signing not required” can enable certain attack paths later and helps tool compatibility.
- Use smbmap first to quickly see share permissions (READ/WRITE). Then dive into smbclient for extraction.
- Automate loot: turn recurse ON and prompt OFF in smbclient to pull entire trees.
- When a share denies SMB3, try SMB2 or NT1 (SMB1) with smbclient -m; on mount.cifs, use vers= flag.
- Enum users early (enum4linux-ng, lookupsid.py). Even a single username can enable a spray.
- Keep loot organized per host/share: loot/<ip>/<share>/ to avoid mixing files.
- If Nmap smb-vuln scripts produce positives, verify manually; NSE can yield false positives.
- On domain controllers, check SYSVOL and NETLOGON shares for scripts/configs and Group Policy artifacts.

## Minimal cheat sheet (one-screen flow)
```bash
TARGET=10.10.10.10
mkdir -p nmap loot/$TARGET

# 1) Quick check
nmap -Pn -p 139,445 -sC -sV $TARGET -oN nmap/smb_basic_$TARGET.nmap
nmap -Pn -p 445 --script "smb-protocols,smb2-security-mode,smb2-time,smb-os-discovery" \
    $TARGET -oN nmap/smb_proto_$TARGET.nmap

# 2) Null/guest attempts
smbclient -L "//$TARGET" -N
smbmap -H $TARGET -u '' -p ''
rpcclient -N -U "" $TARGET -c "srvinfo; lsaquery"

# 3) Broad enum
enum4linux-ng -A $TARGET | tee enum4linux-ng_$TARGET.txt
lookupsid.py anonymous@$TARGET -no-pass | tee lookupsid_$TARGET.txt

# 4) Share loot (anonymous example)
SHARE='public'; mkdir -p loot/$TARGET/$SHARE
smbclient "//$TARGET/$SHARE" -N -c "recurse ON; prompt OFF; lcd loot/$TARGET/$SHARE; mget *"

# 5) With creds (if found)
USER='user'; PASS='Password123!'
smbmap -H $TARGET -u "$USER" -p "$PASS"
crackmapexec smb $TARGET -u "$USER" -p "$PASS" --shares
smbclient "//$TARGET/$SHARE" -U "$USER%$PASS" -c "recurse ON; prompt OFF; lcd loot/$TARGET/$SHARE; mget *"

# 6) Optional mount
MNT="/mnt/${TARGET}_${SHARE}"; sudo mkdir -p "$MNT"
sudo mount -t cifs "//$TARGET/$SHARE" "$MNT" -o guest,ro,vers=3.0 || \
sudo mount -t cifs "//$TARGET/$SHARE" "$MNT" -o guest,ro,vers=2.1 || \
sudo mount -t cifs "//$TARGET/$SHARE" "$MNT" -o guest,ro,vers=1.0
```

## Summary
- SMB enumeration is high-value: confirm ports 139/445, fingerprint SMB protocol/signing, and check for known vulns.
- Always try null/guest; quickly enumerate with enum4linux(-ng), smbmap, and rpcclient.
- Use smbclient to list and recursively pull files; mount shares when needed for speed.
- Build a user list and perform targeted sprays; re-check shares with any valid credentials.
- Keep an organized loot structure and note host/domain/share/permission details for escalation.