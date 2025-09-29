# 03 - SMB & NetBIOS Enumeration

Note: No transcript was provided. The notes below are a conservative, exam-focused summary inferred from the filename and typical eJPT coverage for SMB/NetBIOS in a Network Attacks module.

## What the video covers (Introduction / big picture)
- Understanding SMB and NetBIOS roles in Windows/LAN environments
- Identifying SMB/NetBIOS services and versions on targets
- Enumerating system info, domain/workgroup, users, and shares
- Attempting anonymous/null sessions and authenticated enumeration
- Pulling files from shares and checking permissions
- Using Nmap NSE, enum4linux/NG, smbclient, smbmap, rpcclient, nbtscan/nmblookup
- Quick checks for common SMB vulnerabilities (e.g., MS17-010) and SMB signing

Key ports:
- UDP 137 (NBNS), UDP 138 (NBDS)
- TCP 139 (NetBIOS Session), TCP 445 (SMB over TCP)

## Flow (ordered)
1. Verify open SMB/NetBIOS ports (139/445 TCP; 137/138 UDP).
2. Discover NetBIOS names/workgroups (nbtscan/nmblookup or Nmap nbstat).
3. Enumerate SMB OS/version, time, protocols, signing, and shares via Nmap NSE.
4. Try anonymous/null sessions to list shares and access content.
5. Enumerate users/groups via SAMR/RPC (enum4linux/NG, rpcclient).
6. Enumerate shares and permissions (smbmap, smbclient).
7. If creds found, re-enumerate with authentication and pull files.
8. Check well-known SMB vulns (e.g., MS17-010) and SMB signing state.
9. Mount shares for bulk triage; search for sensitive files/passwords.
10. Optional: password spraying/bruteforce with caution (respect lockouts).

## Tools highlighted
- Nmap + NSE scripts: smb-os-discovery, smb2-security-mode, smb2-time, smb-protocols, smb-enum-shares, smb-enum-users, nbstat, smb-vuln-ms17-010
- nbtscan, nmblookup (NetBIOS)
- enum4linux, enum4linux-ng
- smbclient (interact with shares; null session testing)
- smbmap (list share permissions/content)
- rpcclient (SAMR/RPC queries)
- crackmapexec (rapid SMB checks across hosts)
- mount.cifs (mount shares)
- Optional: hydra (SMB auth brute/spray; beware lockouts)

## Typical command walkthrough (detailed, copy-paste friendly)
Set these variables once to speed up commands:
```bash
export IP=10.10.10.10
export SUBNET=10.10.10.0/24
export OUT=enum_smb_${IP}
mkdir -p $OUT
```

1) Port discovery and quick service detection
```bash
# Quick TCP check for SMB ports
nmap -n -Pn -p 139,445 -sS -sV -oN $OUT/nmap_tcp_139_445.txt $IP

# NetBIOS UDP discovery (NBNS/NetBIOS Datagram)
nmap -n -Pn -sU -p 137,138 --script nbstat -oN $OUT/nmap_udp_nbns.txt $IP
```

2) NetBIOS name/workgroup enumeration
```bash
# Sweep a subnet for NetBIOS names
nbtscan -r $SUBNET | tee $OUT/nbtscan_${IP//\./_}.txt

# Query a single host for its NetBIOS name table
nmblookup -A $IP | tee $OUT/nmblookup_$IP.txt
```

3) SMB OS/version, protocols, signing, time, shares, users (NSE)
```bash
# Core SMB enumeration scripts
nmap -n -Pn -p 139,445 -sV \
  --script "smb-os-discovery,smb2-time,smb-protocols,smb2-security-mode,smb-enum-shares,smb-enum-users" \
  -oN $OUT/nmap_smb_core.txt $IP

# Check MS17-010 (EternalBlue)
nmap -n -Pn -p 445 --script smb-vuln-ms17-010 -oN $OUT/nmap_smb_ms17-010.txt $IP
```

4) Anonymous/null session tests (shares, info)
```bash
# List shares via smbclient (null session)
smbclient -L "//$IP" -N | tee $OUT/smbclient_list_null.txt

# Sometimes you must force a protocol if SMB1 is disabled:
#   -m SMB2 or -m SMB3 (or NT1 for SMB1)
smbclient -L "//$IP" -N -m SMB2 | tee $OUT/smbclient_list_null_smb2.txt

# smbmap null session check
smbmap -H $IP -u '' -p '' | tee $OUT/smbmap_null.txt

# CrackMapExec quick null session and shares
crackmapexec smb $IP -u '' -p '' --shares | tee $OUT/cme_null_shares.txt
```

5) Enumerate users/groups via SAMR/RPC
```bash
# enum4linux classic
enum4linux -a $IP | tee $OUT/enum4linux_a.txt

# enum4linux-ng with output files
enum4linux-ng -A $IP -oA $OUT/enum4linuxng

# rpcclient (null session) - try several queries
rpcclient -U "" -N $IP -c "srvinfo" | tee $OUT/rpc_srvinfo.txt
rpcclient -U "" -N $IP -c "lsaquery" | tee -a $OUT/rpc_lsa.txt
rpcclient -U "" -N $IP -c "enumdomusers" | tee -a $OUT/rpc_users.txt
rpcclient -U "" -N $IP -c "enumdomgroups" | tee -a $OUT/rpc_groups.txt
```
Notes:
- Some RPC/SAMR calls may fail without credentials. Keep trying with and without domain/workgroup. If you have creds, add `-U 'DOMAIN/USER%PASS'`.

6) Interact with shares and pull files
```bash
# Replace SHARE with the actual share name (case-sensitive on Linux client)
export SHARE=Public

# Try connecting anonymously
smbclient "//$IP/$SHARE" -N -c "ls; pwd; exit" | tee $OUT/smbclient_${SHARE}_ls.txt

# Recursively download everything (be mindful of size)
smbclient "//$IP/$SHARE" -N -c "recurse on; prompt off; mget *" | tee $OUT/smbclient_${SHARE}_mget.txt

# Using smbmap to list and try recursive listing
smbmap -H $IP -u '' -p '' -r $SHARE | tee $OUT/smbmap_${SHARE}_r.txt

# Mount the share for easier triage (guest)
sudo mkdir -p /mnt/smb_$SHARE
sudo mount -t cifs "//$IP/$SHARE" /mnt/smb_$SHARE -o guest,ro,vers=3.0,uid=$(id -u),gid=$(id -g)
# If mount fails, try different versions: vers=3.0,2.1,2.0,1.0
# Search for sensitive content
grep -RHiIn -I -E "pass|pwd|cred|user|secret|key|token|config|\.kdbx|\.pfx|\.pem|\.ppk" /mnt/smb_$SHARE | tee $OUT/grep_sensitive_${SHARE}.txt
# Unmount when done
sudo umount /mnt/smb_$SHARE
```

7) Re-run with credentials (if found)
```bash
export USER='user1'
export PASS='P@ssw0rd!'
export DOM='WORKGROUP'  # or actual domain

# smbclient authenticated
smbclient "//$IP/$SHARE" -U "$DOM/$USER%$PASS" -c "ls; exit" | tee $OUT/smbclient_auth_${SHARE}.txt

# smbmap authenticated
smbmap -H $IP -d "$DOM" -u "$USER" -p "$PASS" | tee $OUT/smbmap_auth.txt
smbmap -H $IP -d "$DOM" -u "$USER" -p "$PASS" -R $SHARE | tee $OUT/smbmap_auth_${SHARE}_R.txt

# rpcclient authenticated
rpcclient -U "$DOM/$USER%$PASS" $IP -c "enumdomusers; enumdomgroups; queryuser 0x3e8" | tee $OUT/rpc_auth.txt

# CrackMapExec shares and signing with creds
crackmapexec smb $IP -d "$DOM" -u "$USER" -p "$PASS" --shares | tee $OUT/cme_auth_shares.txt
```

8) Optional: password spraying/bruteforce (beware lockouts)
```bash
# Using CrackMapExec to test one password against a list of users
crackmapexec smb $IP -u users.txt -p 'Summer2024!' --continue-on-success | tee $OUT/cme_spray.txt

# Hydra (SMB) brute force (adjust -t to control concurrency; may trigger lockouts)
hydra -L users.txt -P passwords.txt $IP smb -t 4 -f -o $OUT/hydra_smb.txt
```

9) SMB signing and protocol notes (useful for attacks feasibility)
```bash
nmap -n -Pn -p 445 --script smb2-security-mode -oN $OUT/nmap_smb_signing.txt $IP
# Look for: message_signing: enabled but not required
```

## Practical tips
- Always try null sessions first; many environments still expose some info or read-only shares.
- If smbclient fails, try forcing a protocol version with -m SMB2 or -m SMB3. Use NT1 only if SMB1 is explicitly required.
- When creds include special characters, prefer quoting or use DOMAIN/USER%PASS format carefully.
- enum4linux-ng often extracts more reliably than the classic enum4linux; run both.
- Save output to files to avoid losing findings; grep through later.
- On large shares, mount with CIFS and search locally for “password,” “config,” “.kdbx,” etc.
- Respect account lockouts; confirm lockout policy before any spraying/bruteforce.
- Record NetBIOS name, domain/workgroup, OS, and time skew; this helps correlate across hosts.
- Re-run enumeration with any newly found creds across the subnet using smbmap or crackmapexec.

## Minimal cheat sheet (one-screen flow)
```bash
# Vars
export IP=10.10.10.10; export SUBNET=10.10.10.0/24; mkdir -p smb_$IP

# Ports + NetBIOS
nmap -n -Pn -p 139,445 -sV -oN smb_$IP/tcp.txt $IP
nmap -n -Pn -sU -p 137 --script nbstat -oN smb_$IP/nbns.txt $IP
nbtscan -r $SUBNET | tee smb_$IP/nbtscan.txt
nmblookup -A $IP | tee smb_$IP/nmblookup.txt

# NSE SMB info
nmap -n -Pn -p 139,445 -sV --script "smb-os-discovery,smb2-security-mode,smb2-time,smb-protocols,smb-enum-shares,smb-enum-users" -oN smb_$IP/nse.txt $IP
nmap -n -Pn -p 445 --script smb-vuln-ms17-010 -oN smb_$IP/ms17.txt $IP

# Null session
smbclient -L "//$IP" -N -m SMB2 | tee smb_$IP/smbclient_null.txt
smbmap -H $IP -u '' -p '' | tee smb_$IP/smbmap_null.txt
enum4linux -a $IP | tee smb_$IP/e4l.txt
enum4linux-ng -A $IP -oA smb_$IP/e4lng

# Interact with a share (replace SHARE)
export SHARE=Public
smbclient "//$IP/$SHARE" -N -c "recurse on; prompt off; ls"
# Download all
smbclient "//$IP/$SHARE" -N -c "recurse on; prompt off; mget *"

# Mount and search
sudo mkdir -p /mnt/smb_$SHARE
sudo mount -t cifs "//$IP/$SHARE" /mnt/smb_$SHARE -o guest,ro,vers=3.0,uid=$(id -u),gid=$(id -g)
grep -RHiIn -I -E "pass|pwd|cred|user|secret|key|token|config|\.kdbx|\.pfx|\.pem|\.ppk" /mnt/smb_$SHARE

# With creds (if found)
export DOM=WORKGROUP; export USER=user1; export PASS='P@ssw0rd!'
smbmap -H $IP -d "$DOM" -u "$USER" -p "$PASS" --shares
```

## Summary
- SMB/NetBIOS enumeration starts with confirming ports and gathering NetBIOS names/workgroups.
- Use Nmap NSE to quickly pull OS, protocol level, signing, time, and share/user info.
- Test anonymous access early; use smbclient/smbmap/rpcclient/enum4linux to enumerate users, groups, and shares.
- Interact with shares and download or mount to systematically triage for credentials and configs.
- If credentials are discovered, re-run enumeration and expand across the subnet.
- Check for common SMB vulnerabilities and signing requirements to gauge attack surface.