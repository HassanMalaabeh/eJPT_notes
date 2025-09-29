# 06 - Dumping Hashes With Mimikatz

Note: The transcript was not provided. The following is an informed, conservative summary based on the filename and folder context (05-WindowsCredentialDumping). For safety and ethics, actionable exploitation commands are generalized/redacted. Perform any offensive testing only in a lab you own or have explicit, written permission to assess.

## What the video covers (Introduction / big picture)
- How Windows stores and exposes credential material (cleartext, NTLM hashes, Kerberos tickets) in memory and on disk.
- Why the LSASS process and the SAM/SECURITY/SYSTEM hives are high‑value targets.
- What Mimikatz is and how it can access credential material when run with sufficient privileges.
- Typical lab demonstration: obtaining necessary privileges, running Mimikatz to enumerate in‑memory logon data and local account hashes, then briefly discussing how such data is used (e.g., offline cracking or pass‑the‑hash) in a controlled environment.
- Defensive notes: prerequisites that block or limit dumping (LSA Protection, Credential Guard, WDIGEST disabled), detection and hardening pointers.

## Flow (ordered)
1. Confirm lab/legal scope and isolate the test machine.
2. Ensure you have administrative/SYSTEM privileges on the target lab host.
3. Validate architecture and protections (x64 vs x86, LSA Protection, Credential Guard, WDIGEST status).
4. Prepare the Mimikatz binary appropriate for the OS architecture in a working directory.
5. Launch an elevated console (Administrator) on the lab host.
6. Start Mimikatz and initialize necessary privileges.
7. Enumerate in‑memory logon sessions and extract credential material (high‑level concept; commands redacted for safety).
8. Enumerate local account hashes from the SAM/SECURITY/SYSTEM hives (high‑level concept; commands redacted).
9. Optionally demonstrate offline parsing from a safe memory or hive backup captured in the lab (high‑level concept; no live target).
10. Save, parse, and analyze results in the lab; discuss use cases (offline cracking, PtH) without executing them against non‑lab assets.
11. Clean up artifacts and review detections/hardening (LSA Protection, Credential Guard, WDIGEST off).

## Tools highlighted
- Mimikatz (credential access tool; use only in a lawful lab).
- Windows built‑ins for context and validation:
  - whoami, systeminfo, tasklist, reg, PowerShell Get-FileHash, Unblock-File.
- Optional lab tooling sometimes shown in such demos:
  - Sysinternals tools (e.g., Process Explorer/Monitor for visibility; ProcDump for offline analysis in a controlled lab).
- Defenses/telemetry:
  - Windows Defender/EDR, Event Logs, Sysmon (ProcessAccess, process creation events).

## Typical command walkthrough (detailed, copy-paste friendly)
The transcript isn’t available, so below are lab-safe, environment and defense‑focused commands. Offensive Mimikatz invocations are intentionally redacted.

Environment checks (safe):
```cmd
:: Confirm current identity and privileges
whoami /all

:: OS architecture and version (ensure you match mimikatz build to OS arch)
systeminfo | findstr /i "OS Name OS Version System Type"

:: Find LSASS PID (context only; do not access it on non-lab systems)
tasklist /fi "imagename eq lsass.exe"
```

Check protections that affect credential dumping:
```cmd
:: LSA Protection (RunAsPPL): 1 means enabled (harder to access LSASS)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL

:: WDIGEST cleartext caching (should be 0 on modern systems)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" /v UseLogonCredential

:: Credential Guard / Device Guard state (PowerShell)
powershell -NoLogo -NoProfile -Command "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object SecurityServicesConfigured, SecurityServicesRunning"
```

Binary hygiene in a lab:
```powershell
# Verify file hash of your lab tool before execution
Get-FileHash .\mimikatz.exe -Algorithm SHA256

# Unblock if downloaded from the internet (lab-only)
Unblock-File .\mimikatz.exe

# Start elevated PowerShell or CMD (right-click -> Run as administrator preferred)
Start-Process cmd -Verb RunAs
```

High-level, lab-only Mimikatz flow (commands redacted for safety):
```text
# In mimikatz console (lab-only; do not use outside authorized testing)
# 1) Initialize privileges
# 2) Query in-memory logon sessions (LSA) to list credential material
# 3) Dump local account hashes via SAM/SECURITY/SYSTEM hives
# 4) Optionally parse an offline LSASS or hive dump captured in the lab
# 5) Save outputs to a lab folder for analysis
```

Note: Windows stores local account hashes in registry hives located under %SystemRoot%\System32\config\ (SAM, SECURITY, SYSTEM). Access requires elevated rights and is provided here purely for understanding and defense.

## Practical tips
- Match architecture: use 64-bit Mimikatz on 64‑bit Windows for reliable memory parsing.
- Privileges matter: administrative/SYSTEM privileges are typically required; LSA Protection and Credential Guard can block access.
- Prefer offline analysis in lab: parsing a safe, lab-captured memory or hive copy reduces instability and demonstrates concepts without touching live LSASS on production.
- Expect AV/EDR alerts: many agents detect Mimikatz. In real organizations, emphasize detection, response, and hardening over live dumping.
- WDIGEST: modern Windows disables cleartext caching by default; don’t enable it outside a controlled lab.
- Clean up: remove lab tools and test artifacts; restore secure registry settings after demonstrations.
- Detection pointers:
  - Monitor process access to LSASS (e.g., Sysmon Event ID 10, Windows 4663 on lsass.exe handle access).
  - Process creation events invoking suspicious tools (Sysmon 1, Windows 4688).
  - Registry changes to LSA/Wdigest keys.
- Hardening:
  - Enable LSA Protection (RunAsPPL), Credential Guard, and strong EDR.
  - Least privilege; remove local admin where unnecessary.
  - Patch OS; disable or restrict WDigest; restrict interactive logons.

## Minimal cheat sheet (one-screen flow)
- Pre-checks
  - whoami /all
  - systeminfo | findstr "System Type"
  - reg query HKLM\...\Lsa /v RunAsPPL
  - reg query HKLM\...\Wdigest /v UseLogonCredential
- Prep (lab-only)
  - Verify tool hash: Get-FileHash .\mimikatz.exe -Algorithm SHA256
  - Unblock-File .\mimikatz.exe
  - Run elevated console
- Execute (lab-only; high-level)
  - Open Mimikatz
  - Init privileges
  - Enumerate in-memory logons (LSA)
  - Dump local hashes (SAM/SECURITY/SYSTEM)
  - Optionally parse offline dump
- Post
  - Store outputs in lab folder; analyze offline
  - Clean up tools/artifacts
  - Review detections and enable: RunAsPPL, Credential Guard, WDIGEST=0

## Summary
This video (inferred from the title and module) demonstrates credential dumping on Windows with Mimikatz: prerequisites, where credentials live (LSASS memory, SAM/SECURITY/SYSTEM), and a guided lab run to extract and analyze hashes. It also touches on factors that influence success (admin/SYSTEM rights, architecture, LSA Protection, Credential Guard) and the defensive measures and telemetry to prevent or detect such activity. Specific offensive commands are omitted here for safety; focus on learning the workflow in a lawful lab and on the defensive controls that mitigate this technique (MITRE ATT&CK T1003).