# 03 – Bypassing UAC With UACMe (eJPT)

Note: No transcript was provided. The following notes are inferred conservatively from the filename and the module folder (03-WindowsPrivilegeEscalation). They reflect standard eJPT-style lab workflows for demonstrating UAC behavior and the educational use of UACMe in a controlled environment you own and have permission to test. For safety, the commands below focus on environment enumeration/verification and hardening; method-specific UAC-bypass invocations are intentionally not included. Refer to the official UACMe documentation for lab-only method usage details.

## What the video covers (Introduction / big picture)
- What UAC is: Windows User Account Control limits what a logon session can do by default, even when the user is a local administrator (Medium Integrity Level until consent/elevation).
- What UAC bypass means: moving from Medium Integrity Level (admin but not elevated) to High Integrity Level without showing a prompt. This is not a standard-user-to-admin escalation; it typically requires the user to already be a local admin.
- UACMe overview: a research/education toolset that demonstrates known UAC bypass primitives across Windows versions. Methods are OS/build-specific and often get patched by Microsoft.
- Typical lab goal: verify you’re a local admin at Medium IL, demonstrate an elevation to High IL from a non-elevated context, validate the change, and clean up. Emphasis on responsible, lab-only use.

## Flow (ordered)
1. Confirm current privileges and integrity level (are you a local admin, and are you Medium IL?).
2. Check UAC policy and OS/build (to understand whether any known methods may apply).
3. Prepare a safe test payload (e.g., open an elevated shell that just prints whoami/groups) in a lab VM.
4. Use UACMe in the lab to demonstrate an elevation from Medium IL to High IL.
5. Verify elevation worked (integrity level/groups).
6. Clean up any changes the method may have created (registry/files).
7. Discuss/observe detection and hardening controls.

## Tools highlighted
- UACMe (hfiref0x/UACME) – research tool demonstrating UAC bypass techniques; binaries often named akagi32/akagi64.
- whoami – verify groups, privileges, and integrity level.
- reg, PowerShell registry cmdlets – enumerate UAC settings and revert changes.
- systeminfo, wmic, PowerShell CIM – check OS version/build.
- Process Explorer/Process Hacker (optional) – view integrity levels and token details.
- Event Viewer / wevtutil / Sysmon (optional) – observe process creation, registry ops in lab.

## Typical command walkthrough (detailed, copy-paste friendly)
The following commands are safe, copy-paste friendly, and focus on enumeration, verification, and hardening. For ethical and safety reasons, explicit UAC bypass execution commands are omitted; consult the official UACMe README for lab-only method usage.

- Validate identity, group membership, and privileges:
```cmd
whoami /user
whoami /groups
whoami /priv
```

- Check integrity level (look for “Mandatory Label\Medium” vs “High”):
```cmd
whoami /groups | findstr /I "mandatory"
```

- Confirm you are a local admin (this matters because UAC bypasses typically assume admin group membership already):
```cmd
net localgroup administrators
```

- Get Windows version/build (some methods are version-specific):
```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic os get Caption,Version,BuildNumber /value
```

- Query UAC-related policy settings (registry):
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken
```

- PowerShell equivalents (easier in one shot):
```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' |
  Select-Object EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop, FilterAdministratorToken
```

- Open a non-elevated prompt and confirm Medium IL:
```cmd
whoami /groups | findstr /I "mandatory"
```

- After your lab-only UACMe test, confirm High IL (expected):
```cmd
whoami /groups | findstr /I "mandatory"
```

- Optional: observe process creation in Security log (requires Audit Process Creation enabled via Local Security Policy or GPO):
```cmd
wevtutil qe Security /q:"*[System[(EventID=4688)]]" /f:text /c:5
```

- Optional: inspect integrity with Process Explorer
  - Run procexp.exe, View > Select Columns > Process Image > check “Integrity Level”.
  - Verify the spawned process is High IL after the lab test.

- Cleanup (generic guidance; many UAC bypass methods temporarily modify per-user registry keys):
  - If you modified HKCU or HKCR keys in your lab, revert them. Example stub (do not run blindly; confirm the exact key first):
```cmd
reg delete "HKCU\Software\Classes\<LabTestKeyPath>" /f
```
  - Remove any test files placed during the lab:
```cmd
del /f /q "%Public%\uacme\*"
rmdir /s /q "%Public%\uacme"
```

## Practical tips
- UAC bypass vs PrivEsc: UAC bypass moves you from Medium to High Integrity; it does not turn a standard user into an admin. You typically need to already be in the local Administrators group.
- Version-specific: Many UACMe methods are patched or only apply to certain Windows builds. Always check OS version/build first.
- Integrity matters: Ensure you start from a non-elevated console (Medium IL) to meaningfully demonstrate the change.
- 32-bit vs 64-bit: Use the binary matching the OS architecture. Some methods are architecture-sensitive.
- Visibility: Use whoami and Process Explorer to prove the elevation state before and after.
- Hardening reduces success: “Always notify” prompts (ConsentPromptBehaviorAdmin) and application control (AppLocker/WDAC) can disrupt many methods.
- Hygiene: Always remove lab tools and revert any registry/file changes after testing.
- Source authenticity: Only obtain UACMe from its official repository. Do not trust third-party rehosts.

## Minimal cheat sheet (one-screen flow)
- Check current state:
```cmd
whoami /groups | findstr /I "mandatory"
whoami /groups
whoami /priv
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
```
- Confirm local admin:
```cmd
net localgroup administrators
```
- Lab-only: use UACMe per its README to attempt elevation from Medium to High IL.
- Verify result:
```cmd
whoami /groups | findstr /I "mandatory"
```
- Clean up:
```cmd
reg delete "HKCU\Software\Classes\<LabTestKeyPath>" /f   & rem Replace with actual lab key if used
del /f /q "%Public%\uacme\*" & rmdir /s /q "%Public%\uacme"
```
- Hardening checks (defensive follow-up):
```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' |
  Select EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop
```

## Summary
This module demonstrates the concept of bypassing UAC using UACMe in a lab: confirming you start as a local admin at Medium Integrity Level, using an OS/build-appropriate method to obtain High Integrity without a prompt, and validating the change. It emphasizes the difference between UAC bypass and true privilege escalation, as well as the importance of OS version awareness, cleanup, and defensive configurations. For ethical and safety reasons, these notes avoid method-specific bypass commands; consult UACMe’s official documentation for controlled, authorized lab testing only.