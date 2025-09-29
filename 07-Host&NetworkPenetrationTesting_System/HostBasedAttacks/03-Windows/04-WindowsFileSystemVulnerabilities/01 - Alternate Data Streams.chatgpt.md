# 01 - Alternate Data Streams (ADS)

Note: No transcript was provided. The following is a careful summary inferred from the filename and course folder (04-WindowsFileSystemVulnerabilities). Commands and flags are standard for NTFS ADS and commonly shown in eJPT-style demos.

## What the video covers (Introduction / big picture)
- What Alternate Data Streams (ADS) are: a feature of NTFS that lets files hold multiple data streams (the default stream and additional “hidden” streams).
- Why ADS matter for attackers and defenders: stealthy data storage, payload hiding, and simple persistence tricks; how to find and remove them.
- Practical hands-on: creating, listing, reading, writing, and deleting ADS using built-in tools (cmd and PowerShell) and Sysinternals Streams.
- Key constraints: ADS only on NTFS; copying to non-NTFS (e.g., FAT32) strips ADS; some tools don’t preserve or show ADS unless asked.

## Flow (ordered)
1. Confirm the drive is NTFS (ADS only exists on NTFS).
2. Create a normal file, then create a hidden ADS in it.
3. View ADS with built-in methods (dir /r, PowerShell).
4. Read and modify ADS content (text).
5. Store and recover a binary in an ADS (safe method).
6. Enumerate and remove ADS with Sysinternals Streams.
7. Understand Zone.Identifier (Mark-of-the-Web) stream and how to view/remove it.
8. Tips, caveats, and detection notes.

## Tools highlighted
- Built-in (cmd.exe): dir /r, more, copy /b
- PowerShell (Windows PowerShell 5.1+): Get-Content/Set-Content/Remove-Item with -Stream, .NET [IO.File] methods
- Sysinternals: streams.exe (enumerate and delete ADS)
- Optional: fsutil (to verify NTFS)

## Typical command walkthrough (detailed, copy-paste friendly)

### 1) Verify the drive is NTFS
```
fsutil fsinfo volumeinfo C:
```

### 2) Setup a test directory and create a file
```
mkdir C:\Temp\ads-demo
cd /d C:\Temp\ads-demo
echo Visible content > note.txt
type note.txt
```

### 3) Create an ADS and put text in it
- Using cmd (quick demo):
```
echo supersecret > note.txt:hidden
```
- Or use Notepad to edit the stream interactively:
```
notepad note.txt:hidden
```

### 4) List ADS
- Basic vs ADS-aware directory listings:
```
dir note.txt
dir /r note.txt
```
- PowerShell listing:
```
powershell -NoProfile -Command "Get-Item -Path .\note.txt -Stream *"
```

### 5) Read and modify ADS content (text)
- Read with cmd:
```
more < note.txt:hidden
```
- Read with PowerShell:
```
powershell -NoProfile -Command "Get-Content -Path .\note.txt -Stream hidden"
```
- Overwrite/append with PowerShell:
```
powershell -NoProfile -Command "Set-Content -Path .\note.txt -Stream hidden -Value 'new secret'"
powershell -NoProfile -Command "Add-Content -Path .\note.txt -Stream hidden -Value ' (appended)'"
```

### 6) Store a binary inside an ADS (safe method) and verify
- Do not use type/more for binaries; use copy /b or .NET:
```
copy /b C:\Windows\System32\calc.exe note.txt:calc.exe
dir /r note.txt
```

### 7) Extract a binary from an ADS (safe method)
- PowerShell/.NET (works on Windows PowerShell 5.1):
```
powershell -NoProfile -Command "$in=Join-Path $pwd 'note.txt:calc.exe'; $out=Join-Path $pwd 'calc.exe'; [IO.File]::WriteAllBytes($out, [IO.File]::ReadAllBytes($in))"
```
- Then run it (example):
```
.\calc.exe
```

### 8) Enumerate and remove streams with Sysinternals Streams
- Recursively list streams:
```
streams -s -nobanner C:\Temp\ads-demo
```
- Delete streams from a file:
```
streams -d note.txt
```
- Recursively delete from a directory (use with caution):
```
streams -s -d C:\Temp\ads-demo
```

### 9) View and remove Zone.Identifier (Mark-of-the-Web) stream
- If you downloaded a file (e.g., tool.exe), check its MOTW:
```
more < tool.exe:Zone.Identifier
```
- Remove with PowerShell:
```
powershell -NoProfile -Command "Remove-Item -Path .\tool.exe -Stream Zone.Identifier"
```
- Or with Streams:
```
streams -d tool.exe
```

## Practical tips
- ADS only works on NTFS. Moving a file to FAT32/exFAT will drop its ADS. This can be used to strip streams intentionally.
- Not all tools preserve ADS. For example, a simple copy across filesystems or via certain network paths can remove streams. Robocopy can preserve ADS if used with appropriate flags (e.g., /COPYALL).
- dir by itself won’t show ADS; use dir /r or dedicated tools.
- For text streams, more < file:stream is reliable. Avoid using type for streams; it’s inconsistent and can fail.
- For binaries, never use more/type to embed or extract—use copy /b for writing and PowerShell/.NET for reading/writing byte-accurate data.
- Executing binaries directly from ADS can be inconsistent on modern Windows due to security controls. Safer approach: extract to a normal file, then run.
- Zone.Identifier (MOTW) is a common ADS set by browsers; removing it can change how Windows and AV treat the file (SmartScreen warnings). Don’t remove MOTW in production without policy approval.
- Blue-team note: Sysmon Event ID 15 (File stream created) can detect ADS creation; dir /r and streams.exe are quick triage tools.

## Minimal cheat sheet (one-screen flow)
```
:: Check NTFS
fsutil fsinfo volumeinfo C:

:: Setup
mkdir C:\Temp\ads-demo & cd /d C:\Temp\ads-demo
echo Visible > note.txt

:: Create + list + read ADS (text)
echo secret > note.txt:hidden
dir /r note.txt
more < note.txt:hidden

:: PowerShell ADS ops
powershell -NoProfile -Command "Get-Item .\note.txt -Stream *"
powershell -NoProfile -Command "Get-Content .\note.txt -Stream hidden"
powershell -NoProfile -Command "Remove-Item .\note.txt -Stream hidden"

:: Binary in ADS (store + extract)
copy /b C:\Windows\System32\calc.exe note.txt:calc.exe
powershell -NoProfile -Command "$in='note.txt:calc.exe'; $out='calc.exe'; [IO.File]::WriteAllBytes($out,[IO.File]::ReadAllBytes($in))"

:: Sysinternals Streams (enumerate/delete)
streams -s -nobanner .
streams -d note.txt

:: Zone.Identifier (view/remove)
more < tool.exe:Zone.Identifier
powershell -NoProfile -Command "Remove-Item .\tool.exe -Stream Zone.Identifier"
```

## Summary
- NTFS Alternate Data Streams allow data to be hidden inside a file without changing its main content’s appearance. Attackers can stash config, scripts, or binaries; defenders must know how to find and remove them.
- Key operations: create (echo/notepad/copy /b), list (dir /r, Streams, PowerShell), read/write (more, Get-Content/Set-Content), delete (Remove-Item -Stream, Streams -d).
- Always handle binaries with byte-accurate methods, and remember ADS are lost when leaving NTFS. Streams.exe and PowerShell are your go-to tools for discovery and cleanup.