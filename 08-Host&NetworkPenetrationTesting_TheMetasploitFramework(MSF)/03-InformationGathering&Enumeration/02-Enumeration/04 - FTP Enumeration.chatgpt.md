# 04 - FTP Enumeration (eJPT Study Notes)

Note: No transcript was provided. The following is a conservative, exam-focused summary inferred from the filename and typical eJPT enumeration workflows for FTP.

## What the video covers (Introduction / big picture)
- How to identify and enumerate FTP services (port 21/990).
- Verifying anonymous access and harvesting files.
- Using Nmap scripts to gather service info and known issues.
- Practical file retrieval/mirroring and write-permission checks.
- Pivot ideas if FTP is mapped to a web root.
- Optional credential attacks when anonymous is disabled.

## Flow (ordered)
1. Discover FTP with a port scan (21 and possibly 990).
2. Fingerprint the service and run targeted NSE scripts.
3. Try anonymous login; list, search, and download files.
4. Mirror large/recursive directories non-interactively.
5. Check if the server is writable; test put/rename/delete.
6. If FTP is mapped to a web directory, test uploading a simple file and browse it over HTTP.
7. If no anonymous and scope permits, try credentials (small, controlled brute).
8. Document banners, versions, paths, file contents (credentials, notes, backups).

## Tools highlighted
- Nmap (service detection and NSE scripts)
- ftp (built-in CLI client)
- wget and curl (non-interactive downloads)
- lftp (convenient mirroring, passive mode handling)
- netcat (nc) or telnet (banner grab/raw commands)
- Hydra/Medusa (optional credential attacks, authorized environments only)
- searchsploit (research known FTP service vulns)

## Typical command walkthrough (detailed, copy-paste friendly)
Replace TARGET as needed.

```bash
# 0) Setup
export TARGET=10.10.10.10
mkdir -p scans loot

# 1) Baseline scan for FTP
nmap -p 21,990 -sV -sC --reason -oN scans/ftp_baseline_$TARGET.nmap $TARGET

# 2) Focused FTP NSE scripts (no brute by default)
nmap -p21 -sV \
  --script="banner,ftp-anon,ftp-syst,ftp-bounce,ftp-vsftpd-backdoor,ftp-proftpd-backdoor" \
  -oN scans/ftp_nse_$TARGET.nmap $TARGET

# 3) Quick banner grab (optional)
nc -nv $TARGET 21 << 'EOF'
SYST
FEAT
QUIT
EOF

# 4) Try anonymous login interactively
# Username: anonymous   Password: anonymous (or blank)
ftp -inv $TARGET << 'EOF'
user anonymous anonymous
binary
passive
pwd
ls -la
ls -laR
# Download everything visible in current directory (non-recursive)
prompt
mget *
bye
EOF

# 5) Non-interactive recursive mirror with wget
# Use --no-passive-ftp only if passive is failing; default is usually fine.
wget -m -np --user=anonymous --password=anonymous -P loot ftp://$TARGET/

# 6) Lightweight listing with curl (quick check)
curl -s --user anonymous:anonymous ftp://$TARGET/
curl -s --user anonymous:anonymous ftp://$TARGET/some/dir/

# 7) Test writeability (safe write test)
echo "ftp write test $(date)" > /tmp/ftp_test.txt
ftp -inv $TARGET << 'EOF'
user anonymous anonymous
binary
passive
pwd
put /tmp/ftp_test.txt
rename ftp_test.txt ftp_test_renamed.txt
delete ftp_test_renamed.txt
mkdir test_dir
rmdir test_dir
bye
EOF

# 8) If FTP maps to a web root (e.g., /var/www/html), try a web-accessible file
# Only in authorized labs. Example simple file (not a shell) to confirm path:
echo "hello from ftp $(date)" > /tmp/info.txt
ftp -inv $TARGET << 'EOF'
user anonymous anonymous
binary
passive
cd / # adjust if you identified a web-root-like path
put /tmp/info.txt
bye
EOF
# Then check in browser or:
curl -i http://$TARGET/info.txt

# 9) If anonymous fails and scope allows, attempt small, controlled brute force
# (Throttle, small lists; avoid noisy scans in production.)
hydra -L users.txt -P passwords.txt -f -u -t 4 -V $TARGET ftp -o scans/hydra_ftp_$TARGET.txt

# 10) Version research (post-enum)
grep -i -E "ftp|vsftpd|proftpd|pure-ftpd" scans/ftp_baseline_$TARGET.nmap scans/ftp_nse_$TARGET.nmap
# Investigate findings
searchsploit vsftpd
searchsploit proftpd
```

Interactive ftp tips (inside ftp):
- Switch to binary mode before downloading non-text: `binary`
- Disable interactive prompts for mget: `prompt`
- Enable passive mode if connections hang: `passive`
- Raw commands if needed: `quote SYST`, `quote FEAT`

## Practical tips
- Anonymous login: Try both “anonymous” and “ftp” as the username; password often blank or “anonymous”.
- Passive vs active: If listings or transfers hang, toggle `passive` in ftp or try `--no-passive-ftp` in wget.
- Preserve evidence: Mirror first, analyze offline. Don’t modify server state unless needed to test write permissions.
- Look for sensitive files: backups (.bak, .zip), notes, database dumps, config files with creds.
- Hidden files: Use `ls -la` to reveal dotfiles.
- NSE scope: Avoid `ftp-brute` unless permitted; it’s noisy and can lock accounts.
- Known backdoors: vsftpd 2.3.4 and certain ProFTPD backdoors are classic labs; run the specific NSE checks you enabled above.
- Web root pivot: If you can upload to a directory served by HTTP, you may get code execution by uploading a script (only in labs/authorized tests).
- Document paths and permissions: pwd outputs, directory structure, write tests, and file timestamps help later pivoting.

## Minimal cheat sheet (one-screen flow)
1) Detect and script-scan FTP
```bash
export TARGET=10.10.10.10
nmap -p21,990 -sV -sC -oN scans/ftp_$TARGET.nmap $TARGET
nmap -p21 -sV --script="banner,ftp-anon,ftp-syst,ftp-bounce,ftp-vsftpd-backdoor,ftp-proftpd-backdoor" -oN scans/ftp_nse_$TARGET.nmap $TARGET
```
2) Try anonymous; list and grab quickly
```bash
ftp -inv $TARGET << 'EOF'
user anonymous anonymous
binary
passive
ls -laR
prompt
mget *
bye
EOF
```
3) Mirror recursively
```bash
wget -m -np --user=anonymous --password=anonymous -P loot ftp://$TARGET/
```
4) Test write perms
```bash
echo test > /tmp/ftp_test.txt
ftp -inv $TARGET << 'EOF'
user anonymous anonymous
binary
passive
put /tmp/ftp_test.txt
rename ftp_test.txt ftp_test_ok.txt
delete ftp_test_ok.txt
bye
EOF
```
5) Optional creds (authorized)
```bash
hydra -L users.txt -P passwords.txt -f -u -t 4 -V $TARGET ftp
```

## Summary
- Enumerate FTP by identifying the service (21/990), fingerprinting with Nmap, and running focused NSE scripts.
- Test anonymous access immediately; if allowed, harvest files using ftp/wget/curl and look for sensitive data.
- Check for write permissions safely; if writable and mapped to web content, consider web pivots in authorized labs.
- Use passive mode and binary transfers to avoid hangs and corruption.
- Only attempt credential attacks when in scope, and keep them controlled and documented.