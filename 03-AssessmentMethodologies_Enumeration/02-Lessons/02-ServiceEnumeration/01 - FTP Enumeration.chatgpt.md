# 01 - FTP Enumeration (eJPT) — Study Notes

Note: No transcript was provided. The outline and commands below are inferred conservatively from the filename and typical eJPT FTP enumeration content.

## What the video covers (Introduction / big picture)
- Identifying and profiling FTP services (FTP on 21, FTPS on 990, and explicit TLS on 21).
- Enumerating banners, capabilities, and server OS/version.
- Checking for anonymous access, listing and mirroring files.
- Testing write/upload permissions safely.
- Running targeted Nmap NSE scripts for FTP.
- Credential attacks (Hydra/Nmap ftp-brute) with caution.
- Spotting classic vulnerable versions (e.g., vsftpd 2.3.4, ProFTPD 1.3.3c) and checking TLS.
- Practical workflow to gather loot from misconfigured FTP shares.

## Flow (ordered)
1. Confirm the service and version on the target (port 21/990).
2. Banner grab and feature discovery (SYST/FEAT).
3. Run FTP-focused Nmap scripts (anon, syst, vsftpd/proftpd backdoors, bounce).
4. Try anonymous login; enumerate and download content.
5. Mirror the share for offline analysis; check for sensitive files.
6. Test for write access in a non-destructive way (mkdir/put/delete).
7. If credentials suspected, attempt a careful brute force (Hydra or NSE ftp-brute).
8. Check for TLS (explicit on 21 or implicit on 990); enumerate ciphers/cert.
9. Assess version-specific issues; cross-check with Searchsploit.
10. Correlate findings with other services (e.g., web root exposed via FTP).

## Tools highlighted
- Nmap (+ NSE scripts: ftp-anon, ftp-syst, ftp-bounce, ftp-vsftpd-backdoor, ftp-proftpd-backdoor, ftp-brute)
- Netcat or Telnet (banner/capabilities)
- ftp client (ftp), lftp (scriptable), curl/wget (quick listing/mirroring)
- Hydra (credential attacks)
- OpenSSL (TLS/FTPS checks)
- Searchsploit (version-based vulns)

## Typical command walkthrough (detailed, copy-paste friendly)

Set a target variable for convenience:
```
TARGET=10.10.10.10
```

1) Quick service/version check and default scripts:
```
nmap -p21 -sV -sC -oN nmap_ftp_$TARGET.txt $TARGET
```

2) Focused FTP NSE enumeration:
```
nmap -p21 -sV --script=ftp-anon,ftp-syst,ftp-bounce,ftp-vsftpd-backdoor,ftp-proftpd-backdoor -oN nmap_ftp_nse_$TARGET.txt $TARGET
```

3) Banner grab and capability probing (SYST/FEAT/HELP):
```
nc -nv $TARGET 21 << 'EOF'
SYST
FEAT
HELP
QUIT
EOF
```
Alternative:
```
printf "SYST\r\nFEAT\r\nQUIT\r\n" | nc -nv $TARGET 21
```

4) Try anonymous login (interactive):
```
ftp $TARGET
# When prompted:
# Name: anonymous
# Password: anonymous (or leave blank)
# Then inside: pwd; ls -la; cd pub; ls -la; get filename; bye
```

Non-interactive listing with curl:
```
curl -s --user anonymous:anonymous "ftp://$TARGET/" | sed -n '1,200p'
```

5) Mirror anonymous share for offline analysis (safe, read-only):
```
mkdir -p loot_$TARGET && cd loot_$TARGET
wget -m -nH --cut-dirs=0 --ftp-user=anonymous --ftp-password=anonymous ftp://$TARGET/
cd -
```
If directory listing fails (firewall/NAT), try active mode:
```
wget --no-passive-ftp -m -nH --ftp-user=anonymous --ftp-password=anonymous ftp://$TARGET/
```
Or use lftp for robust listing:
```
lftp -u anonymous,anonymous $TARGET -e "set ftp:passive-mode on; cls -lR; bye"
```

6) Test write access non-destructively (create/put/delete in a temp folder):
```
echo "ftp_write_test $(date)" > test.txt
lftp -u anonymous,anonymous "$TARGET" -e "set ftp:passive-mode on; mkdir .writetest 2>/dev/null; cd .writetest || true; put test.txt; ls -l; rm -f test.txt; cd ..; rmdir .writetest 2>/dev/null; bye"
rm -f test.txt
```
Interactive alternative:
```
ftp -inv $TARGET << 'EOF'
user anonymous anonymous
pwd
ls -la
mkdir .writetest
cd .writetest
put /etc/hostname
delete hostname
cd ..
rmdir .writetest
bye
EOF
```
Note: Replace /etc/hostname with a harmless small file if needed.

7) Credential brute force (lab-safe; beware of lockouts):
Prepare wordlists:
```
# Ensure rockyou is decompressed if using Kali
[ -f /usr/share/wordlists/rockyou.txt ] || sudo gzip -d /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
```
Hydra examples:
```
# Single user, large password list
hydra -l ftpuser -P /usr/share/wordlists/rockyou.txt -u -t 4 -f -o hydra_ftp_$TARGET.txt ftp://$TARGET

# User and password lists
hydra -L users.txt -P passwords.txt -u -t 4 -f -o hydra_ftp_$TARGET.txt ftp://$TARGET
```
Nmap ftp-brute alternative:
```
nmap -p21 --script ftp-brute --script-args userdb=users.txt,passdb=passwords.txt,ftp-brute.timeout=8s -oN nmap_ftp_brute_$TARGET.txt $TARGET
```

8) TLS/FTPS checks (explicit TLS on 21; implicit on 990):
```
nmap -p21,990 --script ssl-cert,ssl-enum-ciphers -oN nmap_ftp_tls_$TARGET.txt $TARGET
```
Manual STARTTLS probe:
```
openssl s_client -starttls ftp -connect $TARGET:21 -crlf </dev/null | sed -n '1,40p'
```
Implicit FTPS on 990:
```
openssl s_client -connect $TARGET:990 -crlf </dev/null | sed -n '1,40p'
```
List via curl requiring TLS (ignore cert issues for testing):
```
curl -k --ssl-reqd --user anonymous:anonymous "ftp://$TARGET/"
```

9) Version-based quick checks:
From your Nmap output, if you see for example:
- vsftpd 2.3.4:
```
searchsploit vsftpd 2.3.4
```
- ProFTPD 1.3.3c:
```
searchsploit proftpd 1.3.3c
```

10) Post-download triage (spot secrets quickly):
```
cd loot_$TARGET
find . -type f -iname "*.zip" -o -iname "*.bak" -o -iname "*.sql" -o -iname "*.conf" -o -iname "*config*" -o -iname "*backup*" -o -iname "*.txt"
grep -RiEn "password|passwd|secret|key|token|DB_|DB_PASS|user" .
file *
strings -n 8 suspicious_binary | head
```

## Practical tips
- Toggle passive/active mode if directory listings or transfers hang (firewalls/NAT often break active mode).
- Always try anonymous:anonymous and anonymous with blank password; look for common folders like pub, upload, backup, www, htdocs, conf.
- Be minimally invasive when checking write access: create a temporary folder, drop a tiny test file, and clean up.
- Use -sC with Nmap for quick wins, then pivot to specific ftp-* scripts.
- Save outputs (-oN) and mirror directories for offline grep and tooling; don’t rely on interactive output.
- Correlate FTP contents with web apps (e.g., wp-config.php, .env, database dumps) if FTP root maps to a web root.
- Limit brute-force speed and set stop-on-first-found (-f) to avoid triggering defenses; prefer curated userlists.
- If FTPS is enforced, use lftp or curl with TLS flags; some plain ftp clients will fail silently.
- Note classic tells:
  - 220 (vsFTPd 2.3.4) … possible backdoor indicator (verify with NSE).
  - 220 ProFTPD 1.3.3c … historical backdoor build (NSE: ftp-proftpd-backdoor).
  - 220 Microsoft FTP Service … often IIS; check for NT-style paths and permission quirks.

## Minimal cheat sheet (one-screen flow)
```
TARGET=10.10.10.10

# Quick enum
nmap -p21 -sV -sC -oN nmap_ftp_$TARGET.txt $TARGET
nmap -p21 -sV --script=ftp-anon,ftp-syst,ftp-bounce,ftp-vsftpd-backdoor,ftp-proftpd-backdoor -oN nmap_ftp_nse_$TARGET.txt $TARGET

# Banner & features
printf "SYST\r\nFEAT\r\nQUIT\r\n" | nc -nv $TARGET 21

# Anonymous check + mirror
curl -s --user anonymous:anonymous "ftp://$TARGET/" | head
mkdir -p loot_$TARGET && cd loot_$TARGET
wget -m -nH --ftp-user=anonymous --ftp-password=anonymous ftp://$TARGET/
cd -

# Safe write test
echo test > test.txt
lftp -u anonymous,anonymous "$TARGET" -e "mkdir .writetest 2>/dev/null; cd .writetest || true; put test.txt; ls -l; rm -f test.txt; cd ..; rmdir .writetest 2>/dev/null; bye"
rm -f test.txt

# Brute force (careful)
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -u -t 4 -f -o hydra_ftp_$TARGET.txt ftp://$TARGET

# TLS/FTPS
nmap -p21,990 --script ssl-cert,ssl-enum-ciphers -oN nmap_ftp_tls_$TARGET.txt $TARGET
openssl s_client -starttls ftp -connect $TARGET:21 -crlf </dev/null | head
```

## Summary
- Enumerate FTP with Nmap to identify versions, capabilities, and low-hanging misconfigurations (anonymous access).
- Use ftp/lftp/curl/wget to list and mirror content, then triage for credentials and backups.
- Test write safely; writable FTP often leads to impactful findings.
- If credentials are needed, perform cautious brute forcing with Hydra or NSE.
- Check TLS status and version-specific issues (vsftpd 2.3.4, ProFTPD 1.3.3c) and verify with NSE and Searchsploit.
- The overall goal is to extract as much information as possible from FTP with minimal noise and risk, then leverage it in subsequent phases.