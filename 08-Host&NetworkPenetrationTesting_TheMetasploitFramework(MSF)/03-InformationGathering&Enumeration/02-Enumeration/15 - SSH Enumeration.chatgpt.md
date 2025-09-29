# 15 - SSH Enumeration (eJPT)

Note: The transcript wasn’t provided. The following is a conservative, practical summary based on the filename and typical eJPT SSH enumeration workflow in an “Enumeration” module.

## What the video covers (Introduction / big picture)
- Recognizing and enumerating SSH (typically TCP/22 but also non-standard ports) during host/service enumeration.
- Extracting SSH server version, banner, algorithms, host keys, and supported authentication methods.
- Validating whether insecure SSHv1 is supported.
- Determining whether password-based auth is available, and if controlled credential attacks are in-scope.
- Using standard tools (nmap, netcat, ssh, ssh-audit, hydra/medusa/patator, Metasploit) to build an actionable picture before exploitation.

## Flow (ordered)
1. Discover SSH and confirm the service/port.
2. Grab the server banner and version.
3. Enumerate SSH algorithms, host keys, and check SSHv1 support with Nmap NSE/ssh-audit.
4. Identify allowed authentication methods per user.
5. Optionally check for user enumeration vectors (only if in-scope).
6. Research version for known issues (post-enum).
7. If permitted, conduct low-and-slow credential attempts.
8. Record host key fingerprints and notes; prepare next steps (SFTP/SSH post-auth enumeration if creds found).

## Tools highlighted
- Nmap (service/version detection; NSE: ssh2-enum-algos, ssh-hostkey, sshv1, ssh-auth-methods)
- Netcat (banner grab)
- OpenSSH client (ssh, sftp; verbose/debug; auth method testing)
- ssh-audit (algorithm and configuration assessment)
- Hydra / Medusa / Patator (controlled password attempts, if allowed)
- Metasploit auxiliary scanners (ssh_version, ssh_enumusers, ssh_login)
- ssh-keyscan and ssh-keygen (host key capture and fingerprinting)

## Typical command walkthrough (detailed, copy-paste friendly)

Set target variables first:
```bash
export TARGET=10.10.10.10
export PORT=22
export USER=admin
```

1) Fast discovery and service/version detection
```bash
# Full TCP scan to catch non-standard SSH (e.g., 2222, 22022)
nmap -p- --min-rate 2000 -T4 -v -oN nmap_allports.txt $TARGET

# Focus on SSH port(s) found (replace $PORT if different)
nmap -sC -sV -p $PORT -oN nmap_ssh_default.txt $TARGET
```

2) Grab the banner (server usually sends it first)
```bash
# Simple banner grab
nc -nv $TARGET $PORT

# Or with Nmap’s banner script
nmap -sV --script=banner -p $PORT -oN nmap_ssh_banner.txt $TARGET
```

3) Enumerate algorithms, host keys, and SSHv1 support
```bash
# Enumerate key exchange, ciphers, MACs
nmap -p $PORT --script ssh2-enum-algos -oN nmap_ssh_algos.txt $TARGET

# Fetch and fingerprint host keys
nmap -p $PORT --script ssh-hostkey -oN nmap_ssh_hostkey.txt $TARGET

# Check if obsolete SSHv1 is supported
nmap -p $PORT --script sshv1 -oN nmap_ssh_v1check.txt $TARGET
```

4) Identify allowed authentication methods for a specific user
```bash
# Nmap NSE: list auth methods for a given username
nmap -p $PORT --script ssh-auth-methods --script-args "ssh.user=$USER" -oN nmap_ssh_authmethods.txt $TARGET

# Using ssh client to see methods in the denial message
ssh -v -o PreferredAuthentications=none -o PubkeyAuthentication=no -o KbdInteractiveAuthentication=no \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    $USER@$TARGET
# Look for: "Permission denied (publickey,password,keyboard-interactive)."
```

5) Audit server algorithms and config posture (quick high-signal)
```bash
# Install (one-time)
# pipx install ssh-audit  OR  pip3 install ssh-audit
ssh-audit $TARGET:$PORT | tee ssh_audit_$TARGET.txt
```

6) Capture host keys separately (for tracking/fingerprints)
```bash
ssh-keyscan -p $PORT -t rsa,ecdsa,ed25519 $TARGET | tee ssh_hostkeys_$TARGET.txt
# Fingerprint any key line (example)
ssh-keyscan -p $PORT $TARGET | ssh-keygen -lf -
```

7) Optional: research version (post-enum)
```bash
# If you have a banner like "OpenSSH_7.2p2 Ubuntu ..."
searchsploit openssh 7.2
```

8) If in-scope, controlled password attempts (slow and respectful)
```bash
# Hydra (single user, wordlist)
hydra -l $USER -P /usr/share/wordlists/rockyou.txt -s $PORT -t 4 -f -V ssh://$TARGET -o hydra_ssh_$TARGET.txt

# Hydra (user and pass lists)
hydra -L users.txt -P passwords.txt -s $PORT -t 4 -F -V ssh://$TARGET -o hydra_ssh_$TARGET.txt

# Medusa
medusa -h $TARGET -n $PORT -U users.txt -P passwords.txt -M ssh -O medusa_ssh_$TARGET.txt

# Patator (fine-grained control; throttle to avoid lockouts)
patator ssh_login host=$TARGET port=$PORT user=FILE0 0=users.txt password=FILE1 1=passwords.txt \
  -x ignore:mesg='Authentication failed.' --rate-limit 2
```

9) Troubleshooting connections to legacy servers (only if needed)
```bash
# Force older algorithms/ciphers to talk to legacy targets
ssh -oKexAlgorithms=+diffie-hellman-group14-sha1 -oCiphers=aes128-cbc \
    -oHostKeyAlgorithms=+ssh-rsa $USER@$TARGET -p $PORT
```

10) Metasploit equivalents (optional)
```bash
msfconsole
use auxiliary/scanner/ssh/ssh_version
set RHOSTS $TARGET
set RPORT $PORT
run

use auxiliary/scanner/ssh/ssh_enumusers
set RHOSTS $TARGET
set USER_FILE users.txt
run

use auxiliary/scanner/ssh/ssh_login
set RHOSTS $TARGET
set RPORT $PORT
set USER_FILE users.txt
set PASS_FILE passwords.txt
set VERBOSE true
run
```

## Practical tips
- Scan all ports first; SSH often lives on 2222, 22022, 2022, etc.
- Record the exact banner; it can leak OS/distribution hints (e.g., Ubuntu, FreeBSD).
- Use ssh-audit early to quickly judge crypto posture and potential legacy weaknesses.
- Check allowed auth methods before any brute attempt; don’t waste time if only publickey is allowed.
- Throttle and keep concurrency low; respect account lockout policies and engagement scope.
- Try context-aware defaults only if in-scope (e.g., pi:raspberry, ubnt:ubnt, vagrant:vagrant, ubuntu:ubuntu).
- If you find credentials, test SFTP too for file access: sftp -P $PORT $USER@$TARGET
- Avoid polluting known_hosts during testing: use -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no
- Note host key fingerprints for later sessions and to detect man-in-the-middle changes.

## Minimal cheat sheet (one-screen flow)
```bash
export TARGET=10.10.10.10; export PORT=22; export USER=admin

# Discover and confirm
nmap -p- --min-rate 2000 -T4 -v -oN nmap_all.txt $TARGET
nmap -sC -sV -p $PORT -oN nmap_ssh_default.txt $TARGET

# Banner & version
nc -nv $TARGET $PORT
nmap -sV --script=banner -p $PORT -oN nmap_ssh_banner.txt $TARGET

# Algorithms / keys / SSHv1
nmap -p $PORT --script ssh2-enum-algos -oN nmap_ssh_algos.txt $TARGET
nmap -p $PORT --script ssh-hostkey -oN nmap_ssh_hostkey.txt $TARGET
nmap -p $PORT --script sshv1 -oN nmap_ssh_v1check.txt $TARGET

# Auth methods for a user
nmap -p $PORT --script ssh-auth-methods --script-args "ssh.user=$USER" -oN nmap_ssh_auth.txt $TARGET
ssh -v -o PreferredAuthentications=none -o PubkeyAuthentication=no -o KbdInteractiveAuthentication=no \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $USER@$TARGET

# SSH audit
ssh-audit $TARGET:$PORT | tee ssh_audit_$TARGET.txt

# Host keys & fingerprints
ssh-keyscan -p $PORT -t rsa,ecdsa,ed25519 $TARGET | tee ssh_hostkeys_$TARGET.txt
ssh-keyscan -p $PORT $TARGET | ssh-keygen -lf -

# Optional cred attempts (scope-permitting)
hydra -l $USER -P /usr/share/wordlists/rockyou.txt -s $PORT -t 4 -f -V ssh://$TARGET -o hydra_ssh_$TARGET.txt
```

## Summary
- Enumerate SSH methodically: confirm the service, grab the banner, enumerate algorithms and host keys, and check SSHv1.
- Determine allowed authentication methods per user before attempting any credentials.
- Use ssh-audit for quick crypto and configuration insights.
- If in-scope, perform cautious, throttled credential attempts; prefer informed guesses based on the environment.
- Document host key fingerprints and service details to guide exploitation and maintain session integrity.