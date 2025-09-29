# 13 – SSH Enumeration (eJPT)

Note: No transcript was provided. The following is a conservative, eJPT-focused summary inferred from the filename and the Service Enumeration module context.

## What the video covers (Introduction / big picture)
- How to enumerate SSH services discovered during scanning (typically TCP/22 or non-standard ports like 2222).
- Fingerprinting SSH versions, algorithms, host keys, and authentication methods.
- Identifying weak/legacy configurations and potential attack paths.
- Safe credential testing and brute-force strategy considerations.
- Tooling: Nmap NSE scripts, netcat, ssh/ssh-keyscan/ssh-audit, Hydra/Ncrack, Metasploit.

## Flow (ordered)
1. Confirm discovery: Identify SSH ports from your scan (e.g., Nmap).
2. Grab the banner: Confirm protocol/version quickly (netcat/ssh -v).
3. Enumerate with Nmap NSE: host keys, algorithms, SSHv1 support, auth methods for a target user.
4. Collect host key fingerprints (ssh-keyscan) and assess crypto (ssh-audit).
5. Check for known issues: map version to potential CVEs and weak algorithms.
6. Probe authentication pathways: which methods are allowed per user; is root login allowed?
7. Credential testing: light/default creds; then controlled brute force (Hydra/Ncrack/Metasploit) if permitted.
8. Handle legacy servers: override ciphers/KEX/host key algorithms to establish a connection.
9. On success: basic post-login checks (id, uname -a) and prepare for further enumeration.

## Tools highlighted
- Nmap (service/version detection + NSE: ssh2-enum-algos, ssh-hostkey, ssh-auth-methods, sshv1, ssh-brute if allowed)
- netcat (nc) for banner grabbing
- OpenSSH client: ssh, ssh-keyscan, ssh-keygen
- ssh-audit (third-party crypto/feature auditor)
- Hydra, Ncrack, Medusa (SSH login brute force)
- Metasploit auxiliary modules (ssh_version, ssh_enumusers, ssh_login)
- searchsploit (to map versions to public exploits)

## Typical command walkthrough (detailed, copy-paste friendly)
Set up some variables:
```bash
export TARGET=10.10.10.10
export PORT=22
export USERS=users.txt
export PASSWORDS=passwords.txt
mkdir -p scans
```

1) Quick service/version check and banner
```bash
nmap -sV -p $PORT --reason -oN scans/ssh_sv_$TARGET.txt $TARGET
nc -nv $TARGET $PORT
# Or verbose SSH client banner/debug
ssh -v -p $PORT invaliduser@$TARGET 2>&1 | head -n 15
```

2) Nmap NSE enumeration (algorithms, hostkeys, auth methods, SSHv1)
```bash
nmap -sV -p $PORT \
  --script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,sshv1 \
  --script-args="ssh.user=root" \
  -oA scans/ssh_enum_$TARGET $TARGET

# Optional: run all ssh-* scripts (may include intrusive ones like ssh-brute)
# nmap -sV -p $PORT --script "ssh-*" -oA scans/ssh_all_$TARGET $TARGET
```

3) Host key fingerprint collection
```bash
# Collect different key types; store for later integrity/MITM checks
ssh-keyscan -p $PORT -t rsa,ecdsa,ed25519 $TARGET 2>/dev/null | tee scans/ssh_known_hosts_$TARGET

# Print readable fingerprints
ssh-keyscan -p $PORT -t rsa,ecdsa,ed25519 $TARGET 2>/dev/null | ssh-keygen -lf - | tee scans/ssh_fingerprints_$TARGET.txt
```

4) Crypto/feature audit (third-party)
```bash
# If not installed: pipx install ssh-audit  (or pip3 install ssh-audit)
ssh-audit $TARGET:$PORT | tee scans/ssh_audit_$TARGET.txt
```

5) Check version for known vulns/notes
```bash
# Example: replace "OpenSSH 7.2" with the version you saw
searchsploit "OpenSSH 7.2"
```

6) Light/default credential testing (non-intrusive)
```bash
# Force password-only to avoid key spam/timeouts
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o StrictHostKeyChecking=no -p $PORT user@$TARGET

# One-shot test with known password (automation)
# sudo apt install -y sshpass
sshpass -p 'Password123!' ssh -o StrictHostKeyChecking=no -p $PORT user@$TARGET "id"
```

7) Controlled brute-force (if allowed)
- Hydra
```bash
# Try per-user list and password list; stop on first success; verbose
hydra -L $USERS -P $PASSWORDS -s $PORT -u -f -I -V -t 4 -o scans/hydra_ssh_$TARGET.txt ssh://$TARGET

# Try null/same/reversed username as password (fast heuristics)
hydra -l admin -P /usr/share/wordlists/rockyou.txt -s $PORT -e nsr -f -t 4 ssh://$TARGET
```
- Ncrack
```bash
ncrack -p ssh:$PORT -U $USERS -P $PASSWORDS -T 4 --connection-limit 1 -v $TARGET \
  -oN scans/ncrack_ssh_$TARGET.txt
```
- Metasploit (version, enum users, brute)
```bash
msfconsole -q -x "
use auxiliary/scanner/ssh/ssh_version; set RHOSTS $TARGET; set RPORT $PORT; run;
use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS $TARGET; set USER_FILE $USERS; set RPORT $PORT; run;
use auxiliary/scanner/ssh/ssh_login; set RHOSTS $TARGET; set RPORT $PORT; set USER_FILE $USERS; set PASS_FILE $PASSWORDS; set STOP_ON_SUCCESS true; run; exit"
```

8) Connecting to legacy/locked-down servers (override algos)
```bash
# Older/legacy servers (only if enumeration showed these algos)
ssh -p $PORT \
  -oKexAlgorithms=+diffie-hellman-group1-sha1 \
  -oCiphers=+aes128-cbc \
  -oHostKeyAlgorithms=+ssh-dss \
  user@$TARGET
```

9) On successful login (quick post-checks)
```bash
id; whoami; uname -a; hostname; last -n 3; w
```

## Practical tips
- Always start passive/light: banner, NSE algo/hostkey/auth-methods before brute forcing.
- Rate limiting and account lockouts: keep low thread counts (e.g., -t 4), respect scope and rules of engagement.
- For consistent automation, avoid host key prompts: -o StrictHostKeyChecking=no.
- Avoid “too many authentication failures”: -o IdentitiesOnly=yes or disable key auth: -o PubkeyAuthentication=no.
- Force password auth if needed: -o PreferredAuthentications=password -o KbdInteractiveAuthentication=no.
- Use ssh -vvv to troubleshoot connection/auth negotiation issues.
- If root login is disabled, focus on unprivileged users first; check ssh-auth-methods output for allowed methods per user.
- Track host key fingerprints (ssh-keyscan + ssh-keygen -lf) to detect changes or MITM during longer engagements.
- If Nmap shows SSHv1 support or weak ciphers/KEX, that’s a finding by itself (reportable even without creds).
- Non-standard ports (e.g., 2222/22022) often host alternate SSH daemons; enumerate them separately.

## Minimal cheat sheet (one-screen flow)
```bash
# Identify SSH
nmap -sV -p 22,2222 --reason 10.10.10.10

# Banner + debug
nc -nv 10.10.10.10 22
ssh -v -p 22 invalid@10.10.10.10 | head

# NSE enum (algos, hostkeys, auth, v1)
nmap -sV -p 22 --script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,sshv1 \
  --script-args="ssh.user=root" 10.10.10.10

# Host key fingerprints
ssh-keyscan -p 22 -t rsa,ecdsa,ed25519 10.10.10.10 | ssh-keygen -lf -

# Crypto/feature audit
ssh-audit 10.10.10.10:22

# Quick default creds test
ssh -o StrictHostKeyChecking=no -o PubkeyAuthentication=no -p 22 user@10.10.10.10

# Brute (if allowed)
hydra -L users.txt -P passwords.txt -s 22 -u -f -t 4 ssh://10.10.10.10

# Legacy override connect
ssh -p 22 -oKexAlgorithms=+diffie-hellman-group1-sha1 -oCiphers=+aes128-cbc user@10.10.10.10
```

## Summary
- SSH enumeration centers on confirming the service, extracting version/banner, enumerating cryptographic algorithms and host keys, and determining allowed authentication methods.
- Use Nmap NSE scripts (ssh2-enum-algos, ssh-hostkey, ssh-auth-methods, sshv1), simple banner grabs, and ssh-audit to build a profile of the target SSH service.
- Only after collecting this intel should you test credentials, starting with low-friction checks and moving to controlled brute force if permitted.
- Be prepared to handle legacy servers by overriding algorithms, and always document host key fingerprints and weak configurations as findings.