# What the video covers (Introduction / big picture)
Note: The transcript for “16 - SMTP Enumeration.mp4” is not provided. The following is a conservative, eJPT-aligned summary based on the filename and typical Service Enumeration content.

This video focuses on enumerating Simple Mail Transfer Protocol (SMTP) services during a penetration test. You learn how to:
- Identify SMTP services and versions on common ports (25/465/587).
- Grab SMTP banners and list supported extensions (e.g., VRFY, EXPN, STARTTLS, AUTH).
- Enumerate valid users via VRFY/EXPN/RCPT techniques and automation tools.
- Check for open relay misconfigurations.
- Probe TLS and authentication safely; optionally test SMTP auth if permitted.

# Flow (ordered)
1. Discover SMTP ports and fingerprint the service (nmap).
2. Banner grab and list supported SMTP extensions (EHLO).
3. Check TLS (STARTTLS on 25/587 and direct TLS on 465).
4. Determine local domains accepted by the server (banner, MX records, nmap scripts).
5. Enumerate users:
   - Manual VRFY/EXPN/RCPT checks.
   - Automated with smtp-user-enum and nmap NSE.
6. Test for open relay (nmap NSE, swaks).
7. Optionally attempt SMTP AUTH brute-force/spray (only if allowed).
8. Capture findings and pivot (valid users → other services).

# Tools highlighted
- nmap + NSE: Service/version detection and SMTP scripts (smtp-commands, smtp-open-relay, smtp-enum-users, smtp-ntlm-info).
- netcat/telnet: Manual banner grabbing, VRFY/EXPN/RCPT.
- openssl s_client: STARTTLS/direct TLS checks on SMTP.
- smtp-user-enum: Automated VRFY/EXPN/RCPT user enumeration.
- swaks (Swiss Army Knife for SMTP): Open relay and workflow tests.
- Metasploit: smtp_version, smtp_enum, smtp_relay modules.
- Hydra/Patator: Optional SMTP AUTH password attacks (exercise caution).
- wordlists: /usr/share/seclists/Usernames/*, custom lists.

# Typical command walkthrough (detailed, copy-paste friendly)
Replace TARGET, DOMAIN, and file paths as appropriate.

Discover and fingerprint
```
# Fast port check for SMTP
nmap -p 25,465,587 -sV -Pn -oA scans/smtp-quick TARGET

# Deeper enumeration with SMTP NSE
nmap -p25,465,587 -sV -sC -Pn \
  --script smtp-commands,smtp-open-relay,smtp-enum-users,smtp-ntlm-info \
  -oA scans/smtp-deep TARGET
```

Manual banner + extensions (EHLO)
```
# Plaintext on 25 (banner grab + EHLO)
printf "EHLO pentest.example\r\nQUIT\r\n" | nc -nv TARGET 25

# STARTTLS on 25 then EHLO
openssl s_client -starttls smtp -connect TARGET:25 -crlf -quiet
# then type:
# EHLO pentest.example
# QUIT

# Direct TLS on 465
openssl s_client -connect TARGET:465 -crlf -quiet
# then type:
# EHLO pentest.example
# QUIT
```

Find an accepted domain
```
# From banner (look for 220 mail.DOMAIN ...), or:
# If you suspect an internet-facing domain:
dig +short mx DOMAIN
# Or reverse lookup to hint at org naming:
dig -x TARGET +short
```

Manual user probes (VRFY/RCPT)
```
# VRFY a single user (if VRFY supported)
printf "EHLO pentest\r\nVRFY root\r\nVRFY administrator\r\nQUIT\r\n" | nc -nv TARGET 25

# RCPT TO probe (often works even if VRFY disabled). You need a local accepted domain.
# Replace LOCALDOMAIN with the recipient domain the server accepts (e.g., example.local).
printf "EHLO pentest\r\nMAIL FROM:<test@external.tld>\r\nRCPT TO:<root@LOCALDOMAIN>\r\nQUIT\r\n" | nc -nv TARGET 25
```

Automated user enumeration
```
# Using smtp-user-enum (VRFY mode)
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t TARGET

# Using smtp-user-enum (RCPT mode) - more likely to work; needs domain
smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -D LOCALDOMAIN -t TARGET

# nmap NSE user enumeration (RCPT based)
nmap -p25 --script smtp-enum-users --script-args smtp-enum-users.domain=LOCALDOMAIN -Pn -oN scans/smtp-enum-nmap.txt TARGET
```

Open relay testing (should be closed)
```
# nmap open relay test
nmap -p25 --script smtp-open-relay -Pn -oN scans/smtp-open-relay.txt TARGET

# swaks test: try to relay from and to external domains (server should reject RCPT)
swaks --server TARGET --from external1@example.net --to external2@example.org --quit-after RCPT

# If server accepts (250) RCPT for external2@example.org without auth, likely open relay.
```

SMTP AUTH checks (optional; only with permission)
```
# Check which AUTH mechanisms are advertised after EHLO
printf "EHLO pentest\r\nQUIT\r\n" | nc -nv TARGET 25
# Look for: 250-AUTH PLAIN LOGIN CRAM-MD5 ...

# Hydra (cleartext SMTP on 25 within lab)
hydra -L users.txt -P passwords.txt -f -vV TARGET smtp

# Hydra (SSL/TLS-wrapped on 465)
hydra -L users.txt -P passwords.txt -s 465 -S -f -vV TARGET smtp

# Patator for STARTTLS on 587 (supports STARTTLS)
patator smtp_login host=TARGET port=587 tls=STARTTLS user=FILE0 password=FILE1 0=users.txt 1=passwords.txt \
  -x ignore:code=535,534 -x ignore:mesg='authentication failed'
```

Metasploit (optional)
```
msfconsole -q
use auxiliary/scanner/smtp/smtp_version
set RHOSTS TARGET
run

use auxiliary/scanner/smtp/smtp_enum
set RHOSTS TARGET
set USER_FILE /usr/share/seclists/Usernames/top-usernames-shortlist.txt
# Optional if using RCPT mode:
# set DOMAIN LOCALDOMAIN
run

use auxiliary/scanner/smtp/smtp_relay
set RHOSTS TARGET
# Defaults attempt external-to-external relay; adjust as needed
run
```

# Practical tips
- Identify the right domain: RCPT-based enumeration requires a domain the server considers local. Derive it from the 220 banner, MX records, nmap smtp-commands output, or org naming.
- Interpret SMTP responses:
  - 250: OK/accepted (e.g., VRFY success or RCPT accepted).
  - 252: “Cannot VRFY user, but will accept message” (user enumeration blocked).
  - 550/551/553: User unknown/not local (useful negative signal).
  - 450/451/452: Temporary failures (greylisting/rate limit; retry slower).
- STARTTLS vs SMTPS: Port 25/587 typically need STARTTLS; 465 is SSL-wrapped. Use openssl s_client appropriately.
- Throttle automation: Slow down smtp-user-enum if you see temp failures or IDS noise (e.g., -W 1 for 1s wait).
- Wordlists: Start small to confirm signal (/usr/share/seclists/Usernames/top-usernames-shortlist.txt), then expand.
- Avoid sending mail: For relay tests, quit after RCPT to avoid delivering messages (swaks --quit-after RCPT).
- Authorization safety: Attempt SMTP AUTH only with explicit authorization; many orgs lock accounts on failed attempts.
- Pivot value: Valid usernames are valuable for VPN/SSH/RDP/WinRM/HTTP auth across the environment.

# Minimal cheat sheet (one-screen flow)
```
# Vars
TARGET=10.10.10.10
LOCALDOMAIN=example.local
USERS=/usr/share/seclists/Usernames/top-usernames-shortlist.txt
mkdir -p scans

# 1) Discover & fingerprint
nmap -p25,465,587 -sV -sC -Pn --script smtp-commands,smtp-open-relay,smtp-enum-users,smtp-ntlm-info -oA scans/smtp $TARGET

# 2) EHLO (plain)
printf "EHLO pentest\r\nQUIT\r\n" | nc -nv $TARGET 25

# 3) STARTTLS check
openssl s_client -starttls smtp -connect $TARGET:25 -crlf -quiet <<< $'EHLO pentest\r\nQUIT\r\n'

# 4) Manual VRFY/RCPT probe
printf "EHLO pentest\r\nVRFY root\r\nVRFY administrator\r\nQUIT\r\n" | nc -nv $TARGET 25
printf "EHLO pentest\r\nMAIL FROM:<x@x.com>\r\nRCPT TO:<root@$LOCALDOMAIN>\r\nQUIT\r\n" | nc -nv $TARGET 25

# 5) Automated user enum
smtp-user-enum -M VRFY -U $USERS -t $TARGET | tee scans/smtp-vrfy.txt
smtp-user-enum -M RCPT -U $USERS -D $LOCALDOMAIN -t $TARGET | tee scans/smtp-rcpt.txt

# 6) Open relay tests
nmap -p25 --script smtp-open-relay -Pn -oN scans/smtp-open-relay.txt $TARGET
swaks --server $TARGET --from a@ext1.net --to b@ext2.org --quit-after RCPT

# 7) (Optional) SMTP AUTH (lab only)
hydra -L users.txt -P passwords.txt -f -vV $TARGET smtp
# or 465
hydra -L users.txt -P passwords.txt -s 465 -S -f -vV $TARGET smtp
```

# Summary
SMTP enumeration aims to learn what the mail server is, which features it supports, whether it secures traffic with TLS, whether it leaks valid users (VRFY/RCPT), and whether it is misconfigured as an open relay. On eJPT-style engagements, the high-value outcomes are:
- A list of valid usernames (useful across multiple services).
- Confirmation of supported auth mechanisms and TLS posture.
- Detection of misconfigurations like open relays.

Without the transcript, these notes reflect standard, conservative SMTP enumeration methodology typically taught in service enumeration modules.