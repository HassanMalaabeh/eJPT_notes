# 17 - SMTP Enumeration (eJPT)

Note: No transcript was provided. The following summary is inferred conservatively from the filename and typical eJPT SMTP enumeration content.

## What the video covers (Introduction / big picture)
- How to enumerate SMTP services to gather usernames, server capabilities, and misconfigurations.
- Ports and protocols: SMTP (25), SMTPS (465), Submission with STARTTLS (587).
- Manual enumeration (EHLO/HELO, VRFY, EXPN, RCPT TO) and automated tooling.
- Identifying valid users, checking for open relay, and extracting server/version/domain info.
- Safe practices to avoid sending emails (quit after RCPT, rate limiting).

## Flow (ordered)
1. Discover SMTP ports and identify the server/version.
2. Enumerate EHLO/ESMTP capabilities (STARTTLS, AUTH, SIZE, PIPELINING).
3. Manual username discovery with VRFY/EXPN (if enabled).
4. RCPT TO-based enumeration with a valid MAIL FROM (commonly works when VRFY/EXPN are disabled).
5. Automate user enumeration with smtp-user-enum / Nmap NSE / Metasploit.
6. Check for Exchange/NTLM info and open relay safely.
7. Use TLS where needed (STARTTLS on 25/587; implicit TLS on 465).
8. Collect evidence and handle edge cases (catch-all domains, relaying denied, throttling).

## Tools highlighted
- Nmap (service detection + smtp NSE scripts)
- Netcat or Telnet (manual SMTP dialogue)
- OpenSSL s_client (TLS/STARTTLS testing)
- smtp-user-enum (PentestMonkey)
- swaks (Swiss Army Knife for SMTP)
- Metasploit auxiliary scanners (smtp_version, smtp_enum, smtp_ntlm_info, smtp_open_relay)
- Seclists wordlists (usernames)

## Typical command walkthrough (detailed, copy-paste friendly)

Set helpful variables:
```bash
TARGET=10.10.10.10
DOM=example.com
```

1) Scan for SMTP services and capabilities
```bash
# Quick ports + versions
nmap -p25,465,587 -sV -Pn -oN nmap_smtp_$TARGET.txt $TARGET

# Focused SMTP NSE
nmap -p25,465,587 -sV -Pn \
  --script smtp-commands,smtp-enum-users,smtp-ntlm-info \
  -oN nmap_smtp_nse_$TARGET.txt $TARGET
```

2) Banner grab and EHLO capabilities (manual)
```bash
# Plain on 25
nc -nv $TARGET 25
# Then type:
# EHLO pentest.local
# QUIT

# STARTTLS on 25
openssl s_client -starttls smtp -crlf -connect $TARGET:25
# Then type:
# EHLO pentest.local
# QUIT

# Implicit TLS on 465
openssl s_client -crlf -connect $TARGET:465
# Then type:
# EHLO pentest.local
# QUIT
```

Non-interactive EHLO (handy to log responses):
```bash
printf "EHLO pentest.local\r\nQUIT\r\n" | nc -nv $TARGET 25
printf "EHLO pentest.local\r\nQUIT\r\n" | openssl s_client -starttls smtp -crlf -connect $TARGET:25
```

3) Manual username checks (VRFY/EXPN)
```bash
# VRFY and EXPN (if enabled) — expect 250 for success, 550/252 for unknown/disabled
printf "EHLO pentest.local\r\nVRFY root\r\nEXPN admin\r\nQUIT\r\n" | nc -nv $TARGET 25
```

4) Manual RCPT TO enumeration (often works even if VRFY/EXPN are disabled)
```bash
# Use a valid sender, then RCPT TO. 250/251 usually = exists; 550/551/553 = not found/relaying denied.
printf "EHLO pentest.local\r\nMAIL FROM:<probe@$DOM>\r\nRCPT TO:<administrator@$DOM>\r\nQUIT\r\n" | nc -nv $TARGET 25
```

5) Automate with smtp-user-enum (PentestMonkey)
```bash
# Install if needed
sudo apt-get update && sudo apt-get install -y smtp-user-enum

# Single-user checks
smtp-user-enum -M VRFY -u root -t $TARGET
smtp-user-enum -M EXPN -u admin -t $TARGET

# Wordlist with VRFY (fast if supported)
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t $TARGET

# RCPT method (commonly effective). Specify domain.
smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t $TARGET -D $DOM

# Alternate port (e.g., 587)
smtp-user-enum -M RCPT -U users.txt -t $TARGET -p 587 -D $DOM
```

6) Nmap NSE user enumeration and options
```bash
# NSE user enum with chosen methods and wordlist
nmap -p25 --script smtp-enum-users \
  --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT},userdb=/usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -oN nmap_smtp_userenum_$TARGET.txt $TARGET
```

7) swaks for safe transaction testing
```bash
# Show EHLO capabilities
sudo apt-get install -y swaks
swaks --server $TARGET --port 25 --ehlo pentest.local --quit-after EHLO

# Test RCPT acceptance without sending an email
swaks --server $TARGET --port 25 --from probe@$DOM --to bob@$DOM --quit-after RCPT

# STARTTLS on 587
swaks --server $TARGET --port 587 --tls --from probe@$DOM --to bob@$DOM --quit-after RCPT
```

8) Open relay tests (safe, stop at RCPT)
```bash
# Nmap open relay test
nmap -p25 --script smtp-open-relay -oN nmap_smtp_openrelay_$TARGET.txt $TARGET

# swaks: attempt external recipient; quit after RCPT to avoid sending data
swaks --server $TARGET --from probe@$DOM --to victim@gmail.com --quit-after RCPT
```

9) Metasploit auxiliary modules
```bash
msfconsole -q -x "
use auxiliary/scanner/smtp/smtp_version;
set RHOSTS $TARGET;
run;

use auxiliary/scanner/smtp/smtp_enum;
set RHOSTS $TARGET;
set THREADS 10;
set USER_FILE /usr/share/seclists/Usernames/top-usernames-shortlist.txt;
run;

use auxiliary/scanner/smtp/smtp_ntlm_info;
set RHOSTS $TARGET;
run;

exit"
```

Interpreting responses (quick guide):
- 220: Service ready (banner)
- 250: OK / capability lines (often “250-...”)
- 250 2.1.5 or 251: Recipient OK (likely valid)
- 550 5.1.1: User unknown
- 550 5.7.1 / 554: Relay denied
- 252: Cannot VRFY but will accept message (ambiguous; use RCPT enumeration)

## Practical tips
- Always EHLO first; many features (AUTH/STARTTLS) only appear after EHLO.
- VRFY/EXPN are often disabled on hardened servers; try RCPT TO with a valid MAIL FROM.
- Use the right recipient style: some servers expect user@domain; others accept just user.
- For 587 (submission), expect STARTTLS; use openssl -starttls smtp or swaks --tls.
- Detect catch-all: if many RCPT TOs return 250, try sending to clearly bogus names; consistent 250 may indicate a catch-all or accept-then-bounce setup.
- Stop at RCPT to avoid sending emails; use QUIT after RCPT to keep tests safe and quiet.
- Rate limit list-based enumeration to avoid throttling or lockouts.
- Exchange/NTLM: use smtp-ntlm-info to leak domain/host info if supported.
- Save raw SMTP dialogues for reporting; include server banners and exact status codes.

## Minimal cheat sheet (one-screen flow)
```bash
TARGET=10.10.10.10; DOM=example.com

# 1) Ports + version + capabilities
nmap -p25,465,587 -sV -Pn $TARGET
nmap -p25,465,587 -sV -Pn --script smtp-commands,smtp-ntlm-info $TARGET

# 2) EHLO (manual)
printf "EHLO pentest.local\r\nQUIT\r\n" | nc -nv $TARGET 25

# 3) Try VRFY/EXPN
printf "EHLO pentest.local\r\nVRFY root\r\nEXPN admin\r\nQUIT\r\n" | nc -nv $TARGET 25

# 4) RCPT-based check
printf "EHLO pentest.local\r\nMAIL FROM:<probe@$DOM>\r\nRCPT TO:<admin@$DOM>\r\nQUIT\r\n" | nc -nv $TARGET 25

# 5) Automate user enum
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t $TARGET
smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t $TARGET -D $DOM

# 6) Open relay (safe)
nmap -p25 --script smtp-open-relay $TARGET
swaks --server $TARGET --from probe@$DOM --to victim@gmail.com --quit-after RCPT
```

## Summary
- Enumerate SMTP on 25/465/587 to identify server type and features with Nmap and EHLO.
- Try VRFY/EXPN for quick wins; fall back to RCPT TO-based user enumeration with a valid MAIL FROM.
- Automate with smtp-user-enum or Nmap’s smtp-enum-users; use Metasploit for additional data (version/NTLM).
- Validate TLS/STARTTLS with openssl or swaks; test open relay safely by quitting after RCPT.
- Interpret status codes carefully, watch for catch-all behavior, and rate-limit to stay stealthy and avoid sending emails.