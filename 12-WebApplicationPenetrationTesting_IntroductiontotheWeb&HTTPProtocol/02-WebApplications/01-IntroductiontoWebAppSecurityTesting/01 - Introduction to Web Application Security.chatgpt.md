Note: No transcript was provided. The notes below are inferred conservatively from the filename/context (“01 - Introduction to Web Application Security.mp4” in 01-IntroductiontoWebAppSecurityTesting). Adjust specifics to your course instance. Use all techniques only in authorized labs/scope.

What the video covers (Introduction / big picture)
- Why web application security matters in eJPT: you’ll enumerate, map, and test HTTP/S services discovered during network recon.
- Core web fundamentals: HTTP methods, status codes, headers; HTTPS/TLS basics; cookies, sessions, and auth.
- Web app architecture: client → web server → app logic → database/APIs/CDN.
- Methodology overview: define scope → passive/active recon → map the app → content/parameter discovery → basic vulnerability checks → document evidence.
- OWASP Top 10 (high-level touch): injection, XSS, auth/session issues, access control, misconfigurations, sensitive data exposure, etc.
- Toolchain you’ll use throughout the web testing module: browser + proxy (Burp), Nmap web scripts, technology fingerprinting, directory/vhost fuzzing, basic scanners.
- Legal/ethical foundations and safe lab setup.

Flow (ordered)
1) Confirm scope and target(s): domains, IPs, ports, rate limits, timing windows.
2) Identify web services: quick TCP scan then focused scripts for HTTP/S.
3) Fingerprint technology: server, frameworks, language, CMS, files/paths.
4) Map the application: browse with a proxy, collect endpoints, note parameters.
5) Content discovery: brute-force directories/files and check robots/sitemaps.
6) Virtual host/subdomain checks: test Host header for vhosts.
7) Parameter discovery: find hidden GET/POST params to expand attack surface.
8) Check HTTP methods and headers: OPTIONS, security headers, caching.
9) Session/auth basics: observe cookies, login flow, logout, password reset.
10) Validate common issues at a high level: error handling, input reflection/encoding, direct object references, default/admin paths.
11) Record findings: screenshots, raw requests/responses, wordlists used, timestamps.
12) Plan deeper tests or tooling for later modules (e.g., auth testing, injections) within scope.

Tools highlighted
- Browser + DevTools: view requests, storage, CSP, errors.
- Burp Suite (Community is fine): Proxy, Target mapping, Repeater, Decoder, Comparer.
- Nmap with HTTP NSE scripts: http-title, http-headers, http-enum, http-methods.
- whatweb or Wappalyzer: technology fingerprinting.
- curl and wget: quick checks of headers, methods, cookies, and endpoints.
- gobuster or ffuf: directory/file and virtual host discovery.
- Nikto: quick baseline web misconfig/vuln checks (use gently, in-scope).
- SecLists wordlists: directory names, extensions, parameters, vhosts, etc.

Typical command walkthrough (detailed, copy-paste friendly)
Use only in an authorized lab. Replace IP/HOST as appropriate.

Setup
```
# Target definitions (edit these)
export IP=10.10.10.10
export HOST=target.local              # If you have a hostname; otherwise leave blank
export T=http://$IP                   # Use https://$HOST if TLS + hostname is available

# Working folders
mkdir -p scans enum loot
```

Discovery and fingerprinting
```
# Quick web-focused scan
nmap -p80,443,8080,8443 -sS -sV -sC -Pn --min-rate 2000 -oA scans/web $IP

# Full TCP sweep if needed to catch odd web ports
nmap -p- -sS -Pn --min-rate 2000 -oA scans/alltcp $IP

# HTTP-specific scripts
nmap -p80,443 --script http-title,http-headers,http-methods,http-server-header,http-enum \
    -oA scans/http-scripts $IP

# Technology fingerprint
whatweb -v $T | tee scans/whatweb.txt
```

Quick HTTP checks with curl
```
# Status line + headers
curl -k -I $T

# Save response headers verbosely
curl -k -s -o /dev/null -D - $T | tee scans/headers.txt

# Check allowed methods
curl -k -i -X OPTIONS $T

# Fetch common well-known files
curl -k -s $T/robots.txt   | tee enum/robots.txt
curl -k -s $T/sitemap.xml  | tee enum/sitemap.xml

# Show only HTTP status code for any path
curl -k -s -o /dev/null -w "%{http_code}\n" $T/admin
```

Content and file discovery
```
# Directory/file brute-forcing (adjust wordlist and extensions)
gobuster dir -u $T \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,html,txt,bak,zip \
  -t 50 -o enum/dirs_common.txt

# Alternative with ffuf
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u $T/FUZZ -e .php,.html,.txt,.bak,.zip \
     -t 50 -mc all -fc 404 -of json -o enum/ffuf_dirs.json
```

Virtual host discovery (if you have a base HOST)
```
# Simple vhost fuzzing (HTTP). Adjust filters to avoid baseline responses.
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://$IP/ -H "Host: FUZZ.$HOST" \
     -fc 400,401,403,404 -o enum/vhosts.json
```

Parameter discovery (expand attack surface)
```
# Try parameter names on a candidate endpoint (edit path)
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u $T/search?FUZZ=test -fs 0 -o enum/params_search.json
```

Session/auth observation with curl
```
# Capture a cookie jar, then reuse it
curl -k -c loot/cookies.txt -s $T/ > /dev/null
curl -k -b loot/cookies.txt -c loot/cookies.txt -s -I $T/account
```

Nikto baseline (gentle, in-scope)
```
nikto -host $T -o scans/nikto.txt
```

Burp Suite (manual workflow)
- Configure browser proxy: 127.0.0.1:8080; import Burp’s CA to intercept HTTPS cleanly.
- Set Target scope to your host(s); enable “Intercept” only when needed.
- Crawl/login normally to map the app; review Site map and Proxy history.
- Send interesting requests to Repeater; modify headers, params, cookies; observe responses.
- Use Decoder/Comparer to inspect encodings and response diffs.
- Save your Burp project frequently.

Practical tips
- Always confirm scope and get explicit authorization before testing.
- Start passive, then active: headers/robots/sitemap before brute-forcing.
- Control noise: set reasonable thread counts in gobuster/ffuf; respect rate limits.
- Filter smartly in ffuf (status, size, words): baseline one miss then filter with -fs/-fw/-fl.
- Check both HTTP and HTTPS, and alternate ports (8080/8443).
- Watch redirects (301/302) and caching headers; follow the chain to find the “real” app.
- Mind cookies and session flags: Secure, HttpOnly, SameSite; note session rotation on login/logout.
- Take notes with exact URLs, parameters, requests/responses, and tool/wordlist versions.
- Re-run quick checks after finding new paths or hosts; discoveries chain together.

Minimal cheat sheet (one-screen flow)
```
# Setup (edit IP/HOST)
export IP=10.10.10.10; export HOST=target.local; export T=http://$IP
mkdir -p scans enum loot

# Scan + scripts
nmap -p80,443,8080,8443 -sS -sV -sC -Pn --min-rate 2000 -oA scans/web $IP
nmap -p80,443 --script http-title,http-headers,http-methods,http-enum -oA scans/http $IP

# Fingerprint + headers
whatweb -v $T | tee scans/whatweb.txt
curl -k -I $T
curl -k -s -o /dev/null -D - $T | tee scans/headers.txt
curl -k -s $T/robots.txt   | tee enum/robots.txt
curl -k -s $T/sitemap.xml  | tee enum/sitemap.xml

# Content discovery
gobuster dir -u $T -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,html,txt,bak,zip -t 50 -o enum/dirs.txt

# Vhost fuzz (if HOST known)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://$IP/ -H "Host: FUZZ.$HOST" -fc 400,401,403,404 -o enum/vhosts.json

# Params (adjust endpoint)
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -u $T/search?FUZZ=test -fs 0 -o enum/params.json

# Baseline scan
nikto -host $T -o scans/nikto.txt
```

Summary
- This introductory lesson frames how you’ll approach web applications in eJPT: understand HTTP fundamentals, map the app, discover content and parameters, use a proxy for precise request manipulation, and document everything.
- The emphasis is on methodology and safe, scoped practice. Master the core toolchain (Nmap + HTTP scripts, curl, whatweb, gobuster/ffuf, Burp) and a repeatable workflow before diving deeper into vulnerabilities in later modules.