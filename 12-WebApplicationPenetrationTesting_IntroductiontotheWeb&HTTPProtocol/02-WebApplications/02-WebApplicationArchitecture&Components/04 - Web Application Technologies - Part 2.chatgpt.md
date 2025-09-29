## What the video covers (Introduction / big picture)
Note: No transcript was provided for “04 - Web Application Technologies - Part 2.mp4” (folder: 02-WebApplicationArchitecture&Components). The summary below is inferred conservatively from the title and typical eJPT curriculum.

This part likely continues from Part 1 (HTTP/client-side basics) and focuses on:
- Server-side web technologies and typical stacks (LAMP/LEMP, WAMP/IIS, Java/Tomcat, Node.js/Express, Python/Flask/Django, Ruby on Rails).
- How to fingerprint technologies from headers, cookies, and responses.
- Common directories/paths, admin endpoints, and indicators for frameworks/CMS.
- Practical enumeration workflow and tooling for a pentester: headers, methods, content discovery, WAF detection, virtual hosts, TLS.
- Where configs/logs often live (useful for local enumeration after footholds).

Goal: Build a fast, reliable process to identify the tech stack and map the attack surface of a web application.

## Flow (ordered)
1. Identify service and stack quickly:
   - Check HTTP/HTTPS, grab headers, detect server/framework/language.
2. Cross-validate fingerprints:
   - Combine headers, cookies, and file structure; use multiple tools (whatweb/Wappalyzer/nmap NSE).
3. Probe HTTP behavior:
   - Methods, redirects, compression, HTTP/2, TLS ciphers/certs.
4. Inspect entry points:
   - robots.txt, sitemap.xml, common files (login, admin, config samples), framework/CMS artifacts.
5. Content discovery:
   - Directory and file fuzzing with proper extensions; handle redirects and status code filtering.
6. Virtual hosts and subdomains (if a domain is in-scope):
   - Host header brute force; enumerate subdomains.
7. CMS/framework-specific checks:
   - WordPress/Joomla/Drupal signatures; app server endpoints (/manager for Tomcat, etc.).
8. Note platform-specific paths:
   - Apache/Nginx/IIS/Tomcat default roots, configs, and logs for post-foothold enumeration.
9. Consolidate findings and plan targeted testing:
   - Auth/session behavior, upload points, APIs (Swagger/OpenAPI), version disclosures.

## Tools highlighted
- Browser DevTools (Network/Headers): Quick visual of headers, cookies, redirects.
- curl: Inspect headers/methods, follow redirects, quick checks for common files.
- nmap (HTTP NSE scripts): http-headers, http-title, http-enum, http-methods, http-robots.txt, ssl-*.
- whatweb or Wappalyzer: Technology and framework fingerprinting.
- httpx: Title, status, tech-detect at scale.
- wafw00f: Identify presence/type of WAF.
- gobuster / ffuf / feroxbuster: Directory and file discovery.
- nikto: Quick misconfig and dangerous files check (use as a broad recon, verify manually).
- Optional, when relevant:
  - wpscan (WordPress-specific enumeration).
  - dirsearch (Python-based content discovery).
  - arjun (parameter discovery).
  - openssl s_client (TLS/handshake details).

## Typical command walkthrough (detailed, copy-paste friendly)
Set a target and base URL (adjust http/https as needed):

```bash
# Setup
export TARGET=10.10.10.10
export SCHEME=http
export BASE="$SCHEME://$TARGET"
```

1) Quick service/tech fingerprint

```bash
# Raw headers + status line
curl -sSL -D- -o /dev/null "$BASE" | sed -n '1,40p'

# Key headers quickly
curl -sI "$BASE" | egrep -i 'server|x-powered-by|set-cookie|via|x-aspnet|x-runtime|x-drupal|x-generator|x-frame-options|x-content-type-options|x-xss-protection'

# whatweb deep-ish fingerprint
whatweb -a 3 "$BASE"

# nmap HTTP enumeration (adjust ports)
nmap -p80,443 -sV --script http-headers,http-title,http-methods,http-robots.txt,http-enum,http-server-header "$TARGET"

# WAF detection
wafw00f "$BASE"

# httpx quick overview (if installed)
httpx -u "$BASE" -title -status-code -tech-detect -ip -cdn -follow-redirects
```

2) Methods, WebDAV, trace

```bash
# Allowed methods
curl -s -i -X OPTIONS "$BASE"

# TRACE test (should be disabled)
curl -s -i -X TRACE "$BASE" -H "X-Test: tracecheck"

# WebDAV scan
nmap -p80,443 --script http-webdav-scan "$TARGET"
```

3) Common entry points

```bash
# robots.txt / sitemap
curl -s "$BASE/robots.txt" || true
curl -s "$BASE/sitemap.xml" || true

# Standard login/admin guesses (non-intrusive GETs)
for p in /login /admin /administrator /wp-login.php /wp-admin/ /config.php /phpinfo.php /server-status /server-info; do
  code=$(curl -k -o /dev/null -s -w "%{http_code}" "$BASE$p"); echo "$code $p";
done
```

4) Content discovery (pick one, tune wordlists)

```bash
# ffuf: extensions matter; adjust wordlist to scope
ffuf -u "$BASE/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -e php,html,txt,js,asp,aspx,jsp -mc 200,204,301,302,307,401,403 -t 100

# gobuster (similar)
gobuster dir -u "$BASE" -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,js,asp,aspx,jsp -t 60

# feroxbuster (recursive by default; consider -d 1 to limit depth)
feroxbuster -u "$BASE" -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x php,html,txt,js,asp,aspx,jsp -t 50 -q
```

5) Virtual hosts (if you have a domain name and a direct IP)

```bash
# Replace DOMAIN with the in-scope domain; supply the server IP as TARGET
export DOMAIN=example.com
# Baseline size (to filter default vhost response)
export BASELEN=$(curl -s "http://$TARGET" | wc -c)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u "http://$TARGET/" -H "Host: FUZZ.$DOMAIN" -fs $BASELEN -t 100
```

6) TLS and HTTP/2 (if HTTPS)

```bash
# TLS ciphers and certificate
nmap -p443 --script ssl-cert,ssl-enum-ciphers "$TARGET"

# HTTP/2 support probe
curl -sI --http2 "$SCHEME://$TARGET" || true
```

7) Cookies and framework indicators

```bash
# Inspect cookies
curl -sI "$BASE" | grep -i set-cookie

# Quick mapping (common indicators):
#  - PHPSESSID            -> PHP app (LAMP/LEMP)
#  - JSESSIONID           -> Java/Tomcat/JSP
#  - ASP.NET_SessionId    -> ASP.NET/IIS
#  - csrftoken, sessionid -> Django
#  - _rails session names -> Rails
#  - X-Powered-By: Express -> Node.js/Express
#  - Server: Apache-Coyote -> Tomcat
```

8) CMS checks (only if indicators suggest a CMS)

```bash
# WordPress indicators
curl -sI "$BASE/wp-login.php" | head -n 1
curl -s "$BASE" | grep -i 'wp-content\|wp-includes\|generator.*WordPress' || true

# Optional WP enumeration (non-intrusive flags; requires Ruby and tool install)
# wpscan --url "$BASE" --enumerate ap,at,tt,cb,u --plugins-detection passive
```

9) API discovery (common OpenAPI/Swagger paths)

```bash
for p in /swagger /swagger-ui/ /swagger.json /openapi.json /api-docs /v2/api-docs; do
  code=$(curl -k -o /dev/null -s -w "%{http_code}" "$BASE$p"); echo "$code $p";
done
```

10) Nmap deeper HTTP scripts (select as needed)

```bash
nmap -p80,443 -sV --script http-title,http-headers,http-methods,http-robots.txt,http-enum,http-auth,http-server-header,http-cors,http-security-headers "$TARGET"
```

## Practical tips
- Correlate multiple signals: Don’t trust a single header. Combine Server/X-Powered-By with cookies, paths, and file fingerprints.
- Check both HTTP and HTTPS: Redirects and reverse proxies can change headers and behavior.
- Normalize status codes in fuzzing: Use -mc to include 301/302/401/403; inspect sizes (-fs/-fl) to filter noise.
- Respect scope and rate limits: Tune concurrency; WAFs can throttle. Use -t carefully.
- Follow redirects for accurate tech detection: Some stacks reveal tech only after the final landing page.
- Common platform paths and files:
  - Apache (Debian/Ubuntu): webroot /var/www/html; conf /etc/apache2/; vhosts /etc/apache2/sites-enabled/; logs /var/log/apache2/
  - Nginx: webroot /usr/share/nginx/html or /var/www; conf /etc/nginx/; vhosts /etc/nginx/sites-enabled/; logs /var/log/nginx/
  - PHP-FPM ini: /etc/php/*/*/php.ini (varies by version/SAPI)
  - IIS: webroot C:\inetpub\wwwroot; config C:\Windows\System32\inetsrv\config\applicationHost.config; logs C:\inetpub\logs\LogFiles
  - Tomcat: base /var/lib/tomcat*/ or /opt/tomcat/; webapps /var/lib/tomcat*/webapps; manager /manager/html
- Recognize framework hints:
  - Tomcat: Server: Apache-Coyote; cookie JSESSIONID; paths like /manager
  - ASP.NET: X-Powered-By: ASP.NET; cookie ASP.NET_SessionId; Server: Microsoft-IIS/10.0
  - Node/Express: X-Powered-By: Express; default port 3000 (not definitive)
  - Django: csrftoken and sessionid cookies; security headers often strict
  - WordPress: wp-content/wp-includes; /wp-login.php; meta generator
- Keep notes of redirects, cookies, and versions; they guide targeted checks later (auth, file uploads, injection points).
- Validate findings manually: Automated tools can misidentify; verify by fetching specific endpoints or assets.

## Minimal cheat sheet (one-screen flow)
```bash
# Setup
TARGET=10.10.10.10; SCHEME=http; BASE="$SCHEME://$TARGET"

# Fingerprint
curl -sSL -D- -o /dev/null "$BASE" | sed -n '1,30p'
whatweb -a 3 "$BASE"
nmap -p80,443 -sV --script http-headers,http-title,http-methods,http-robots.txt,http-enum "$TARGET"
wafw00f "$BASE"

# Methods & basics
curl -s -i -X OPTIONS "$BASE"
curl -s "$BASE/robots.txt" || true
curl -s "$BASE/sitemap.xml" || true

# Content discovery
ffuf -u "$BASE/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -e php,html,txt,js,asp,aspx,jsp -mc 200,204,301,302,307,401,403 -t 100

# TLS (if HTTPS)
nmap -p443 --script ssl-cert,ssl-enum-ciphers "$TARGET"

# Virtual hosts (if domain known)
DOMAIN=example.com; BASELEN=$(curl -s "http://$TARGET" | wc -c)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://$TARGET/" -H "Host: FUZZ.$DOMAIN" -fs $BASELEN -t 100

# CMS quick checks
curl -sI "$BASE/wp-login.php" | head -n 1
curl -s "$BASE" | grep -i 'wp-content\|wp-includes\|generator'
```

## Summary
Based on the module title and context, this video likely deepens your understanding of server-side web technologies and shows how to quickly fingerprint stacks and map web-application components. The focus is on practical, low-noise enumeration: collect and correlate headers, cookies, and content; probe methods and TLS; discover files/directories; check for WAFs, vhosts, and CMS/framework-specific indicators; and note platform-specific default paths. Use a consistent, repeatable workflow to turn raw observations into a clear picture of the application’s architecture, guiding later targeted testing.