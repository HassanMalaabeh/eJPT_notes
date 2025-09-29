# 01 - Web Application Architecture (eJPT) — Study Notes

Note: No transcript was provided. The following summary is based on the filename and typical eJPT curriculum for “Web Application Architecture & Components.” Where specific commands/paths are shown, they are common defaults; verify in your environment.

## What the video covers (Introduction / big picture)
- High-level web application architecture and why it matters for pentesting.
- Typical request path: client → DNS → TCP/TLS → edge (CDN/WAF/load balancer/reverse proxy) → web server → application runtime → database/cache → response.
- Core components and their roles: web server (Apache/Nginx/IIS), application layer (PHP-FPM, Node.js/Express, Python WSGI, Java/Tomcat/.NET), databases (MySQL/Postgres/MSSQL, NoSQL), caches (Redis/Memcached), and supporting infra (WAF, CDN, API gateways).
- Trust boundaries and common attack surfaces that map to architecture: input handling, authentication/session state, server-side integrations (SSRF), database interactions (injection), client-side rendering (XSS), deserialization, file uploads, and misconfigurations.
- Common deployment stacks and defaults: LAMP/LEMP, MERN/MEAN, Java/Tomcat, .NET/IIS; default ports, paths, headers, log locations.
- How to quickly map an unknown web app’s architecture during an engagement to drive focused testing.

## Flow (ordered)
1. Client and DNS
   - Browser resolves domain via DNS (A/AAAA/CNAME).
   - Subdomains and virtual hosts affect routing.
2. Transport and Security
   - TCP handshake on web ports (80/443/8080/8443...).
   - TLS handshake; SNI determines certificate and backend in many setups.
3. Edge Layer
   - CDN for static assets; WAF and load balancers/reverse proxies (e.g., Nginx/HAProxy) apply policies and route traffic.
4. Web Server
   - Serves static content and forwards dynamic requests to application runtime (PHP-FPM, uWSGI/Gunicorn, Node, .NET, Java).
5. Application Layer
   - Business logic, templates, frameworks (WordPress, Django, Rails, Express, Spring, ASP.NET).
   - Outbound calls to internal services and third-party APIs (potential SSRF pivot).
6. Data Layer
   - Databases (MySQL/PostgreSQL/MSSQL/Oracle/NoSQL), caches (Redis/Memcached), message queues.
7. State Management
   - Sessions via cookies (Secure/HttpOnly/SameSite), tokens (JWT), server-side stores.
8. Logging/Monitoring
   - Web server, application, and DB logs; error stacks can leak details.
9. Common Stacks and Defaults
   - LAMP/LEMP paths, IIS defaults, common admin panels/endpoints.
10. Pentest Mapping
   - Identify ports/tech, enumerate routes and vhosts, fingerprint headers/TLS, find hidden endpoints, understand trust boundaries, then test systematically.

## Tools highlighted
- Scanning/fingerprinting: nmap, whatweb, httpx, nikto (noisy), wafw00f, testssl.sh, openssl s_client.
- HTTP interaction: curl, wget, browser devtools, Burp Suite (Community).
- Discovery/fuzzing: gobuster, ffuf, dirsearch/feroxbuster.
- DNS/virtual hosts: dig, host, gobuster vhost, ffuf Host header fuzzing.
- Misc: jq, sed/awk for parsing; wordlists from SecLists.

## Typical command walkthrough (detailed, copy-paste friendly)
Adjust IP/DOMAIN/ports as needed. Use only on systems you’re authorized to test.

Setup
```
export IP=10.10.10.10
export DOMAIN=target.example
mkdir -p scans
```

1) Discover web ports and basic service info
```
nmap -Pn -p 80,443,8080,8443,8000,8888,9000,9090,5000,3000 -sC -sV -oA scans/web-quick $IP
nmap -Pn -p- --min-rate 5000 -T4 -oA scans/allports $IP
```

2) Fingerprint HTTP/TLS/tech stack
```
# Titles, status, tech detection (httpx)
echo $IP | httpx -title -tech-detect -status-code -web-server -ip -cdn -tls-grab -p 80,443,8080,8443

# Server headers and redirects
curl -sI http://$IP | sed -n '1,20p'
curl -skI https://$IP | sed -n '1,40p'

# TLS details and certificate (use SNI if you know domain)
openssl s_client -connect ${IP}:443 -servername $DOMAIN </dev/null 2>/dev/null \
| openssl x509 -noout -text | sed -n '1,80p'

# Deeper TLS scan (optional; noisy)
# ./testssl.sh --fast --sneaky https://$DOMAIN
```

3) Identify WAF/CDN and edge behavior
```
wafw00f -a http://$DOMAIN
dig +short $DOMAIN
dig +short CNAME $DOMAIN
```

4) Quick technology fingerprinting and low-hanging files
```
whatweb -a 3 http://$IP
curl -s http://$IP/robots.txt || true
curl -s http://$IP/sitemap.xml | head
curl -s http://$IP/server-status?auto | head     # Apache mod_status (if exposed)
curl -s http://$IP/nginx_status | head          # Nginx stub_status
curl -s http://$IP/phpinfo.php | head
```

5) Enumerate HTTP methods and potential WebDAV
```
nmap -Pn --script http-methods -p 80,443,8080,8443 $IP
# Or manual:
for m in GET POST PUT DELETE PATCH OPTIONS HEAD PROPFIND; do
  echo "== $m =="; curl -s -o /dev/null -w "%{http_code}\n" -X $m http://$IP/;
done
```

6) Directory and file brute-forcing
```
# HTTP
gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,asp,aspx,txt,js,html -t 50 -o scans/gobuster-http.txt

# HTTPS (ignore cert issues)
gobuster dir -k -u https://$IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -x php,asp,aspx,txt,js,html -t 50 -o scans/gobuster-https.txt

# Alternative with ffuf
ffuf -u http://$IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fc 404 -t 100 -o scans/ffuf-dir.json
```

7) Virtual host and subdomain discovery (host header routing)
```
# If you know a base domain that points to the target IP
# Gobuster vhost
gobuster vhost -u http://$IP -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 50 -o scans/gobuster-vhost.txt -r -a "Mozilla/5.0"

# ffuf Host header fuzzing (more control). Baseline size to filter:
BASE=$(curl -s http://$IP | wc -c)
ffuf -u http://$IP/ -H "Host: FUZZ.$DOMAIN" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs $BASE -t 100 -o scans/ffuf-vhost.json
```

8) Parameter discovery (useful for hidden GET params)
```
ffuf -u "http://$IP/index.php?FUZZ=1" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs 0 -t 100 -o scans/ffuf-params.json
```

9) Session/cookie reconnaissance
```
# Capture cookies and inspect flags
curl -sD - http://$IP/login -o /dev/null | grep -i set-cookie

# Maintain a cookie jar for authenticated probes
curl -s -c /tmp/cj.txt -b /tmp/cj.txt -d "user=alice&pass=test" http://$IP/login
curl -s -c /tmp/cj.txt -b /tmp/cj.txt http://$IP/profile
```

10) Check for common admin panels/framework endpoints
```
# Tomcat
curl -sI http://$IP:8080/manager/html
# Jenkins
curl -sI http://$IP:8080/login
# WordPress
curl -sI http://$IP/wp-login.php
# phpMyAdmin
curl -sI http://$IP/phpmyadmin/
# IIS defaults
curl -sI http://$IP/iisstart.htm
```

11) Database/caching layer reachability (from tester perspective)
```
nmap -Pn -p 3306,5432,1433,1521,6379,11211 $IP -sV -oA scans/db-quick
# Banner grabs (if accessible; don’t brute creds without scope)
timeout 3 bash -c 'echo | nc -v $IP 3306'
timeout 3 bash -c 'echo | nc -v $IP 5432'
```

12) Proxy to browser for manual testing (Burp)
- Configure browser to send traffic through Burp 127.0.0.1:8080, import Burp CA for HTTPS interception, explore, record sitemap, and use Repeater/Intruder for targeted requests.

Common defaults/reference
- Web roots: Apache (/var/www/html), Nginx (/usr/share/nginx/html or /var/www), IIS (C:\inetpub\wwwroot).
- Configs: /etc/apache2/sites-enabled/, /etc/nginx/sites-enabled/, C:\Windows\System32\inetsrv\config\applicationHost.config.
- Logs: /var/log/apache2/{access.log,error.log}, /var/log/nginx/{access.log,error.log}, Windows Event Viewer for IIS.
- Ports: 80/443 (HTTP/S), 8080/8443 (alt HTTP/S, Tomcat/Jenkins), 3000/5000 (Node/Flask), 3306 (MySQL), 5432 (Postgres), 1433 (MSSQL), 6379 (Redis), 11211 (Memcached).

## Practical tips
- Map trust boundaries early: where does user input cross into server logic, external calls, and the database?
- Pay attention to headers: Server, X-Powered-By, Via, X-Forwarded-For, Set-Cookie; they reveal stack and edge devices.
- Use SNI in TLS probes; virtual hosts behind a single IP may serve different apps per Host header.
- WAF and CDN can change response sizes and codes; baseline with multiple requests and vary User-Agent.
- Prefer -I/HEAD or -s in curl to reduce noise; avoid overly aggressive scans on production unless authorized.
- Directory and vhost enumeration benefit from strong wordlists (SecLists); filter by response size rather than status alone.
- Hidden “status” endpoints (server-status, nginx_status, /actuator, /metrics) leak architecture details.
- If HTTP is redirected to HTTPS, re-run tools with -k (ignore cert) and correct scheme.
- Use Burp Suite to observe cookies, CSRF tokens, and session flows; record a sitemap before fuzzing.
- Always comply with scope and rate limits; coordinate with clients about testing windows.

## Minimal cheat sheet (one-screen flow)
```
export IP=10.10.10.10; export DOMAIN=target.example; mkdir -p scans

# Ports and basic services
nmap -Pn -p 80,443,8080,8443 -sC -sV -oA scans/web-quick $IP

# Fingerprint HTTP/TLS/tech
echo $IP | httpx -title -tech-detect -status-code -web-server -ip -cdn -tls-grab -p 80,443,8080,8443
curl -sI http://$IP | head
openssl s_client -connect ${IP}:443 -servername $DOMAIN </dev/null 2>/dev/null | openssl x509 -noout -text | head -n 40

# WAF/CDN
wafw00f -a http://$DOMAIN

# Low-hanging files and methods
curl -s http://$IP/robots.txt
nmap -Pn --script http-methods -p 80,443 $IP

# Content discovery
gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,js -t 50 -o scans/gobuster.txt

# VHost discovery (needs a domain)
BASE=$(curl -s http://$IP | wc -c)
ffuf -u http://$IP/ -H "Host: FUZZ.$DOMAIN" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs $BASE -t 100 -o scans/ffuf-vhost.json

# Params
ffuf -u "http://$IP/index.php?FUZZ=1" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0 -t 100 -o scans/ffuf-params.json
```

## Summary
- The module introduces web application architecture from a pentester’s perspective: how requests traverse edge devices, web servers, app runtimes, and data layers, and where trust boundaries create attack surfaces.
- Understanding components (CDN/WAF, reverse proxies, runtimes, databases, caches) and their fingerprints enables efficient enumeration and targeted testing.
- Use a structured approach: identify ports, fingerprint stack and TLS, enumerate content and vhosts, map session/auth flows, and probe common management or status endpoints before deeper vulnerability testing.
- Always validate findings, respect scope, and tailor wordlists and techniques to the observed stack and deployment.