# 03 - Web Application Technologies - Part 1 (eJPT) — Study Notes

Note: No transcript was provided. The following summary is inferred conservatively from the filename and course folder (02-WebApplicationArchitecture&Components). It reflects common eJPT coverage for “Web Application Technologies - Part 1.”

## What the video covers (Introduction / big picture)
- Web application architecture basics:
  - Client–server model; how browsers talk to web servers over HTTP/HTTPS.
  - HTTP requests/responses, methods (GET/POST/etc.), status codes, headers, URL structure.
  - Static vs dynamic content; the roles of web servers (Apache, Nginx, IIS) vs application platforms (PHP, Python, Java/Tomcat, Node.js).
- Technology fingerprinting:
  - Identifying server/framework/language via headers, default pages, and behavior.
  - Common ports and services hosting web apps beyond 80/443 (e.g., 8080, 8443, 8000, 5000, 3000, 8888, 9090).
- Initial web enumeration workflow:
  - Discovering web services, pulling headers/banners, checking methods, grabbing robots.txt/sitemap.xml, basic content discovery, and TLS overview.
- Where to look for hints:
  - Common default paths, admin panels, error pages, and HTTP headers (Server, X-Powered-By, Set-Cookie).

## Flow (ordered)
1. Discover open ports and identify web services (scan + service detection).
2. Pull HTTP(S) headers and titles; note technologies and versions.
3. Fingerprint frameworks/servers with specialized tools (whatweb, nmap http-* NSE).
4. Check HTTP methods allowed and other behavior (OPTIONS, TRACE).
5. Retrieve well-known files (robots.txt, sitemap.xml, security.txt).
6. Perform content discovery (directories/files, extensions) cautiously.
7. Review TLS certificate and security headers (if HTTPS).
8. Consider virtual hosts and DNS context (Host header fuzzing).
9. Manual recon with a browser and an intercepting proxy (Burp Suite).
10. Organize findings and prioritize follow-up (auth endpoints, admin panels, error pages).

## Tools highlighted
- nmap (with http-* NSE scripts) — discovery, fingerprinting
- curl and wget — headers, methods, file grabs
- whatweb — technology fingerprinting
- ffuf or gobuster — directory/file discovery
- nikto — quick web misconfig/known issue checks
- openssl s_client — TLS certificate details
- wafw00f — WAF detection
- dig/host — DNS lookups when a domain is in scope
- Burp Suite — intercepting proxy for manual testing

## Typical command walkthrough (detailed, copy-paste friendly)
Replace 10.10.10.10 with your target. If you have a hostname (e.g., target.local or example.com), use it where appropriate.

1) Setup
```
export T=10.10.10.10
# If you know it’s HTTPS, set U accordingly.
export U=http://$T
# Common web ports to check quickly
export WEBPORTS=80,81,88,443,8000,8080,8443,8888,5000,3000,9000,9090
```

2) Port and service discovery (focus on common web ports)
```
nmap -sC -sV -p$WEBPORTS $T -oN nmap-web.txt
# If you need full sweep first:
# nmap -p- --min-rate 3000 -Pn -n $T -oN nmap-full.txt
# Then:
# nmap -sC -sV -p <open-ports> $T -oN nmap-targeted.txt
```

3) HTTP fingerprinting via nmap NSE
```
nmap -sV -p80,443,8080,8443 --script http-title,http-headers,http-server-header,http-methods,http-security-headers $T -oN nmap-http-headers.txt
```

4) Pull headers and status quickly with curl
```
curl -s -D - -o /dev/null $U/
curl -sk -I https://$T/    # ignore TLS validation if needed
```

5) Technology fingerprinting
```
whatweb -a 3 $U/           # look for frameworks, CMS, server, versions
# If multiple ports:
# whatweb -a 3 http://$T:8080/ ; whatweb -a 3 https://$T:8443/
```

6) HTTP methods and verb behavior
```
curl -s -i -X OPTIONS $U/ | sed -n '1,15p'
for m in GET POST PUT DELETE PATCH TRACE OPTIONS; do
  echo "=== $m ==="
  curl -s -i -X $m $U/ -H "Content-Type: application/json" -d '{}' | head -n 8
done
```

7) Well-known files and hints
```
for f in robots.txt sitemap.xml security.txt; do
  echo "=== $f ==="
  curl -sk $U/$f || true
done
```

8) Directory and file discovery (use either ffuf or gobuster)
- ffuf:
```
ffuf -u $U/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -e .php,.txt,.bak,.old,.zip,.tar.gz \
  -fc 403,404 -t 50 -o ffuf-root.json
```
- gobuster:
```
gobuster dir -u $U/ \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -x php,txt,bak,old,zip,tar.gz -t 50 -k -o gobuster-root.txt
```

9) TLS and certificate review (if HTTPS)
```
# If you know a hostname, add -servername <host> to see correct SNI
openssl s_client -connect $T:443 -showcerts </dev/null 2>/dev/null | openssl x509 -noout -text
```

10) WAF detection (optional)
```
wafw00f $U/
```

11) Virtual host (vhost) discovery (if you have/guess a base domain)
Replace example.com with the real domain in scope.
```
# If site resolves by IP but uses name-based vhosts, try Host header fuzzing
ffuf -u $U/ -H "Host: FUZZ.example.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 0 -t 100 -o ffuf-vhost.json
```

12) Quick checks for common admin panels and default endpoints
```
# Apache status (often 403/404 if disabled)
curl -s -o /dev/null -w "%{http_code} /server-status\n" $U/server-status
# Tomcat Manager
curl -s -o /dev/null -w "%{http_code} /manager/html\n" $U/manager/html
# phpMyAdmin
curl -s -o /dev/null -w "%{http_code} /phpmyadmin\n" $U/phpmyadmin
# Jenkins
curl -s -o /dev/null -w "%{http_code} /jenkins\n" $U/jenkins
```

13) Quick mirroring of static assets for offline review (be cautious)
```
mkdir -p loot && wget -r -np -k -p -e robots=off -P loot/ $U/
```

## Practical tips
- Ports: Check non-standard web ports (8080/8443/8000/5000/3000/8888/9090). Many app servers (Tomcat, Jenkins, Node/Express, Flask/Gunicorn) live there.
- Headers to watch:
  - Server, X-Powered-By, Set-Cookie (session names can hint at tech), Content-Type, Location (redirect behavior), Allow (from OPTIONS).
- Fingerprinting caveat: Headers can be hidden or faked. Correlate with page structure, default pages, error messages, and whatweb results.
- robots.txt often lists sensitive paths; don’t ignore it.
- Content discovery:
  - Start with small/medium wordlists; filter 403/404 with ffuf -fc 403,404 or filter-size/lines after a baseline 404.
  - Add relevant extensions (-e / -x), e.g., php, asp, aspx, jsp, js, txt, bak, zip.
- Rate/stealth:
  - Throttle if needed (ffuf -rate 50) and set a realistic User-Agent (-H "User-Agent: Mozilla/5.0").
- TLS certs: CN/SANs can reveal valid hostnames and additional vhosts.
- Virtual hosts: If the site looks like a placeholder on IP, try Host header with the domain you discover from DNS or certs.
- Default paths (typical, may vary):
  - Linux web roots: /var/www/html, /usr/share/nginx/html
  - Apache: /etc/apache2/, Nginx: /etc/nginx/, vhosts in sites-available/sites-enabled
  - Windows IIS root: C:\inetpub\wwwroot
  - Tomcat: $CATALINA_BASE/webapps, admin at /manager/html (often protected)
- Use Burp Suite early:
  - Intercept, inspect requests, view cookies, edit headers, repeat requests, and map the site.

## Minimal cheat sheet (one-screen flow)
```
export T=10.10.10.10; export U=http://$T
nmap -sC -sV -p80,81,88,443,8000,8080,8443,8888,5000,3000,9000,9090 $T -oN nmap-web.txt
nmap -sV -p80,443,8080,8443 --script http-title,http-headers,http-server-header,http-methods,http-security-headers $T -oN nmap-http.txt
curl -s -D - -o /dev/null $U/
whatweb -a 3 $U/
curl -s -i -X OPTIONS $U/ | sed -n '1,15p'
for f in robots.txt sitemap.xml security.txt; do curl -sk $U/$f; done
ffuf -u $U/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .php,.txt,.bak,.zip -fc 403,404 -t 50 -o ffuf.json
openssl s_client -connect $T:443 -showcerts </dev/null 2>/dev/null | openssl x509 -noout -text
wafw00f $U/
# If you have a domain:
# ffuf -u $U/ -H "Host: FUZZ.example.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 0 -t 100 -o vhosts.json
```

## Summary
- This part introduces how web apps work at a protocol and component level and how to recognize the technologies in play.
- The core workflow: find web services, read headers/titles, fingerprint tech, test methods, grab well-known files, enumerate content, inspect TLS, and consider virtual hosts—all while validating findings against real responses and default behaviors.
- Use nmap/curl/whatweb for fast initial reconnaissance, ffuf/gobuster for discovery, and Burp Suite for interactive exploration.