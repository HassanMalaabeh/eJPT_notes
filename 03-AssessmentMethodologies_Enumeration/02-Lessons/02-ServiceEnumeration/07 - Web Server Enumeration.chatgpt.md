# 07 - Web Server Enumeration

Note: No transcript was provided. The following is a conservative, experience-based summary inferred from the filename and the eJPT Service Enumeration context. Commands and steps reflect a standard eJPT methodology for enumerating HTTP/HTTPS services.

Only test systems you own or have explicit permission to assess.

## What the video covers (Introduction / big picture)
- How to enumerate web servers discovered during service enumeration.
- Quickly identifying stack and exposure (server, framework/CMS, headers).
- Systematic content discovery (files/folders, hidden endpoints).
- Virtual host (vhost) discovery and Host header use.
- Inspecting HTTP methods, WebDAV, TLS/SSL details.
- Using common tools (nmap NSE, curl, whatweb, gobuster/ffuf, nikto).
- Turning findings into actionable footholds (default pages, admin panels, backups).

## Flow (ordered)
1. Confirm web ports and run focused nmap http/ssl scripts.
2. Grab headers, titles, and banners; browse manually.
3. Fingerprint tech stack (whatweb; optionally Wappalyzer extension).
4. Inspect robots.txt, sitemap.xml, and common info leaks.
5. Enumerate HTTP methods and WebDAV.
6. Perform content discovery (dirs/files) with wordlists and extensions.
7. Check for vhosts via Host header fuzzing and certificate SANs.
8. Enumerate TLS/SSL configuration and pull cert details.
9. Run lightweight vulnerability checks (nikto).
10. Map hostnames in /etc/hosts if needed; intercept with Burp when testing forms/auth.
11. Document findings and iterate on each discovered app/host.

## Tools highlighted
- nmap with NSE scripts: http-title, http-headers, http-server-header, http-methods, http-enum, http-robots.txt, http-webdav-scan, ssl-cert, ssl-enum-ciphers
- curl (headers, methods, robots, host header testing)
- whatweb (tech stack fingerprint)
- gobuster, ffuf, feroxbuster, or dirsearch (content discovery)
- nikto (common misconfig/known issues)
- openssl s_client (TLS, certificate SANs)
- wafw00f (optional WAF detection)
- Burp Suite (manual testing, interception)
- SecLists wordlists

## Typical command walkthrough (detailed, copy-paste friendly)

Set target variables once for reuse:
```bash
export TARGET=10.10.10.10        # IP of the target
export HOST=target.local         # If you suspect name-based vhosts (set to best-guess domain); else leave blank
```

1) Quick service check and baseline HTTP/HTTPS enumeration with nmap
```bash
# If not already done: focused nmap on typical web ports
nmap -p 80,443,8080,8443 -sC -sV -oA nmap/web_quick $TARGET

# Run specific HTTP NSE scripts on detected open ports (adjust -p as needed)
nmap -p80,443,8080,8443 --script http-title,http-headers,http-server-header,http-methods,http-enum,http-robots.txt,http-webdav-scan -oA nmap/http_enum $TARGET

# Enumerate TLS on HTTPS ports
nmap -p443,8443 --script ssl-cert,ssl-enum-ciphers -oA nmap/ssl_enum $TARGET
```

2) Header/title/banner grab (HTTP and HTTPS)
```bash
# HTTP
curl -sI http://$TARGET/
curl -sSL -D - http://$TARGET/ | head -n 50

# HTTPS (ignore cert errors for now)
curl -k -sI https://$TARGET/
curl -k -sSL -D - https://$TARGET/ | head -n 50

# If you know/suspect a vhost:
curl -sI -H "Host: $HOST" http://$TARGET/
curl -k -sI -H "Host: $HOST" https://$TARGET/
```

3) Technology fingerprinting
```bash
whatweb -a 3 http://$TARGET/
whatweb -a 3 -v http://$TARGET/ 2>&1 | tee whatweb_http.txt
whatweb -a 3 -v https://$TARGET/ --no-colour 2>&1 | tee whatweb_https.txt
```

4) Robots, sitemap, and quick info leaks
```bash
curl -s http://$TARGET/robots.txt
curl -s http://$TARGET/sitemap.xml
curl -sk https://$TARGET/robots.txt
curl -sk https://$TARGET/sitemap.xml

# Common info-leak endpoints (check quickly)
for p in /.env /.git/HEAD /.gitignore /backup.zip /backup.tar.gz /config.php.bak /server-status /server-info; do
  echo "Testing $p"
  curl -skI "http://$TARGET$p" | head -n 1
done
```

5) HTTP methods and WebDAV
```bash
# Allowed methods on root
curl -sI -X OPTIONS http://$TARGET/ | sed -n 's/^Allow: //Ip'
curl -ksI -X OPTIONS https://$TARGET/ | sed -n 's/^Allow: //Ip'

# Nmap confirmation and DAV detection
nmap -p80,443 --script http-methods,http-webdav-scan $TARGET -oA nmap/http_methods_dav

# TRACE test (safe)
curl -i -X TRACE http://$TARGET/ | head -n 20
```

6) Content discovery (directories/files)
- Pick one tool; below are common choices. Adjust threads to avoid DoS.

Gobuster:
```bash
# Common wordlist and extensions (tweak -t threads if needed)
WORDLIST=/usr/share/seclists/Discovery/Web-Content/common.txt
EXT=php,txt,html,js,bak,zip
gobuster dir -u http://$TARGET -w $WORDLIST -x $EXT -t 50 -o gobuster_http.txt
gobuster dir -u https://$TARGET -k -w $WORDLIST -x $EXT -t 50 -o gobuster_https.txt
```

ffuf:
```bash
# Directory brute-force
ffuf -u http://$TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .php,.txt,.html,.js,.bak,.zip -t 100 -mc all -fc 404 -of csv -o ffuf_http_dirs.csv

# Recursive-like discovery (follow up on findings)
# You can feed new paths back into ffuf or use feroxbuster for recursion
```

feroxbuster (fast recursion):
```bash
feroxbuster -u http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt,bak,zip -t 200 -o ferox_http.txt
```

dirsearch (good defaults):
```bash
dirsearch -u http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e php,txt,html,js,bak,zip -t 50 -o dirsearch_http.txt
```

7) Virtual host (vhost) discovery
```bash
# Get a baseline page length (no Host header or default Host)
BASE=$(curl -s http://$TARGET/ | wc -c); echo "Baseline size: $BASE"

# Fuzz Host header with ffuf; adjust -fs to filter baseline size responses
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://$TARGET/ \
     -H "Host: FUZZ.$HOST" \
     -fs $BASE \
     -t 100 -of csv -o ffuf_vhosts.csv

# When you find a candidate vhost, add it to /etc/hosts for easy browsing:
# echo "$TARGET app.$HOST" | sudo tee -a /etc/hosts
```

8) TLS/SSL and certificate SANs
```bash
# Pull cert and inspect SANs (potential vhosts)
openssl s_client -connect $TARGET:443 -servername $HOST -showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# Nmap TLS scripts already captured cipher info; review nmap/ssl_enum.*
```

9) Lightweight vulnerability checks
```bash
# Nikto (limit runtime to be polite)
nikto -h http://$TARGET -maxtime 2m -o nikto_http.txt
nikto -h https://$TARGET -maxtime 2m -o nikto_https.txt
```

10) Manual review and interception
- Open the site in a browser; note titles, forms, version strings.
- Use Burp Suite to intercept and map the site. Save interesting requests for later exploitation.

11) CMS-specific (if detected)
```bash
# WordPress example (if detected by whatweb or response)
wpscan --url http://$TARGET --enumerate u,vt,tt --api-token YOUR_WPSCAN_TOKEN
```

## Practical tips
- Always try with and without the correct Host header. Name-based vhosts can hide entire apps.
- Check cert SANs for valid hostnames; add promising names to /etc/hosts.
- Start with small/medium wordlists; escalate only if needed to avoid noise and bans.
- Include common extensions (.php, .bak, .zip, .old, .txt) to uncover backups/configs.
- Review nmap http-methods output; WebDAV or PUT often leads to easy upload footholds.
- robots.txt often reveals admin/backup paths; sitemap.xml reveals public structure.
- Default apps/panels: /server-status, /manager/html (Tomcat), /phpmyadmin, /jenkins, /actuator, /console, /admin.
- If responses are uniform, use ffuf/gobuster size filtering (-fs) to weed out false positives.
- If a WAF is present (wafw00f), throttle, randomize User-Agent, and prefer manual/burp-led recon.
- Document each interesting path, version, and credential prompt; tie back to known exploits or default creds.

## Minimal cheat sheet (one-screen flow)
```bash
# Vars
export TARGET=10.10.10.10; export HOST=target.local

# Nmap HTTP/TLS
nmap -p80,443,8080,8443 -sC -sV -oA nmap/web_quick $TARGET
nmap -p80,443,8080,8443 --script http-title,http-headers,http-server-header,http-methods,http-enum,http-robots.txt,http-webdav-scan -oA nmap/http_enum $TARGET
nmap -p443,8443 --script ssl-cert,ssl-enum-ciphers -oA nmap/ssl_enum $TARGET

# Fast headers/titles
curl -sI http://$TARGET/; curl -k -sI https://$TARGET/
curl -sI -H "Host: $HOST" http://$TARGET/

# Fingerprint
whatweb -a 3 http://$TARGET/ | tee whatweb.txt

# Methods & WebDAV
curl -sI -X OPTIONS http://$TARGET/ | sed -n 's/^Allow: //Ip'
nmap -p80,443 --script http-webdav-scan $TARGET -oA nmap/dav

# Quick leaks
curl -s http://$TARGET/robots.txt; curl -s http://$TARGET/sitemap.xml

# Content discovery (pick one)
gobuster dir -u http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,html,js,bak,zip -t 50 -o gobuster_http.txt

# Vhost fuzz
BASE=$(curl -s http://$TARGET/ | wc -c)
ffuf -u http://$TARGET/ -H "Host: FUZZ.$HOST" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs $BASE -o ffuf_vhosts.csv

# TLS cert SANs
openssl s_client -connect $TARGET:443 -servername $HOST </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName

# Nikto (quick)
nikto -h http://$TARGET -maxtime 2m -o nikto_http.txt
```

## Summary
This video likely demonstrates a structured approach to web server enumeration within eJPT: confirm and script-scan HTTP/S services, fingerprint the stack, inspect headers and well-known endpoints, enumerate methods and WebDAV, perform directory/file discovery with tuned wordlists and extensions, and uncover hidden virtual hosts via Host header fuzzing and TLS certificate SANs. Using nmap NSE, curl, whatweb, gobuster/ffuf, and nikto, you build a comprehensive picture of exposed web surfaces, identify misconfigurations and interesting paths, and prepare for targeted exploitation steps.