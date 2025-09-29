# 09 - Web Server Enumeration (eJPT) — Study Notes

Note: No transcript was provided. The following summary infers likely content for “Web Server Enumeration” in an eJPT Enumeration module. Commands and flow are standard, conservative practices you can apply on the exam labs.

## What the video covers (Introduction / big picture)
- Purpose: Systematically identify what web services are running, on which ports, what technologies they use, and which content/endpoints are exposed.
- Goals:
  - Detect HTTP/HTTPS services across ports.
  - Fingerprint server stack (server, language, frameworks, CMS).
  - Harvest low-hanging info (titles, headers, robots.txt, sitemap, cert SANs).
  - Discover directories/files (bruteforce) and virtual hosts.
  - Check HTTP methods and WebDAV.
  - Identify potential entry points (logins, admin panels, default pages).
- Outcome: A structured list of web assets, technologies, and prioritized findings to guide exploitation.

## Flow (ordered)
1. Scan for open TCP ports (find all HTTP/S services).
2. Fingerprint HTTP services (titles, headers, versions).
3. Manually preview pages and static endpoints (robots.txt, sitemap.xml, server-status).
4. Identify technologies (server, language, CMS, WAF) via tools and headers.
5. If HTTPS: enumerate TLS and extract certificate domains (SANs).
6. Crawl/Bruteforce directories and files (multiple extensions; handle 301/302/401/403).
7. Enumerate virtual hosts (Host header fuzzing) and update /etc/hosts for discovered vhosts.
8. Check HTTP methods and WebDAV (OPTIONS/WebDAV/PUT).
9. CMS-specific checks (e.g., WordPress with wpscan) where applicable.
10. Take notes/screenshots and consolidate URLs, creds, versions.
11. Re-scan discovered hosts/ports as needed (recursive enumeration).
12. Prioritize next steps (auth endpoints, uploads, config leaks, admin consoles).

## Tools highlighted
- Nmap: Port scan, service/version detection, HTTP and TLS scripts.
- curl/wget: Titles, headers, simple page fetches, methods testing.
- netcat/openssl s_client: Raw banner grabbing (HTTP/1.1 Host header!), TLS certs.
- whatweb / Wappalyzer: Stack/technology identification.
- wafw00f: WAF detection.
- gobuster / ffuf: Directory and vhost discovery.
- nikto: Quick web vuln/config checks.
- testssl.sh or Nmap ssl-enum-ciphers: TLS enumeration.
- Burp Suite: Manual inspection, intercept, parameter discovery.
- davtest (optional): WebDAV testing.
- wpscan (optional): WordPress enumeration.

## Typical command walkthrough (detailed, copy-paste friendly)
Replace 10.10.10.10 with your target IP. Adjust ports if different.

Setup
```
export IP=10.10.10.10
mkdir -p scans loot
```

1) Find open TCP ports, then identify HTTP
```
nmap -p- --min-rate 10000 -T4 -oA scans/alltcp $IP
# Extract ports that look like HTTP services from the gnmap
HTTP_PORTS=$(grep -oP '\d+/open/tcp//http' scans/alltcp.gnmap | cut -d/ -f1 | paste -sd, -)
echo "HTTP-like ports: $HTTP_PORTS"
```

2) Enumerate HTTP services with Nmap scripts
```
# Run common HTTP scripts (adjust ports if needed)
[ -n "$HTTP_PORTS" ] && nmap -p $HTTP_PORTS -sC -sV \
  --script http-title,http-headers,http-methods,http-robots.txt,http-server-header,http-security-headers,http-enum,http-auth,http-vhosts \
  -oA scans/nmap-http $IP
```

3) Quick manual banner grabs (HTTP/1.1 requires Host header)
```
# Port 80 (HTTP)
curl -sI http://$IP/ | sed -n '1,20p'
printf "HEAD / HTTP/1.1\r\nHost: $IP\r\nConnection: close\r\n\r\n" | nc -nv $IP 80

# Port 443 (HTTPS) — show cert and headers
curl -k -sI https://$IP/ | sed -n '1,20p'
echo | openssl s_client -connect $IP:443 -servername $IP 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

4) Low-hanging files and common endpoints
```
curl -ks http://$IP/robots.txt
curl -ks http://$IP/sitemap.xml
curl -ks http://$IP/server-status
curl -ks http://$IP/phpinfo.php
# If HTTPS:
curl -ks https://$IP/robots.txt
```

5) Technology and WAF detection
```
whatweb -a 3 http://$IP/ | tee scans/whatweb_80.txt
wafw00f http://$IP/ | tee scans/wafw00f_80.txt
# If HTTPS:
whatweb -a 3 https://$IP/ | tee scans/whatweb_443.txt
wafw00f https://$IP/ | tee scans/wafw00f_443.txt
```

6) TLS enumeration (if 443 open)
```
nmap -sV --script ssl-cert,ssl-enum-ciphers -p 443 -oA scans/nmap-tls $IP
# Optional if installed:
# testssl.sh https://$IP:443 | tee scans/testssl.txt
```

7) Content discovery — gobuster and ffuf (HTTP)
```
# Gobuster (directories + common extensions)
gobuster dir -u http://$IP/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt,js,bak,zip,conf \
  -t 50 -o scans/gobuster_80.txt

# ffuf (include useful status codes)
ffuf -u http://$IP/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e .php,.html,.txt,.bak \
  -t 100 -mc 200,204,301,302,307,401,403 \
  -o scans/ffuf_80.json
```

8) Content discovery — HTTPS (if 443)
```
gobuster dir -u https://$IP/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,asp,aspx,jsp \
  -k -t 50 -o scans/gobuster_443.txt

ffuf -u https://$IP/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .php,.html,.txt,.bak,.old \
  -t 100 -mc 200,204,301,302,307,401,403 -k \
  -o scans/ffuf_443.json
```

9) Virtual host enumeration (Host header fuzzing)
```
# Get a baseline response size for a bogus Host:
BASE=$(curl -s -H "Host: notreal" http://$IP/ | wc -c)
echo "Baseline size: $BASE"

# Fuzz subdomains against Host header; filter by size
ffuf -u http://$IP/ -H "Host: FUZZ" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs $BASE -mc 200,301,302,401,403 \
  -o scans/ffuf_vhosts.json

# Add discovered vhost to /etc/hosts (example)
# echo "$IP dev.example.com" | sudo tee -a /etc/hosts
```

10) HTTP methods and WebDAV
```
curl -i -s -X OPTIONS http://$IP/
nmap -p 80,443 --script http-methods,http-webdav-scan -oA scans/nmap-methods $IP
# Optional upload tests if WebDAV appears enabled:
# davtest -url http://$IP/
```

11) Quick vuln/config sweep (noisy; use in labs)
```
nikto -h http://$IP -C all -o scans/nikto_80.txt
# If HTTPS:
nikto -h https://$IP -C all -o scans/nikto_443.txt
```

12) CMS checks (if indicators found)
```
# WordPress example (if WP detected)
# wpscan --url http://$IP/ --enumerate ap,at,tt,u -f cli-no-color | tee scans/wpscan.txt
```

13) Save interesting responses
```
# Save any promising pages for offline review
wget -k -p -nd -P loot http://$IP/
```

## Practical tips
- Always include Host header when speaking HTTP/1.1 manually; many servers won’t respond correctly without it.
- Treat 301/302/401/403 as interesting, not failures; follow redirects (-L in curl) and note protected areas for later auth bypass or brute force (per scope).
- Use multiple wordlists and extensions; try language-specific extensions (php, asp, aspx, jsp).
- For HTTPS-only sites, always use -k in tools if certs are self-signed.
- TLS cert SANs often reveal real domains; enumerate vhosts once you have a domain and add to /etc/hosts.
- Use ffuf’s filters: -fs (size) or -fc (status) to remove noise; get a baseline first.
- Check default endpoints: /admin, /login, /phpinfo.php, /server-status, /manager/html (Tomcat), /jenkins, /console, /setup, /.git/, /backup, /test, /old, /dev.
- Document everything: ports, titles, headers, tech versions, discovered paths, potential creds.
- In exam labs, noisy tools (nikto, wide ffuf) are fine; on real engagements, get permission and consider rate limits.

## Minimal cheat sheet (one-screen flow)
```
export IP=10.10.10.10
mkdir -p scans loot

# Ports
nmap -p- --min-rate 10000 -T4 -oA scans/alltcp $IP
HTTP_PORTS=$(grep -oP '\d+/open/tcp//http' scans/alltcp.gnmap | cut -d/ -f1 | paste -sd, -)

# HTTP enum
[ -n "$HTTP_PORTS" ] && nmap -p $HTTP_PORTS -sC -sV \
  --script http-title,http-headers,http-methods,http-robots.txt,http-server-header,http-security-headers,http-enum,http-auth,http-vhosts \
  -oA scans/nmap-http $IP

# Quick headers
curl -sI http://$IP/ | sed -n '1,20p'
curl -k -sI https://$IP/ | sed -n '1,20p'

# Tech/WAF
whatweb -a 3 http://$IP/ | tee scans/whatweb_80.txt
wafw00f http://$IP/ | tee scans/wafw00f_80.txt

# TLS (if 443)
nmap -sV --script ssl-cert,ssl-enum-ciphers -p 443 -oA scans/nmap-tls $IP

# Low-hanging
curl -ks http://$IP/robots.txt
curl -ks http://$IP/sitemap.xml
curl -ks http://$IP/server-status

# Dir brute
gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,js,bak,zip -t 50 -o scans/gobuster_80.txt
ffuf -u http://$IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .php,.html,.txt,.bak -t 100 -mc 200,204,301,302,307,401,403 -o scans/ffuf_80.json

# Methods/WebDAV
curl -i -s -X OPTIONS http://$IP/
nmap -p 80,443 --script http-methods,http-webdav-scan -oA scans/nmap-methods $IP

# Vhosts (baseline + fuzz)
BASE=$(curl -s -H "Host: notreal" http://$IP/ | wc -c)
ffuf -u http://$IP/ -H "Host: FUZZ" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs $BASE -mc 200,301,302,401,403 -o scans/ffuf_vhosts.json

# Quick vuln scan (lab-safe)
nikto -h http://$IP -C all -o scans/nikto_80.txt
```

## Summary
This module’s focus is a reliable, repeatable process to enumerate web servers: find HTTP services, fingerprint them, pull easy disclosures, and aggressively discover content and vhosts. Use Nmap to map services and run HTTP/TLS scripts; use curl/netcat/openssl for quick headers and certs; identify technologies with whatweb and nikto; then brute-force directories and vhosts with gobuster/ffuf. Check methods/WebDAV and note any admin or login endpoints for later exploitation. The output should be a clean list of ports, tech stacks, discovered paths, and candidate attack surfaces to drive the next phase.