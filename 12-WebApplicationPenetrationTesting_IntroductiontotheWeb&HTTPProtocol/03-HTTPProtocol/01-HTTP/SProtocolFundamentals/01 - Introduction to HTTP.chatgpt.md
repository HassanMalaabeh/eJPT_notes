# 01 - Introduction to HTTP (SProtocolFundamentals)

Note: No transcript was provided. The following summary is inferred conservatively from the filename/context and aligned with typical eJPT “HTTP fundamentals” content. Commands and flags are industry-standard and copy-paste ready.

## What the video covers (Introduction / big picture)
- What HTTP is: a stateless, text-based application protocol over TCP (default ports 80 for HTTP, 443 for HTTPS).
- Request/response model and message anatomy.
- URL structure and the role of the Host header/virtual hosts.
- Common methods, status codes, and headers.
- Cookies and sessions at a high level.
- HTTPS basics (TLS, SNI, certs) and how it changes inspection.
- Practical inspection and manual interaction with HTTP using curl, netcat, OpenSSL, tcpdump/Wireshark, and brief nmap HTTP enumeration.
- How these fundamentals support eJPT tasks: identification, enumeration, baseline testing, and preparing for deeper web exploitation.

## Flow (ordered)
1. HTTP vs HTTPS and where they live in the network stack (TCP/80,443).
2. URL anatomy: scheme://host:port/path?query#fragment (fragment stays client-side).
3. HTTP message structure:
   - Request line: METHOD SP PATH SP HTTP/version CRLF
   - Headers (Host required in HTTP/1.1), blank line, optional body
   - Response line: HTTP/version SP status-code SP reason, headers, blank line, optional body
4. Common methods: GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH.
5. Status codes: 1xx, 2xx, 3xx, 4xx, 5xx (typical examples for pentesting).
6. Headers you’ll constantly see: Host, User-Agent, Accept, Content-Type, Content-Length, Authorization, Cookie/Set-Cookie, Location, Referer, Origin, Connection.
7. Cookies/sessions: server state via Set-Cookie/Cookie; basic auth vs session cookies.
8. HTTPS: TLS handshake, certificates, SNI, practical limitations for cleartext sniffing.
9. Tooling demos: curl (all-purpose), nc/openssl (raw requests), nmap (http-* scripts), tcpdump/Wireshark (capture/filters), Burp proxy basics.
10. Quick lab tasks: grab headers/body, follow redirects, view robots.txt, craft a raw request, observe in a sniffer, test POST.

## Tools highlighted
- curl (primary CLI HTTP client)
- netcat (nc) for raw HTTP/1.1 requests
- OpenSSL s_client for raw HTTPS
- nmap with HTTP NSE scripts for light enumeration
- tcpdump and Wireshark for traffic capture/analysis
- Browser DevTools and/or Burp Suite (HTTP proxy)
- Python’s simple HTTP server for quick local testing

## Typical command walkthrough (detailed, copy-paste friendly)

Set a couple of variables to reuse:
```bash
export TARGET_IP=10.10.10.10
export TARGET_HOST=example.com   # If a vhost/FQDN is known; else leave blank or use IP
```

1) Identify HTTP/HTTPS and versions
```bash
nmap -sV -Pn -p80,443 --script http-title,http-headers,http-methods,http-server-header,http-robots.txt $TARGET_IP
```

2) Basic GET and headers with curl
```bash
# GET body, show status and timing
curl -s -o /dev/null -w "HTTP %{http_code} in %{time_total}s\n" http://$TARGET_IP/

# Show headers only (server banner, cookies, redirects)
curl -I http://$TARGET_IP/

# Verbose (request + response headers)
curl -v http://$TARGET_IP/ 2>&1 | sed -n '1,80p'
```

3) Follow redirects, save headers and body
```bash
curl -L -D headers.txt -o index.html http://$TARGET_IP/
```

4) Specify Host header (virtual hosting)
```bash
# If the site expects a name, force it via Host (and optionally /etc/hosts)
curl -H "Host: $TARGET_HOST" http://$TARGET_IP/

# Add a hosts entry (needs sudo)
echo "$TARGET_IP $TARGET_HOST" | sudo tee -a /etc/hosts
curl http://$TARGET_HOST/
```

5) HEAD, OPTIONS, and method probing
```bash
curl -I http://$TARGET_HOST/
curl -X OPTIONS -i http://$TARGET_HOST/
curl -X PUT -i http://$TARGET_HOST/test.txt -d 'hello'    # Expect 405/403 on many servers
```

6) robots.txt, common files
```bash
curl -i http://$TARGET_HOST/robots.txt
curl -i http://$TARGET_HOST/.well-known/security.txt
```

7) POST form data and JSON
```bash
# application/x-www-form-urlencoded
curl -i -X POST http://$TARGET_HOST/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=admin&password=admin'

# application/json
curl -i -X POST http://$TARGET_HOST/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'
```

8) Cookies
```bash
# Save cookies set by server
curl -c cookies.txt -i http://$TARGET_HOST/

# Reuse cookies in subsequent requests
curl -b cookies.txt -i http://$TARGET_HOST/account
```

9) Basic Authentication
```bash
# With curl
curl -u 'user:pass' -i http://$TARGET_HOST/secure

# Manual header (user:pass base64)
printf 'user:pass' | base64
# Use result, e.g. dXNlcjpwYXNz
curl -i http://$TARGET_HOST/secure -H 'Authorization: Basic dXNlcjpwYXNz'
```

10) Control encoding and HTTP versions
```bash
# Avoid compressed content for easier inspection
curl --compressed -I https://$TARGET_HOST/        # negotiate gzip
curl -H 'Accept-Encoding: identity' -I https://$TARGET_HOST/  # request uncompressed

# Force protocol version for testing
curl --http1.0 -I http://$TARGET_HOST/
curl --http2 -I https://$TARGET_HOST/
```

11) Proxy through Burp (127.0.0.1:8080 by default)
```bash
# One-off
curl -x http://127.0.0.1:8080 -k -I https://$TARGET_HOST/

# Environment for many tools
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
# Unset when done
unset http_proxy https_proxy
```

12) Manual raw HTTP with netcat (HTTP/1.1 requires Host)
```bash
# Plain HTTP
printf 'GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: nc-test\r\nConnection: close\r\n\r\n' "$TARGET_HOST" | nc -nv $TARGET_IP 80

# If using the hostname directly (DNS resolves)
printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$TARGET_HOST" | nc -nv $TARGET_HOST 80
```

13) Manual raw HTTPS with OpenSSL
```bash
# Fetch and print response; -servername sets SNI
printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$TARGET_HOST" | \
openssl s_client -connect $TARGET_HOST:443 -servername $TARGET_HOST -quiet

# View certificate chain/banners
openssl s_client -showcerts -connect $TARGET_HOST:443 -servername $TARGET_HOST </dev/null
```

14) Sniff HTTP traffic (cleartext)
```bash
# ASCII dump of HTTP on port 80 to/from target
sudo tcpdump -A -s0 -nn port 80 and host $TARGET_IP

# Wireshark display filters
#   http
#   http.request.method == "POST"
#   http.host contains "example"
#   tcp.port == 80
```

15) Quick local server for testing
```bash
# Python 3 simple server (serves current dir)
python3 -m http.server 8000

# Or for uploads (SimpleHTTPServerWithUpload alternatives exist, but basic server is read-only)
```

16) Handy curl extras
```bash
# Print only HTTP code
curl -s -o /dev/null -w "%{http_code}\n" http://$TARGET_HOST/

# Save response headers separately
curl -D headers.txt -o /dev/null http://$TARGET_HOST/

# Follow redirects and show each hop
curl -L -v -o /dev/null http://$TARGET_HOST/ 2>&1 | sed -n '1,120p'
```

## Practical tips
- Always include Host for HTTP/1.1; many servers rely on it for virtual hosting.
- Use Connection: close in raw requests to avoid hanging sockets when testing with nc/openssl.
- There must be a blank line between headers and the body; lines end with CRLF (\r\n) in raw requests.
- HTTPS hides payload from sniffers; capture at the proxy or client if you need visibility (e.g., Burp, curl -x).
- Prefer -I or -X HEAD to quickly check availability and headers without large bodies.
- Use -L to follow redirects; inspect Location for potential vhost/HTTPS enforcement.
- If content appears garbled, it may be compressed; request identity encoding or use curl --compressed to auto-decompress.
- For vhost-only sites on an IP lab box, add an /etc/hosts entry mapping IP to the expected hostname.
- Don’t rely on Server headers for exact tech fingerprints; they’re easy to change. Confirm with multiple signals (responses, files, behavior).
- 401 with WWW-Authenticate indicates Basic/Digest; 403 often indicates access control; 405 indicates method disabled.

## Minimal cheat sheet (one-screen flow)
- Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH
- Status: 200 OK, 301/302 Redirect, 307/308 Strict Redirect, 401 Unauthorized, 403 Forbidden, 404 Not Found, 405 Method Not Allowed, 500 Server Error
- Key headers:
  - Request: Host, User-Agent, Accept, Accept-Language, Accept-Encoding, Content-Type, Content-Length, Authorization, Cookie, Referer, Origin, Connection
  - Response: Server, Set-Cookie, Location, Content-Type, Content-Length, Date
- Quick enum:
```bash
nmap -sV -p80,443 --script http-title,http-headers,http-methods,http-robots.txt $TARGET_IP
curl -I http://$TARGET_IP/
curl -L -D - http://$TARGET_HOST/ -o /dev/null
curl -H "Host: $TARGET_HOST" http://$TARGET_IP/robots.txt
```
- Manual request:
```bash
printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$TARGET_HOST" | nc -nv $TARGET_IP 80
printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$TARGET_HOST" | \
openssl s_client -connect $TARGET_HOST:443 -servername $TARGET_HOST -quiet
```
- POSTs:
```bash
curl -i -X POST http://$TARGET_HOST/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'u=admin&p=admin'
curl -i -X POST http://$TARGET_HOST/api \
  -H 'Content-Type: application/json' \
  -d '{"a":1}'
```
- Cookies/auth:
```bash
curl -c c.txt -i http://$TARGET_HOST/
curl -b c.txt -i http://$TARGET_HOST/account
curl -u 'user:pass' -I http://$TARGET_HOST/secure
```

## Summary
This introduction establishes HTTP fundamentals crucial for eJPT work: understanding the request/response format, methods, headers, cookies, and status codes; appreciating the differences introduced by HTTPS; and building muscle memory with curl, nc, openssl, nmap, and sniffers. With these basics, you can reliably identify and enumerate web services, craft and inspect requests manually, follow redirects, handle authentication and cookies, and prepare for deeper web application testing in later modules.