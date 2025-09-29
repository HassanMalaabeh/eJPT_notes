# HTTP Basics Lab — Part 2 (eJPT SProtocolFundamentals)

Note: The transcript for “09 - HTTP Basics Lab - Part 2.mp4” is not provided. The notes below conservatively infer typical eJPT HTTP Basics lab content: hands-on HTTP/1.1 requests, headers, methods (GET/HEAD/POST), status codes, cookies, Basic Auth, redirects, and HTTPS checks using curl, netcat, and OpenSSL.

## What the video covers (Introduction / big picture)
- Deepening HTTP fundamentals with hands-on request crafting and analysis.
- Reading and writing raw HTTP/1.1:
  - Start line, headers, CRLF line endings, body.
  - Mandatory Host header in HTTP/1.1.
- Using command-line tools to interact with web servers:
  - curl for quick inspection and automation.
  - netcat (nc) for raw requests.
  - openssl s_client to inspect TLS/HTTPS.
- Demonstrating common methods and behaviors:
  - GET, HEAD, POST.
  - Status codes (200/301/302/401/403/404/500).
  - Basic Authentication, cookies/sessions, redirects.
- Practical enumeration targets: /, /robots.txt, headers, vhosts.

## Flow (ordered)
1. Confirm HTTP/HTTPS services and banners (nmap quick check).
2. Fetch a page with curl and observe verbose request/response.
3. Craft a raw HTTP/1.1 GET via netcat; emphasize CRLF and Host header.
4. Use HEAD to retrieve only headers; note Content-Length and server details.
5. Enumerate common paths: /robots.txt and others.
6. Perform POST with application/x-www-form-urlencoded (curl and raw).
7. Trigger and satisfy HTTP Basic Auth (401 then curl -u).
8. Capture and reuse cookies for authenticated endpoints.
9. Handle redirects (3xx) and follow with -L.
10. Check HTTPS/TLS with openssl s_client; fetch with curl -k if needed.
11. Optional: Probe allowed methods via OPTIONS.

## Tools highlighted
- curl: Flexible HTTP client (verbose, headers-only, POST, auth, cookies, redirects).
- netcat (nc): Send raw HTTP; see exact server responses.
- openssl s_client: Inspect TLS, SNI, certificate details.
- nmap (quick service check): Identify ports/services before testing.
- Optional: Wireshark/tcpdump for packet-level visibility.

## Typical command walkthrough (detailed, copy-paste friendly)

Set target variables:
```bash
# Set these to match your lab
HOST=10.10.10.10
PORT_HTTP=80
PORT_HTTPS=443
BASEURL="http://$HOST"
```

0) Discover service quickly:
```bash
nmap -sS -sV -Pn -p $PORT_HTTP,$PORT_HTTPS $HOST
```

1) Basic GET with curl (show request/response details):
```bash
curl -v "$BASEURL/"
```

2) Raw HTTP/1.1 GET with netcat (note CRLF and Host):
```bash
printf 'GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: nc-test\r\nConnection: close\r\n\r\n' "$HOST" | nc -nv $HOST $PORT_HTTP
```

3) HEAD request (headers only):
```bash
# Headers only (server, content-type, content-length, cookies, etc.)
curl -I "$BASEURL/"

# Or explicitly send HEAD
curl -i -X HEAD "$BASEURL/"
```

4) Enumerate simple paths:
```bash
curl -s "$BASEURL/robots.txt" | sed -n '1,120p'
curl -s "$BASEURL/favicon.ico" > favicon.ico
curl -s "$BASEURL/" -o index.html
```

5) POST form (application/x-www-form-urlencoded) with curl:
```bash
curl -i -X POST "$BASEURL/login" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'user=alice&pass=secret'

# If you need URL-encoding for values with spaces or symbols:
curl -i -X POST "$BASEURL/search" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'q=a b c'
```

6) Raw POST with netcat (compute Content-Length):
```bash
DATA='user=alice&pass=secret'
LEN=$(printf %s "$DATA" | wc -c)

printf 'POST /login HTTP/1.1\r\nHost: %s\r\nUser-Agent: nc-test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
  "$HOST" "$LEN" "$DATA" | nc -nv $HOST $PORT_HTTP
```

7) Basic Auth (observe 401 then authenticate):
```bash
# Expect 401 Unauthorized with a WWW-Authenticate header
curl -i "$BASEURL/protected"

# Provide credentials
curl -i -u admin:admin "$BASEURL/protected"
```

8) Cookies and session handling:
```bash
# Login and store cookies
curl -i -c cookies.txt -X POST "$BASEURL/login" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'user=alice&pass=secret'

# Use stored cookies to access authenticated page
curl -i -b cookies.txt "$BASEURL/dashboard"
```

9) Redirects:
```bash
# See the 3xx Location header
curl -i "$BASEURL/redirect"

# Follow redirects automatically
curl -i -L "$BASEURL/redirect"
```

10) Virtual host testing (if IP hosts multiple sites):
```bash
# HTTP vhost via Host header
curl -v -H "Host: vhost.local" "http://$HOST/"

# Raw with nc
printf 'GET / HTTP/1.1\r\nHost: vhost.local\r\nConnection: close\r\n\r\n' | nc -nv $HOST $PORT_HTTP
```

11) HTTPS/TLS checks:
```bash
# TLS handshake, SNI, and certificate summary
openssl s_client -connect "$HOST:$PORT_HTTPS" -servername "$HOST" -brief < /dev/null

# Fetch via HTTPS (ignore certificate errors in labs)
curl -vk "https://$HOST/"
```

12) Methods allowed (OPTIONS):
```bash
curl -i -X OPTIONS "$BASEURL/"
```

13) HTTP/1.0 vs HTTP/1.1 (Host header behavior):
```bash
# Many servers still reply, but Host is not required in 1.0
printf 'GET / HTTP/1.0\r\n\r\n' | nc -nv $HOST $PORT_HTTP

# Missing Host in 1.1 often yields 400 Bad Request
printf 'GET / HTTP/1.1\r\n\r\n' | nc -nv $HOST $PORT_HTTP
```

## Practical tips
- Always send CRLF line endings in raw requests: each header ends with \r\n and a blank \r\n line before the body.
- In HTTP/1.1, include Host and often Connection: close for clean netcat tests.
- For raw POSTs, ensure Content-Length matches the exact byte count of the body.
- Use curl -v to see the full handshake, request line, and response headers.
- Save and reuse session cookies with -c and -b; this avoids reauthenticating.
- Follow redirects (-L) when you expect login or directory index handoffs.
- For self-signed HTTPS in labs, use curl -k and openssl s_client to inspect cert/SNI.
- Probe vhosts by setting Host in HTTP requests when hitting an IP directly.
- HEAD (-I) is fast for header discovery; good for banner/content-type and content-length checks.
- If a server hangs on raw requests, add Connection: close or ensure you send the terminating blank line.

## Minimal cheat sheet (one-screen flow)
```bash
# Setup
HOST=10.10.10.10; BASEURL="http://$HOST"

# Quick service check
nmap -sS -sV -Pn -p 80,443 $HOST

# Verbose GET
curl -v "$BASEURL/"

# Raw GET (HTTP/1.1)
printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$HOST" | nc -nv $HOST 80

# Headers only
curl -I "$BASEURL/"

# Enumerate
curl -s "$BASEURL/robots.txt"

# POST (form)
curl -i -X POST "$BASEURL/login" -H 'Content-Type: application/x-www-form-urlencoded' --data 'user=alice&pass=secret'

# Cookies
curl -i -c cookies.txt -X POST "$BASEURL/login" -H 'Content-Type: application/x-www-form-urlencoded' --data 'user=alice&pass=secret'
curl -i -b cookies.txt "$BASEURL/dashboard"

# Basic Auth
curl -i "$BASEURL/protected"
curl -i -u admin:admin "$BASEURL/protected"

# Redirects
curl -i "$BASEURL/redirect"
curl -i -L "$BASEURL/redirect"

# HTTPS check
openssl s_client -connect "$HOST:443" -servername "$HOST" -brief < /dev/null
curl -vk "https://$HOST/"
```

## Summary
This lab segment reinforces HTTP protocol fundamentals by manually crafting and inspecting HTTP/1.1 traffic. You learn how to:
- Build raw GET/HEAD/POST requests and interpret responses, including status codes and headers.
- Provide essential headers (Host, Content-Type, Content-Length, Connection) and correct CRLF formatting.
- Handle Basic Auth challenges, manage cookies/sessions, and follow redirects.
- Verify HTTPS/TLS characteristics and fetch over TLS when certificates aren’t trusted in lab settings.
The workflow prepares you to confidently enumerate, interact with, and script against web services in eJPT-style assessments.