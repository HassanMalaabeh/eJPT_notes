# 03 - HTTP Requests - Part 1 (eJPT Study Notes)

Note: No transcript was provided. The following summary is inferred conservatively from the filename and SProtocolFundamentals context. Examples and commands reflect common eJPT-relevant practice for learning HTTP request fundamentals.

## What the video covers (Introduction / big picture)
- Core anatomy of an HTTP request and how clients talk to web servers over TCP.
- Request line, headers, blank line, and optional body (HTTP/1.1).
- Common methods (GET, POST, HEAD, OPTIONS) and when they are used.
- How to craft, send, and inspect HTTP requests using CLI tools and intercepting proxies.
- Practical handling of Host, Content-Type, Content-Length, and other key headers.
- Building raw requests by hand to demystify what tools like browsers and Burp send.

## Flow (ordered)
1. HTTP overview: stateless, application-layer over TCP (80) and TLS (443).
2. URL/URI anatomy: scheme://host:port/path?query#fragment.
3. Request message structure:
   - Request line: METHOD SP URI SP HTTP/version CRLF
   - Headers (each ends with CRLF)
   - Blank line (CRLF)
   - Optional body
4. Essential headers in requests:
   - Host (required in HTTP/1.1), User-Agent, Accept*, Connection, Referer, Origin, Cookie, Authorization, Content-Type, Content-Length.
5. Methods basics:
   - GET (no body; query in URL), POST (body), HEAD (headers only), OPTIONS (capabilities).
6. Build a raw HTTP/1.1 request by hand; importance of CRLF and Content-Length.
7. Use curl for reproducible requests; add/override headers; send data; follow redirects; auth.
8. HTTPS considerations: certificate warnings, SNI, using openssl/ncat for raw TLS requests.
9. Inspect traffic with Burp and Wireshark; proxying curl through Burp for interception.

## Tools highlighted
- curl (compose and test requests, auth, headers, proxying)
- netcat/nc or telnet (plain TCP to craft raw HTTP/1.1)
- openssl s_client or ncat --ssl (raw HTTPS with correct SNI)
- Burp Suite (intercept/modify/replay requests)
- Browser DevTools Network tab (view exact requests)
- Wireshark (capture and filter HTTP/TLS traffic)

## Typical command walkthrough (detailed, copy-paste friendly)

Raw HTTP by hand (HTTP/1.1 requires CRLF and Host):

Plain HTTP (port 80) with netcat:
```
printf 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' | nc -nv example.com 80
```

Plain HTTP with OpenBSD nc (auto CRLF on -C when typing interactively):
```
nc -C -nv example.com 80
# Then type (press Enter after each line, and press Enter twice at the end):
# GET / HTTP/1.1
# Host: example.com
# Connection: close
#
```

HTTPS with SNI using OpenSSL:
```
printf 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' \
| openssl s_client -connect example.com:443 -servername example.com -quiet
```

HTTPS with Ncat (often easier):
```
printf 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' \
| ncat --ssl example.com 443
```

Compute and send a POST body manually (Content-Length must match bytes in body):
```
body='user=admin&pass=123456'
len=$(printf %s "$body" | wc -c)
{
  printf 'POST /login HTTP/1.1\r\n'
  printf 'Host: target.local\r\n'
  printf 'Content-Type: application/x-www-form-urlencoded\r\n'
  printf 'Content-Length: %s\r\n' "$len"
  printf 'Connection: close\r\n'
  printf '\r\n'
  printf '%s' "$body"
} | nc -nv target.local 80
```

Curl basics (inspect, headers, methods):
```
# Verbose GET with response headers
curl -v http://example.com/

# Only response headers (HEAD request)
curl -I http://example.com/

# Follow redirects
curl -L http://example.com/

# Ignore TLS certificate warnings (lab self-signed)
curl -vk https://example.com/
```

Set headers and query parameters:
```
# Set Host when hitting an IP hosting multiple vhosts
curl -v -H 'Host: app.target' http://10.10.10.10/

# GET with query parameters
curl -G -d 'q=test&lang=en' http://example.com/search

# Ensure proper URL encoding of special characters
curl -G --data-urlencode 'q=red team & blue' http://example.com/search
```

POST forms and JSON:
```
# application/x-www-form-urlencoded
curl -v -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin&password=admin123' http://target.local/login

# JSON body
curl -v -X POST -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' http://target.local/api/login
```

Cookies and auth:
```
# Send cookie
curl -v -b 'PHPSESSID=abcdef1234567890' http://target.local/dashboard

# Save and reuse cookies
curl -c cookies.txt -v http://target.local/
curl -b cookies.txt -v http://target.local/profile

# HTTP Basic Auth
curl -v -u admin:admin123 http://target.local/protected
```

Proxies and interception (Burp at 127.0.0.1:8080):
```
# Proxy HTTP through Burp
curl -v -x http://127.0.0.1:8080 http://target.local/

# Proxy HTTPS through Burp and ignore cert pinning in curl
curl -v -x http://127.0.0.1:8080 -k https://target.local/
```

Capture and analyze:
```
# Save response headers to file, body to file
curl -sS -D headers.txt -o body.bin http://target.local/

# Wireshark filter (HTTP over 80)
#   http or tcp.port == 80
# TLS SNI (to spot host)
#   tls.handshake.extensions_server_name == "example.com"
```

Referer/Origin/User-Agent manipulation:
```
curl -v -H 'Referer: http://target.local/from' \
       -H 'Origin: http://target.local' \
       -A 'Mozilla/5.0 (X11; Linux x86_64) eJPT-Lab' \
       http://target.local/
```

OPTIONS and allowed methods:
```
curl -v -X OPTIONS http://target.local/resource -H 'Access-Control-Request-Method: POST' -H 'Origin: http://example.com'
```

## Practical tips
- Always include Host for HTTP/1.1; without it, virtual-hosted servers may respond incorrectly.
- Use Connection: close in raw requests to make servers close the socket after response (prevents nc hangs).
- CRLF matters: each header line ends with \r\n, followed by a blank line (\r\n) before any body.
- If you craft a POST manually, Content-Length must equal the exact byte length of the body.
- Use curl -k against lab/self-signed TLS; real-world targets should validate certificates.
- Prefer printf over echo for precise control of newlines and no escape ambiguity.
- For HTTPS raw testing, include -servername in openssl s_client to set SNI to the Host.
- URL-encode special characters in URLs and form bodies; use curl --data-urlencode when unsure.
- Quickly discover behavior:
  - curl -I for headers
  - curl -L to follow redirects
  - curl -v to see request/response
- Interception workflow: configure browser or curl to use Burp, reproduce actions, then Repeater to modify and replay.
- When hitting an IP, set Host header to the intended vhost; this often reveals different apps.
- Know common content types you’ll see: application/x-www-form-urlencoded, multipart/form-data, application/json.

## Minimal cheat sheet (one-screen flow)
```
# GET
curl -v http://host/               # verbose
curl -I http://host/               # HEAD only
curl -G -d 'k=v' http://host/path  # query params

# POST
curl -v -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'u=admin&p=pass' http://host/login
curl -v -X POST -H 'Content-Type: application/json' \
  -d '{"u":"admin","p":"pass"}' http://host/api

# Headers / cookies / auth
curl -v -H 'Host: vhost' -H 'Referer: http://host/' -A 'UA' http://ip/
curl -v -b 'SID=abc123' http://host/
curl -v -u user:pass http://host/protected

# HTTPS / proxy
curl -vk https://host/                             # ignore cert
curl -v -x http://127.0.0.1:8080 http://host/      # proxy via Burp
curl -vk -x http://127.0.0.1:8080 https://host/

# Raw HTTP (plain)
printf 'GET / HTTP/1.1\r\nHost: host\r\nConnection: close\r\n\r\n' | nc -nv host 80

# Raw HTTPS (SNI)
printf 'GET / HTTP/1.1\r\nHost: host\r\nConnection: close\r\n\r\n' \
| openssl s_client -connect host:443 -servername host -quiet
```

## Summary
- HTTP requests consist of a method, target (path/URI), version, headers, a blank line, and an optional body.
- HTTP/1.1 requires the Host header; correct CRLF formatting and accurate Content-Length are critical when crafting by hand.
- Use curl for fast, precise request construction and inspection; leverage Burp for interception and manipulation.
- For raw understanding, practice sending minimal GET/POST requests via nc/openssl and compare with browser/Burp traffic.
- Mastery of GET vs POST, headers, and body formats is foundational for the eJPT and sets up later modules on responses, cookies, and web attacks.