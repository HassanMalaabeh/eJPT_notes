# 06 - HTTP Responses (SProtocolFundamentals)

Note: No transcript was provided. The summary below is inferred conservatively from the filename/context of an eJPT “Protocol Fundamentals” module. It reflects standard HTTP response fundamentals and typical eJPT workflows.

## What the video covers (Introduction / big picture)
- How HTTP responses are structured and interpreted during reconnaissance and testing.
- Status line (protocol/version, status code, reason phrase), headers, blank line, and optional message body.
- Status code classes (1xx–5xx) and the most common codes relevant to testing.
- Key response headers that reveal technology, behavior, and potential misconfigurations (Server, Set-Cookie, Location, Content-Type, Content-Length, Transfer-Encoding, Cache-Control, etc.).
- Differences you’ll see when inspecting HTTP/1.1 vs HTTP/2/3 (at the wire and in tools).
- Practical inspection with curl, netcat/openssl, browser devtools, Burp, and Wireshark.
- How specific responses guide next steps in enumeration and exploitation.

## Flow (ordered)
1. HTTP request/response recap (client sends request; server returns response).
2. The status line: HTTP/1.1 200 OK (version, code, reason).
3. Status codes:
   - 1xx informational
   - 2xx success (200, 204, 206)
   - 3xx redirection (301, 302, 303, 307, 308, 304)
   - 4xx client errors (400, 401, 403, 404, 405, 429)
   - 5xx server errors (500, 501, 502, 503, 504)
4. Response headers:
   - Server identity: Server, X-Powered-By
   - Content metadata: Content-Type, Content-Length, Content-Encoding
   - Transfer: Transfer-Encoding: chunked, Connection: keep-alive/close
   - Caching: Cache-Control, Expires, ETag, Last-Modified
   - Redirects: Location
   - Cookies: Set-Cookie (Secure, HttpOnly, SameSite)
   - Security headers: HSTS, CSP, X-Frame-Options, etc.
5. Body and encodings (HTML/JSON/binary; gzip; chunked).
6. HTTP/1.1 line endings and header parsing (CRLF, blank line).
7. Observing responses with tools (curl, nc/openssl, browser devtools, Burp, Wireshark).
8. Using responses to drive testing (auth challenges, redirects, caching behavior, error handling).
9. Quick demos: manual GET, follow redirects, provoke 401/403/404/500, partial content, ETag/304.

## Tools highlighted
- curl (quick inspection, headers, redirects, auth, compression)
- nc/ncat or telnet (raw HTTP over TCP)
- openssl s_client (raw HTTP over TLS)
- Browser DevTools (Network tab)
- Burp Suite (Proxy/Repeater to inspect/modify responses)
- Wireshark (packet-level HTTP response analysis)

## Typical command walkthrough (detailed, copy-paste friendly)

Replace TARGET and HOST as needed; httpbin.org is used here for predictable demo responses.

1) Manual HTTP/1.1 GET (plain HTTP, see raw response)
```bash
# Basic GET with Host header (HTTP/1.1 requires Host)
printf "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n" | nc -nv example.com 80
```

2) Manual HTTPS GET with TLS
```bash
# SNI is important for virtual hosts
printf "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n" | \
openssl s_client -connect example.com:443 -servername example.com -quiet
```

3) Include response headers with curl (-i) and show verbose (-v)
```bash
# Full response (headers + body)
curl -i http://example.com/

# Verbose (shows request/response exchange)
curl -v http://example.com/
```

4) HEAD requests and saving headers
```bash
# Only headers
curl -I http://example.com/

# Save headers to a file
curl -sD headers.txt -o /dev/null http://example.com/
```

5) Follow redirects and inspect the chain
```bash
# Show redirect chain headers
curl -IL http://httpbin.org/redirect/3

# Follow redirects and get final body
curl -L http://httpbin.org/redirect/3
```

6) Trigger common status codes (httpbin)
```bash
# 200 OK
curl -i http://httpbin.org/status/200

# 301 Moved Permanently (Location header)
curl -i http://httpbin.org/redirect-to?url=https://example.com

# 304 Not Modified via ETag (2-step)
curl -sD - http://httpbin.org/etag/test | tee etag_headers.txt
# Extract ETag value and reuse it
ETAG=$(grep -i ^ETag: etag_headers.txt | cut -d' ' -f2- | tr -d '\r')
curl -I -H "If-None-Match: $ETAG" http://httpbin.org/etag/test

# 401 Unauthorized then 200 with Basic auth
curl -i http://httpbin.org/basic-auth/user/passwd
curl -i -u user:passwd http://httpbin.org/basic-auth/user/passwd

# 403 Forbidden
curl -i http://httpbin.org/status/403

# 404 Not Found
curl -i http://httpbin.org/status/404

# 405 Method Not Allowed (POST to a GET-only endpoint)
curl -i -X POST http://httpbin.org/get

# 429 Too Many Requests (rate limited)
curl -i http://httpbin.org/status/429

# 500 Internal Server Error
curl -i http://httpbin.org/status/500
```

7) Content negotiation and compression
```bash
# Ask server to compress (Accept-Encoding) and observe Content-Encoding
curl -I --compressed http://example.com/

# Force HTTP/1.0 vs HTTP/1.1 (affects Connection, caching semantics)
curl --http1.0 -I http://example.com/
curl --http1.1 -I http://example.com/
```

8) Transfer and length semantics
```bash
# Look for Content-Length or Transfer-Encoding: chunked
curl -I http://example.com/

# Download first N bytes (Range => 206 Partial Content)
curl -i -H "Range: bytes=0-99" http://httpbin.org/range/1024
```

9) Cookies in responses (Set-Cookie) and persistence
```bash
# Observe Set-Cookie
curl -i "http://httpbin.org/cookies/set?session=abc123"

# Save and reuse cookies
curl -c cookies.txt -b cookies.txt -i "http://httpbin.org/cookies/set?flag=test"
curl -b cookies.txt -i http://httpbin.org/cookies
```

10) Inspect redirects and Location header targets
```bash
curl -sI http://example.com | grep -i '^HTTP\|^Location\|^Server\|^Set-Cookie'
```

11) TLS certificate plus response peek
```bash
# Show cert chain and then request; helpful for vhosts/misconfig
openssl s_client -connect example.com:443 -servername example.com < /dev/null
```

12) Wireshark quick filters (for reference)
- Basic display filters:
  - http
  - http.response
  - http.response.code == 200
  - tcp.port == 80 or tls
- Follow TCP Stream to see raw response with headers/body.

## Practical tips
- The status line sets the context: 3xx means follow the Location; 4xx/5xx often leak info. 500s can reveal stack traces or frameworks—note them for later exploitation.
- Headers are gold:
  - Server/X-Powered-By can hint at versions and frameworks (enumeration pivot).
  - Set-Cookie flags (Secure, HttpOnly, SameSite) inform session handling security.
  - Location helps identify redirect logic and possible open redirect issues.
  - Cache-Control/ETag/Last-Modified reveal caching rules (can impact auth/cross-tenant data exposure).
  - Content-Type mismatches may indicate misconfig leading to XSS or file execution issues.
  - Content-Length vs Transfer-Encoding: chunked identifies how body is delivered; be aware in request smuggling contexts (advanced).
- Always send an explicit Host header when testing HTTP/1.1; virtual hosting is common.
- Use curl -i/-v during recon so you don’t miss crucial headers.
- Test with and without TLS; some misconfigs only show on one side (e.g., different upstreams).
- For 401/407, look for WWW-Authenticate/Proxy-Authenticate schemes; try Basic/Digest/NTLM as context allows.
- For 304 workflows, capture ETag/Last-Modified and replay with If-None-Match/If-Modified-Since to understand caching.
- When you see compression (Content-Encoding: gzip), some tools auto-decompress; if you need raw, save with -sS --raw or via nc.
- Note security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options). Absence or misconfiguration can be reported.
- Redirect chains crossing schemes or domains may indicate policy issues; verify -L path and final destination carefully.

## Minimal cheat sheet (one-screen flow)
- Full response quickly:
  - curl -i http://TARGET/
  - curl -v http://TARGET/
- Only headers / save:
  - curl -I http://TARGET/
  - curl -sD - -o /dev/null http://TARGET/
- Follow redirects:
  - curl -IL http://TARGET/
  - curl -L http://TARGET/
- Auth probe:
  - curl -i http://TARGET/protected
  - curl -i -u user:pass http://TARGET/protected
- Compression / protocol:
  - curl -I --compressed http://TARGET/
  - curl --http1.0 -I http://TARGET/
- Partial content:
  - curl -i -H "Range: bytes=0-99" http://TARGET/path
- Manual raw:
  - printf "GET / HTTP/1.1\r\nHost: TARGET\r\nConnection: close\r\n\r\n" | nc -nv TARGET 80
  - printf "GET / HTTP/1.1\r\nHost: TARGET\r\nConnection: close\r\n\r\n" | openssl s_client -connect TARGET:443 -servername TARGET -quiet

## Summary
This lesson explains how to read and leverage HTTP responses during assessment: parse the status line, interpret status codes, and mine headers for technology hints, session behavior, redirects, caching, and security posture. You practice observing raw responses over TCP/TLS, using curl for headers/redirects/auth/compression, and validating behavior in Burp/DevTools/Wireshark. Mastery of response semantics helps you pivot efficiently in recon, identify misconfigurations, and prioritize attack paths on the eJPT.