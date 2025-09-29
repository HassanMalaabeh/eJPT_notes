# What the video covers (Introduction / big picture)

No transcript was provided. Based on the filename “04 - HTTP Requests - Part 2” in SProtocolFundamentals, this video likely continues from Part 1 by deepening HTTP request knowledge used in eJPT labs:
- Recap of HTTP request anatomy (request line, headers, body).
- Practical differences: GET vs POST vs other verbs; idempotency and safety.
- Request bodies and encodings: application/x-www-form-urlencoded, JSON, multipart/form-data (file uploads), URL encoding.
- Core headers: Host, User-Agent, Referer, Cookie, Content-Type, Content-Length, Accept, Accept-Encoding, Connection, Authorization.
- Sessions, cookies, and auth (Basic/Bearer).
- Redirects, content negotiation, caching, and conditional requests (ETag, If-Modified-Since).
- Crafting and inspecting raw requests with netcat/OpenSSL; using curl/Burp.
- Common security-relevant behaviors (host header manipulation, proxying, custom headers).

Where specific command flags/paths are uncertain, they are inferred conservatively from standard practice.


# Flow (ordered)

1. Quick recap of HTTP request structure and the request line.
2. GET request dissection and essential headers (Host, Connection).
3. POST requests and body formats:
   - application/x-www-form-urlencoded
   - application/json
   - multipart/form-data (file upload)
4. Key headers and why they matter (Content-Type, Content-Length, Accept, Accept-Encoding, User-Agent, Referer).
5. Cookies and sessions (Set-Cookie/Cookie; HttpOnly, Secure; persistence).
6. Authentication in requests (Basic, Bearer tokens).
7. Redirects and following them safely.
8. Conditional and caching headers (ETag/If-None-Match, Last-Modified/If-Modified-Since).
9. Working via proxies and overriding DNS resolution.
10. Inspecting and crafting raw HTTP with nc/telnet and openssl s_client for HTTPS.
11. Troubleshooting: verbose output, header inspection, handling TLS issues.
12. Security considerations tied to requests (host header injection, method confusion, CRLF).


# Tools highlighted

- curl (primary CLI HTTP client for crafting/inspecting requests)
- netcat (nc) or telnet (raw HTTP over TCP)
- openssl s_client (raw HTTPS + certificate/TLS details)
- Browser DevTools (Network tab) to observe actual requests/headers
- Burp Suite (Community) for intercepting/modifying HTTP
- Wireshark/tshark for packet-level validation


# Typical command walkthrough (detailed, copy-paste friendly)

Set a few reusable variables (adjust to your target):
```bash
# Adjust these for your lab
export HOST="10.10.10.10"
export PORT="80"
export SCHEME="http"          # or https
export BASE="$SCHEME://$HOST:$PORT"
export COOKIEJAR="cookies.txt"
```

1) Basic GET and headers
```bash
# Fetch page with response headers
curl -i "$BASE/"

# Headers only (HEAD)
curl -I "$BASE/"

# Verbose (shows request/response, TLS if https)
curl -v "$BASE/"

# Custom User-Agent and Referer
curl -i -A "eJPT-Student/1.0" -e "$BASE/from" "$BASE/"

# Show raw headers separate from body
curl -sS -D - "$BASE/" -o /dev/null
```

2) GET with query parameters (proper URL encoding)
```bash
curl -G --data-urlencode "q=admin@example.com" --data-urlencode "page=1" "$BASE/search"
```

3) POST application/x-www-form-urlencoded (typical login)
```bash
curl -i -X POST "$BASE/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=pass123"

# Alternate with --data-urlencode for safety
curl -i -X POST "$BASE/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=admin" \
  --data-urlencode "password=pass123"
```

4) Maintain session with cookies
```bash
# Save cookies on login
curl -i -c "$COOKIEJAR" -X POST "$BASE/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=pass123"

# Reuse cookies for authenticated request
curl -i -b "$COOKIEJAR" "$BASE/account"
```

5) POST JSON
```bash
curl -i -X POST "$BASE/api/v1/items" \
  -H "Content-Type: application/json" \
  --data '{"name":"widget","price":10.5}'

# Modern cURL shortcut (creates Content-Type and serializes)
curl -i "$BASE/api/v1/items" --json '{"name":"widget","price":10.5}'
```

6) File upload (multipart/form-data)
```bash
# Upload a file with additional fields
curl -i -X POST "$BASE/upload" \
  -F "file=@/path/to/local/file.jpg" \
  -F "desc=summer photo"

# Explicit MIME type for file if needed
curl -i -X POST "$BASE/upload" \
  -F "file=@/path/to/webshell.php;type=application/x-php" \
  -F "desc=test"
```

7) Auth headers (Basic and Bearer)
```bash
# Basic auth (sends Authorization: Basic base64(user:pass))
curl -i -u admin:pass123 "$BASE/admin"

# Bearer token
curl -i -H "Authorization: Bearer REPLACE_WITH_TOKEN" "$BASE/api/me"
```

8) Redirect handling
```bash
# Follow redirects
curl -i -L "$BASE/old-path"

# See redirect chain with verbose
curl -L -v "$BASE/old-path" -o /dev/null
```

9) Content negotiation and compression
```bash
# Ask for JSON and compressed response
curl -i --compressed -H "Accept: application/json" "$BASE/api/v1/info"

# Prefer a language
curl -i -H "Accept-Language: en-US,en;q=0.8" "$BASE/"
```

10) Conditional requests and caching headers
```bash
# Grab headers to get ETag/Last-Modified
curl -sS -D - "$BASE/static/app.js" -o /dev/null

# Revalidate with ETag (replace value from previous response)
curl -i -H 'If-None-Match: "abc123etagvalue"' "$BASE/static/app.js"

# Or with Last-Modified
curl -i -H "If-Modified-Since: Tue, 24 Sep 2024 12:00:00 GMT" "$BASE/static/app.js"
```

11) Range requests (partial content)
```bash
curl -i -H "Range: bytes=0-199" "$BASE/large.iso" -o part1.bin
```

12) Method override and uncommon verbs
```bash
# Explicit PUT/DELETE (if API supports)
curl -i -X PUT "$BASE/api/v1/item/12" --json '{"price":12.99}'
curl -i -X DELETE "$BASE/api/v1/item/12"

# Some apps accept override via header/form field
curl -i -X POST "$BASE/resource" \
  -H "X-HTTP-Method-Override: DELETE"
```

13) Custom Host header, virtual hosts, and DNS override
```bash
# If service uses virtual hosting; override Host
curl -i "$SCHEME://$HOST:$PORT/" -H "Host: vhost.example.local"

# Force DNS mapping (like /etc/hosts) without editing system files
curl -i --resolve vhost.example.local:$PORT:$HOST "http://vhost.example.local:$PORT/"
```

14) Work via an HTTP proxy or SOCKS
```bash
# HTTP proxy
export PROXY="http://127.0.0.1:8080"
curl -i -x "$PROXY" "$BASE/"

# With proxy auth
curl -i -x "$PROXY" -U user:pass "$BASE/"

# SOCKS5 (e.g., via ssh -D or tor)
curl -i --socks5 127.0.0.1:9050 "$BASE/"
```

15) TLS and certificate issues (HTTPS)
```bash
# Ignore TLS issues during recon (only if necessary)
curl -i -k "https://$HOST/"

# Show TLS details with OpenSSL and make a raw request
printf 'GET / HTTP/1.1\r\nHost: '"$HOST"'\r\nConnection: close\r\n\r\n' \
 | openssl s_client -connect "$HOST:443" -servername "$HOST" -ign_eof
```

16) Crafting raw HTTP with netcat
```bash
# Interactive raw request
nc -nv "$HOST" "$PORT"
# Then paste:
# GET / HTTP/1.1
# Host: 10.10.10.10
# Connection: close
#
# (Press Enter twice)

# One-shot raw request (Linux/GNU)
printf 'GET /secret HTTP/1.1\r\nHost: '"$HOST"'\r\nConnection: close\r\n\r\n' | nc -nv "$HOST" "$PORT"
```

17) Inspect response headers/body cleanly
```bash
# Split headers to a file and save body
curl -sS -D headers.txt "$BASE/path" -o body.bin
file body.bin
```

18) HTTP/2 and protocol choice
```bash
# Force HTTP/1.1 (sometimes needed for legacy/broken servers)
curl -i --http1.1 "$BASE/"

# Try HTTP/2 (useful for modern targets; may change header casing/behavior)
curl -i --http2-prior-knowledge "$BASE/"
```


# Practical tips

- Always set the right Content-Type for POSTs; servers may ignore bodies with mismatched types.
- Use --data-urlencode for any value that may include special characters.
- Session handling: save cookies with -c and reuse with -b; verify Set-Cookie attributes (HttpOnly, Secure, Path, Domain) in responses.
- For uploads, -F automatically constructs multipart/form-data; use @filepath and specify an explicit type if server-side filters check MIME.
- Follow redirects with -L, but audit each hop; avoid blindly following when testing auth flows or open redirect issues.
- Use -v or -D - to see server behavior; it’s often more informative than just the body.
- If you suspect virtual hosting, try custom Host headers or --resolve to hit alternate vhosts.
- When going through Burp, set the proxy in curl (-x) and disable certificate warnings in Burp or use -k in curl during testing.
- Test idempotency: GET/HEAD should not change state; POST typically does; PUT/DELETE are intended to be idempotent.
- Conditional requests help fingerprint caching layers and save bandwidth; 304 Not Modified indicates cache validation works.
- Be cautious with -k (insecure); use it for recon only and record that TLS verification was skipped.


# Minimal cheat sheet (one-screen flow)

```bash
# Setup
HOST=10.10.10.10; PORT=80; SCHEME=http; BASE="$SCHEME://$HOST:$PORT"; JAR=cookies.txt

# Recon headers/body
curl -sS -D - "$BASE/" -o /dev/null
curl -I "$BASE/"

# GET with UA/Referer
curl -i -A "eJPT/1.0" -e "$BASE/from" "$BASE/"

# Login (form), persist session
curl -i -c "$JAR" -X POST "$BASE/login" -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=admin" --data-urlencode "password=pass123"
curl -i -b "$JAR" "$BASE/account"

# JSON API
curl -i "$BASE/api" --json '{"op":"list"}'

# File upload
curl -i -b "$JAR" -F "file=@/tmp/poc.txt" "$BASE/upload"

# Auth
curl -i -u admin:pass123 "$BASE/admin"
curl -i -H "Authorization: Bearer TOKEN" "$BASE/api/me"

# Redirects and compression
curl -i -L --compressed "$BASE/old"

# Proxy and vhost
curl -i -x http://127.0.0.1:8080 "$BASE/"
curl -i --resolve vhost.local:$PORT:$HOST "http://vhost.local:$PORT/"

# Raw HTTP (quick)
printf 'GET / HTTP/1.1\r\nHost: '"$HOST"'\r\nConnection: close\r\n\r\n' | nc -nv "$HOST" "$PORT"
```


# Summary

This part focuses on making you fluent in constructing and analyzing HTTP requests beyond the basics. You learn to:
- Choose the correct method and body encoding (form, JSON, multipart).
- Set and read critical headers (Host, Cookie, Content-Type, Authorization, Accept, etc.).
- Maintain sessions via cookies, perform authenticated requests, and handle redirects.
- Work through proxies, override DNS resolution, and troubleshoot TLS.
- Craft and inspect raw HTTP using nc/openssl and verify behavior with verbose output.

These skills directly support eJPT tasks such as enumerating web apps, authenticating, interacting with APIs, testing file uploads, and identifying security misconfigurations through precise control of HTTP requests.