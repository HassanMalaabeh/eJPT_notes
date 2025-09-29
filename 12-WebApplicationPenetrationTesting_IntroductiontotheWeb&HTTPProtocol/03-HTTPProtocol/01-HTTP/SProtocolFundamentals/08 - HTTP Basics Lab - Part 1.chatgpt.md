# 08 - HTTP Basics Lab - Part 1 — Study Notes

Note: No transcript was provided. The following is a conservative, context-based summary and a practical command set for an HTTP basics lab in an eJPT context.

## What the video covers (Introduction / big picture)
- HTTP request/response fundamentals in a lab setting
- Viewing and crafting raw HTTP (HTTP/1.0 vs HTTP/1.1)
- Essential methods: GET, HEAD, basic POST with form data
- Core headers: Host, User-Agent, Content-Type, Content-Length, Cookie/Set-Cookie, Connection
- Inspecting status codes and headers with tools
- Using curl, netcat, and packet capture to understand how HTTP works on the wire

## Flow (ordered)
1. Identify an HTTP service and its ports (80/8080/8000) with nmap.
2. Retrieve a page and headers with curl; interpret status code, Server header, and cookies.
3. Compare GET vs HEAD requests.
4. Observe redirects and how to follow them.
5. Understand HTTP/1.1 Host header importance and try HTTP/1.0.
6. Manually craft a GET request over a TCP socket (netcat) with proper CRLF.
7. Manually craft a POST with Content-Length and form data.
8. Optionally test Basic Auth and cookies with curl headers.
9. Capture HTTP traffic with tcpdump/Wireshark to see raw protocol exchanges.
10. (Optional) Spin up a simple local HTTP server to test against.

## Tools highlighted
- curl (HTTP client)
- netcat/nc (raw TCP client for manual requests)
- nmap (service discovery; optional http scripts)
- tcpdump or Wireshark/tshark (packet capture/inspection)
- Python http.server (quick test server; optional)
- Browser DevTools or Burp (optional intercept/inspection)

## Typical command walkthrough (detailed, copy-paste friendly)
These commands assume a Linux shell. Replace values as needed.

Set target variables:
```bash
# Target host and port
export TARGET=10.10.10.10
export PORT=80

# If the site uses virtual hosting, set the expected Host header (domain)
# Use the IP if you don't know the hostname.
export HOST=example.com
```

1) Quick discovery and fingerprinting:
```bash
nmap -p80,8080,8000 -sV --script http-headers,http-title,http-server-header -oN nmap-http.txt "$TARGET"
```

2) Basic GET with verbose output (see request/response lines and headers):
```bash
curl -v "http://$TARGET:$PORT/" -H "Host: $HOST"
```

3) Headers only (HEAD request):
```bash
curl -I "http://$TARGET:$PORT/" -H "Host: $HOST"
```

4) Dump response headers without body, follow redirects if any:
```bash
curl -sSL -D - -o /dev/null "http://$TARGET:$PORT/" -H "Host: $HOST"
```

5) Follow redirects and show final body:
```bash
curl -L "http://$TARGET:$PORT/" -H "Host: $HOST"
```

6) HTTP/1.0 vs HTTP/1.1:
```bash
# Force HTTP/1.0
curl --http1.0 -v "http://$TARGET:$PORT/" -H "Host: $HOST"

# Default is HTTP/1.1; demonstrate keep-alive vs close
curl -v -H "Connection: close" "http://$TARGET:$PORT/" -H "Host: $HOST"
```

7) Manual GET via netcat (raw HTTP). Note the CRLF line endings and Host header:
```bash
printf 'GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: nc-test\r\nAccept: */*\r\nConnection: close\r\n\r\n' "$HOST" \
| nc -w 5 "$TARGET" "$PORT"
```

8) Manual HEAD via netcat:
```bash
printf 'HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$HOST" \
| nc -w 5 "$TARGET" "$PORT"
```

9) HTTP POST with x-www-form-urlencoded via curl:
```bash
curl -v -X POST "http://$TARGET:$PORT/login" \
  -H "Host: $HOST" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'username=alice&password=secret'
```

10) Manual POST via netcat (compute Content-Length accurately):
```bash
body='username=alice&password=secret'
len=$(printf %s "$body" | wc -c)

printf 'POST /login HTTP/1.1\r\nHost: %s\r\nUser-Agent: nc-test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "$HOST" "$len" "$body" \
| nc -w 5 "$TARGET" "$PORT"
```

11) Basic Auth (two ways):
```bash
# Using curl -u
curl -v -u admin:password "http://$TARGET:$PORT/protected" -H "Host: $HOST"

# Manually build the Authorization header
b64=$(printf 'admin:password' | base64)
curl -v "http://$TARGET:$PORT/protected" -H "Host: $HOST" -H "Authorization: Basic $b64"
```

12) Cookies: capture and resend
```bash
# Capture cookies to a jar and reuse them
curl -v -c cookies.txt "http://$TARGET:$PORT/" -H "Host: $HOST"
curl -v -b cookies.txt "http://$TARGET:$PORT/dashboard" -H "Host: $HOST"

# Or set a cookie manually
curl -v "http://$TARGET:$PORT/" -H "Host: $HOST" -H "Cookie: session=abcdef123456"
```

13) Packet capture to observe raw HTTP:
```bash
# Replace eth0 with your interface; -A prints ASCII payload
sudo tcpdump -i eth0 -nn -s0 -A 'tcp port 80'
```

14) Optional: start a quick local server for testing:
```bash
# Serve current directory on port 8000
python3 -m http.server 8000
# Test it
curl -v http://127.0.0.1:8000/
```

Notes:
- Paths like /login or /protected are examples—adjust to your target.
- For HTTPS, use curl -k https://… or openssl s_client -connect host:443 (HTTPS likely covered later).

## Practical tips
- HTTP/1.1 requires a Host header; omit it and many servers will reply 400 Bad Request.
- End each header line with CRLF and add a blank CRLF before any body when crafting manually.
- For manual POSTs, Content-Length must match the exact byte count of the body.
- Use Connection: close to make netcat demos predictable (server closes after response).
- curl -I (HEAD) is quick to see status, server, cookies, content type without downloading bodies.
- curl -L follows redirects; combine with -I or -v for clarity on 301/302 flows.
- Cookie/Set-Cookie sequences are often key to authentication flow—capture them with -c/-b.
- If the site is behind virtual hosting, ensure Host matches the expected domain, not just the IP.
- Prefer printf over echo -e for reliable CRLF in manual requests.

## Minimal cheat sheet (one-screen flow)
```bash
export TARGET=10.10.10.10; export PORT=80; export HOST=example.com

# Scan
nmap -p80,8080,8000 -sV --script http-title,http-headers "$TARGET"

# GET + headers
curl -v "http://$TARGET:$PORT/" -H "Host: $HOST"

# HEAD only
curl -I "http://$TARGET:$PORT/" -H "Host: $HOST"

# Follow redirects
curl -sSL -D - -o /dev/null "http://$TARGET:$PORT/" -H "Host: $HOST"

# HTTP/1.0 test
curl --http1.0 -v "http://$TARGET:$PORT/" -H "Host: $HOST"

# Raw GET via nc
printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$HOST" | nc -w 5 "$TARGET" "$PORT"

# Raw POST via nc
body='a=1&b=2'; len=$(printf %s "$body" | wc -c)
printf 'POST /post HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "$HOST" "$len" "$body" | nc -w 5 "$TARGET" "$PORT"

# Cookies
curl -c c.txt "http://$TARGET:$PORT/" -H "Host: $HOST"; curl -b c.txt "http://$TARGET:$PORT/" -H "Host: $HOST"

# Capture
sudo tcpdump -i eth0 -nn -s0 -A 'tcp port 80'
```

## Summary
- This Part 1 lab builds hands-on familiarity with HTTP by using curl and netcat to observe and craft requests, emphasizing request/response anatomy, key headers, and basic methods.
- You should be able to: identify HTTP services, fetch and interpret headers, follow redirects, respect Host and Content-Length requirements, and watch raw exchanges on the wire.
- Keep your workflow simple: enumerate with nmap, inspect with curl, validate with a raw socket (nc), and confirm behavior via packet capture.