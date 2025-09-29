# 12 - HTTPS (SProtocolFundamentals)

Note: No transcript was provided. The following summary is inferred from the filename and context of an eJPT “Protocol Fundamentals” module. Commands and steps are standard and conservative for HTTPS/TLS enumeration and testing.

## What the video covers (Introduction / big picture)
- What HTTPS is: HTTP over TLS providing confidentiality, integrity, and server authentication (usually on TCP/443).
- TLS handshake basics: negotiation of protocol version and cipher suite, certificate verification, key exchange, and session key establishment.
- Certificates and PKI: leaf vs intermediate vs root CA, CN vs SAN, trust stores.
- Practical pentesting tasks:
  - Discovering and enumerating HTTPS services.
  - Inspecting certificates and chains.
  - Checking supported TLS versions and ciphers.
  - Identifying misconfigurations (weak protocols, expired/self-signed certs, missing HSTS).
  - Intercepting HTTPS traffic in labs with a trusted proxy (e.g., Burp).
  - Capturing/decrypting lab traffic in Wireshark using key logs.

## Flow (ordered)
1. HTTP vs HTTPS recap; why TLS matters on the wire.
2. TLS handshake overview (ClientHello, ServerHello, Certificate, key exchange, Finished).
3. Certificates and validation (SAN, chain, expiration, trust).
4. TLS versions and ciphers (TLS 1.0/1.1 deprecated; prefer TLS 1.2/1.3; forward secrecy).
5. Server features: SNI and ALPN; HTTP/2 over TLS; HSTS and redirect behavior.
6. Enumeration workflow with Nmap, OpenSSL, curl/testssl.sh.
7. Intercepting HTTPS with a trusted proxy (Burp) and verifying with curl.
8. Wireshark lab decryption via SSLKEYLOGFILE.
9. Common findings and reporting considerations.

## Tools highlighted
- Nmap (+ NSE scripts: ssl-enum-ciphers, ssl-cert, ssl-dh-params, tls-alpn, http-security-headers)
- OpenSSL (s_client, x509, s_server, req)
- curl (TLS version forcing, headers, ALPN/HTTP/2)
- testssl.sh and/or sslscan (TLS capability scanners)
- Wireshark (tls filter, (Pre)-Master Secret log)
- Burp Suite (CA trust, HTTPS interception)
- Browser trust store (for Burp CA) and system time checks

## Typical command walkthrough (detailed, copy-paste friendly)
Set a target for convenience:
```bash
TGT=example.com
```

1) Discover HTTPS services and quick service detection:
```bash
nmap -p 443,8443,9443 -sV -Pn "$TGT"
```

2) Enumerate TLS versions, ciphers, DH params, certificate details:
```bash
nmap -sV -Pn --script ssl-cert,ssl-enum-ciphers,ssl-dh-params -p 443 "$TGT"
```

Optional: enumerate ALPN (HTTP/2 support):
```bash
nmap -Pn --script tls-alpn -p 443 "$TGT"
```

Optional: basic web security headers (including HSTS):
```bash
nmap -Pn --script http-security-headers -p 443,80 "$TGT"
```

3) Grab the certificate chain and inspect it:
```bash
# Fetch the chain
openssl s_client -connect "$TGT:443" -servername "$TGT" -showcerts </dev/null 2>/dev/null \
  | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/ {print}' > chain.pem

# Split into individual PEM files cert-00.pem, cert-01.pem, ...
csplit -f cert- -b '%02d.pem' chain.pem '/BEGIN CERTIFICATE/' '{*}' >/dev/null 2>&1

# Inspect the leaf cert
openssl x509 -in cert-00.pem -noout -subject -issuer -dates -serial -fingerprint -sha256 -ext subjectAltName

# Full verbose view
openssl x509 -in cert-00.pem -noout -text
```

4) Check HTTPS redirect and HSTS:
```bash
# Does HTTP redirect to HTTPS?
curl -sI "http://$TGT" | egrep -i 'HTTP/|Location:'

# HSTS present?
curl -sI "https://$TGT" | grep -i '^Strict-Transport-Security'
```

5) Test supported TLS protocol versions with curl (ignore cert errors to probe handshake only):
```bash
for v in 1.0 1.1 1.2 1.3; do
  echo -n "TLS$v -> "
  curl -sk --tlsv$v -o /dev/null -w '%{http_code}\n' "https://$TGT/"
done
```

6) Probe ALPN / HTTP version:
```bash
# Show negotiated HTTP version
curl -sk -o /dev/null -w 'HTTP Version: %{http_version}\n' "https://$TGT/"

# Force HTTP/2 and view status line
curl -skI --http2 "https://$TGT/" | head -n1
```

7) Force specific ciphers or versions with OpenSSL (useful for testing downgrades/misconfigs):
```bash
# General handshake details (TLS 1.2 example)
openssl s_client -connect "$TGT:443" -servername "$TGT" -tls1_2 -brief </dev/null

# Try to negotiate weak/legacy (will often fail on modern servers)
# Note: On OpenSSL 3.x you may need '@SECLEVEL=0' to attempt legacy ciphers.
openssl s_client -connect "$TGT:443" -servername "$TGT" -tls1 -cipher 'DEFAULT:@SECLEVEL=0' </dev/null
```

8) Automated TLS scanner (testssl.sh). On Kali:
```bash
# If not installed
sudo apt-get update && sudo apt-get install -y testssl.sh
testssl.sh -U --sneaky --fast "$TGT:443"
```
Or run from repo:
```bash
git clone --depth 1 https://github.com/drwetter/testssl.sh
cd testssl.sh
./testssl.sh -U --sneaky --fast "$TGT:443"
```

9) SNI/vhost check against an IP:
```bash
IP=$(dig +short "$TGT" | head -n1)
openssl s_client -connect "$IP:443" -servername "$TGT" -showcerts </dev/null | head -n 25
```

10) Quick local HTTPS lab server (self-signed):
```bash
# Generate key+cert
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"

# Start an HTTPS test server on 8443
openssl s_server -accept 8443 -key key.pem -cert cert.pem -www
# In another terminal:
curl -k https://localhost:8443/
```

11) Intercept HTTPS via Burp (verify with curl):
- In Burp: Proxy listening on 127.0.0.1:8080. Export and trust Burp CA in your browser.
- Verify interception with curl through the proxy:
```bash
curl -vk -x http://127.0.0.1:8080 "https://$TGT/"
```

12) Wireshark lab decryption with SSLKEYLOGFILE (Chrome/Firefox):
```bash
# Linux/macOS: set env var before launching the browser
export SSLKEYLOGFILE="$HOME/sslkeys.log"
firefox &  # or chromium, google-chrome

# In Wireshark: Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename -> choose sslkeys.log
# Filter:
#   tls
```
Windows (PowerShell):
```powershell
$env:SSLKEYLOGFILE="$env:USERPROFILE\sslkeys.log"; Start-Process firefox
```

## Practical tips
- Always include SNI when probing virtual hosts: openssl s_client -servername <hostname>.
- SAN beats CN: verify the intended hostname appears in subjectAltName.
- Clock matters: certificate validation fails if your system time is off.
- Don’t rely on --insecure/-k except for probing; note it explicitly if used.
- Look for reportable items: TLS 1.0/1.1 enabled, weak ciphers (RC4/3DES), small DH params, missing HSTS, expired/self-signed certs on public apps, mismatched names.
- Use nmap ssl-enum-ciphers and testssl.sh for comprehensive but quick coverage.
- HTTP/2 is negotiated via ALPN; check if your tooling supports it when testing.
- If you only have an IP, use -servername to avoid default/wrong certificates on shared hosts.
- For non-HTTPS TLS protocols (SMTP/IMAP/LDAP), use openssl s_client -starttls <proto> (outside the scope of pure HTTPS, but handy on exams).
- In labs, use SSLKEYLOGFILE to decrypt your own browser traffic; do not expect to decrypt third-party TLS in real engagements.

## Minimal cheat sheet (one-screen flow)
```bash
# Target
TGT=example.com

# Discover HTTPS
nmap -p 443,8443,9443 -sV -Pn "$TGT"

# Enumerate TLS
nmap -sV -Pn --script ssl-cert,ssl-enum-ciphers,ssl-dh-params -p 443 "$TGT"

# Grab and inspect cert
openssl s_client -connect "$TGT:443" -servername "$TGT" -showcerts </dev/null \
  | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/ {print}' > chain.pem
csplit -f cert- -b '%02d.pem' chain.pem '/BEGIN CERTIFICATE/' '{*}' >/dev/null 2>&1
openssl x509 -in cert-00.pem -noout -subject -issuer -dates -ext subjectAltName

# TLS versions
for v in 1.0 1.1 1.2 1.3; do echo -n "TLS$v -> "; curl -sk --tlsv$v -o /dev/null -w '%{http_code}\n' "https://$TGT/"; done

# HTTP->HTTPS and HSTS
curl -sI "http://$TGT" | egrep -i 'HTTP/|Location:'
curl -sI "https://$TGT" | grep -i '^Strict-Transport-Security'

# HTTP version / ALPN
curl -sk -o /dev/null -w 'HTTP Version: %{http_version}\n' "https://$TGT/"

# Automated scanner
testssl.sh -U --sneaky --fast "$TGT:443"  # or install from repo if missing
```

## Summary
This module introduces HTTPS as HTTP over TLS and shows how a pentester enumerates and evaluates TLS configurations. You learn to:
- Discover HTTPS endpoints and extract/inspect certificates and chains.
- Identify supported TLS versions and ciphers, ALPN/HTTP/2, redirect and HSTS behavior.
- Use Nmap, OpenSSL, curl, and testssl.sh to spot weak protocols, expired/mismatched certs, and missing security headers.
- Intercept and analyze HTTPS safely in lab settings with Burp and Wireshark key logs.
Report insecure protocols/ciphers, certificate issues, and missing HSTS, and note all testing conditions (SNI used, --insecure where applicable).