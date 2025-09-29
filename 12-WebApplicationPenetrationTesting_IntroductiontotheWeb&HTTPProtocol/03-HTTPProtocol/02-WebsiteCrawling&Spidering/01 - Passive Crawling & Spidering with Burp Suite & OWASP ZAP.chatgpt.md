# 01 - Passive Crawling & Spidering with Burp Suite & OWASP ZAP

Note: The transcript was not provided. The following is a careful, eJPT-focused summary inferred from the filename and module folder. It covers standard, safe workflows for passive crawling in Burp Suite Community and spidering in OWASP ZAP.

Only test systems you are authorized to assess.

## What the video covers (Introduction / big picture)
- How to map a web application with minimal impact using:
  - Burp Suite Community for passive crawling (build a site map by proxying normal browsing; no active scanning).
  - OWASP ZAP for spidering (automated link discovery) and passive scanning.
- Proper scoping to avoid hitting third-party domains.
- Exporting discovered endpoints for later testing.

## Flow (ordered)
1. Prepare tools and ports: run Burp on 127.0.0.1:8080; run ZAP separately (e.g., 127.0.0.1:8090 if using API).
2. Configure your browser to use Burp’s proxy; import Burp CA and set Intercept to Off.
3. Define scope in Burp to the target domain/IP. Browse the app normally to passively build the Site map.
4. Review Burp’s Proxy History and Target Site map for endpoints, parameters, and hidden inputs. Export URLs.
5. Launch ZAP. Define scope/context to the same target; disable any active scanning. Configure Spider options (do not submit forms, set depth/time limits).
6. Run ZAP Spider (and Ajax Spider if needed) to enumerate URLs within scope.
7. Review ZAP’s Sites tree and passive alerts; export reports and URL lists.
8. Optional: Use ZAP’s Docker baseline scan to do a passive scan + spider in one shot.
9. Consolidate results (URLs/params) and save project/session files for later phases.

## Tools highlighted
- Burp Suite Community Edition (Proxy, Target > Site map, Scope filtering).
- OWASP ZAP (Spider, Ajax Spider, Passive Scan, Context/Scope, Reports).
- Browser (Firefox/Chrome) with proxy configuration; FoxyProxy extension helps switch proxies.
- curl/wget for quick checks through the proxy.
- Docker for ZAP baseline scan (owasp/zap2docker-stable).
- jq for processing ZAP API JSON output.

## Typical command walkthrough (detailed, copy-paste friendly)

Install tools (Kali/Debian-based):
```bash
sudo apt update
sudo apt install -y burpsuite zaproxy jq docker.io
```

Start Burp (Community) and use as intercepting proxy:
```bash
# GUI start (Kali/menus) or:
burpsuite &
```
- Burp default listener: 127.0.0.1:8080 (Proxy > Options > Proxy Listeners).
- In your browser, set HTTP/HTTPS proxy to 127.0.0.1:8080.
- Export/import Burp CA:
  - Burp: Proxy > Options > Import / export CA certificate > Export (DER).
  - Firefox: Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import.

Quickly test proxy path with curl through Burp:
```bash
# Use -k to ignore TLS errors until CA is installed
curl -x http://127.0.0.1:8080 -k https://TARGET/ -I
curl -x http://127.0.0.1:8080 -k https://TARGET/robots.txt
curl -x http://127.0.0.1:8080 -k https://TARGET/sitemap.xml
```

Burp passive crawl (manual steps):
- Proxy > Intercept: Off.
- Target > Scope: Add https://TARGET (tick “Show only in-scope items” in Site map/Proxy History).
- Browse the site normally to build Site map.
- Export URLs: Target > Site map > filter to in-scope > right-click host/branch > Copy URLs in this host (or save project).

Start OWASP ZAP (daemon/API on alternate port to avoid clashing with Burp):
```bash
# If installed natively
zap.sh -daemon -port 8090 -config api.disablekey=true

# Or Docker (runs ZAP daemon with API, proxy on 8090)
docker run --rm -u zap -p 8090:8080 -t owasp/zap2docker-stable \
  zap.sh -daemon -port 8080 -config api.disablekey=true \
  -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
```

Run ZAP Spider via API (passive-friendly; do not start Active Scan):
```bash
# Start a spider against TARGET
curl -s "http://127.0.0.1:8090/JSON/spider/action/scan/?url=https://TARGET&maxChildren=0&recurse=true&subtreeOnly=false"

# Poll status until it returns "100"
curl -s "http://127.0.0.1:8090/JSON/spider/view/status/?scanId=0" | jq

# List discovered URLs
curl -s "http://127.0.0.1:8090/JSON/core/view/urls/?baseurl=https://TARGET" | jq -r '.urls[]' | sort -u

# Export an HTML report (includes passive findings)
curl -s "http://127.0.0.1:8090/OTHER/core/other/htmlreport/" -o zap-report.html

# Export raw alerts JSON (passive)
curl -s "http://127.0.0.1:8090/JSON/alert/view/alerts/?baseurl=https://TARGET" -o zap-alerts.json
```

Optional: ZAP Docker Baseline scan (spider + passive only):
```bash
# Pull image
docker pull owasp/zap2docker-stable

# Run a baseline scan for up to 5 minutes of spidering (-m 5), include alpha passive rules (-a),
# ignore failure exit (-I), write HTML and JSON/XML outputs locally
docker run --rm -v "$(pwd)":/zap/wrk -t owasp/zap2docker-stable \
  zap-baseline.py -t https://TARGET -m 5 -a -I \
  -r zap-baseline.html -x zap-baseline.xml -J zap-baseline.json \
  -z "-config spider.postform=false -config spider.submitForm=false -config spider.maxDepth=5"
```

Useful ZAP configuration via API (optional scoping/exclusions):
```bash
# Exclude logout endpoints from spidering (regex example)
curl -s "http://127.0.0.1:8090/JSON/spider/action/excludeFromScan/?regex=.*(logout|signout).*"

# Confirm Sites currently known
curl -s "http://127.0.0.1:8090/JSON/core/view/sites/" | jq -r '.sites[]'
```

Collect a single deduplicated list of in-scope URLs from ZAP API:
```bash
curl -s "http://127.0.0.1:8090/JSON/core/view/urls/?baseurl=https://TARGET" \
 | jq -r '.urls[]' \
 | grep -E "^https?://TARGET" \
 | sort -u > urls.txt
wc -l urls.txt
head -n 20 urls.txt
```

## Practical tips
- Scope is everything:
  - In Burp: Target > Scope; enable “Show only in-scope” in Proxy/Target views.
  - In ZAP: Define a Context and include only your target. Exclude third-party CDNs, fonts, analytics to avoid noise.
- Passive means “observe only”:
  - Burp Community has no active scanner; just browse with Intercept Off.
  - In ZAP, do not trigger Active Scan. Use Spider/Ajax Spider with “do not submit forms” to reduce impact.
- Certificates:
  - Installing Burp/ZAP CA avoids HTTPS errors and missing traffic. Use a dedicated testing browser profile.
- Two proxies at once:
  - Run Burp on 8080 and ZAP on 8090; switch via FoxyProxy profiles in the browser to avoid conflicts.
- Be gentle:
  - Limit spider depth/time; exclude logout/destructive endpoints; throttle if the target is resource constrained.
- Quick wins:
  - Check /robots.txt and /sitemap.xml early.
  - Sort URLs by path depth to see deeper functionality quickly.
- Save your work:
  - Burp: Project file/save state.
  - ZAP: Session save; export reports (HTML/JSON/XML) and URL lists.

## Minimal cheat sheet (one-screen flow)
- Start Burp on 127.0.0.1:8080; browser through Burp; Intercept Off; add target to Scope.
- Browse site normally to build Site map. Export URLs from Target > Site map.
- Start ZAP (daemon/API) on 127.0.0.1:8090:
```bash
zap.sh -daemon -port 8090 -config api.disablekey=true
curl "http://127.0.0.1:8090/JSON/spider/action/scan/?url=https://TARGET&recurse=true"
curl "http://127.0.0.1:8090/JSON/spider/view/status/?scanId=0"
curl -s "http://127.0.0.1:8090/JSON/core/view/urls/?baseurl=https://TARGET" | jq -r '.urls[]' | sort -u > urls.txt
curl -s "http://127.0.0.1:8090/OTHER/core/other/htmlreport/" -o zap-report.html
```
- Optional one-shot Docker baseline:
```bash
docker run --rm -v "$(pwd)":/zap/wrk -t owasp/zap2docker-stable \
  zap-baseline.py -t https://TARGET -m 5 -a -I -r zap-baseline.html
```

## Summary
- Passive crawling with Burp Suite Community builds a high-fidelity site map by proxying real browsing without active probes.
- OWASP ZAP’s Spider/Ajax Spider safely automate URL discovery within scope and run passive checks; the Docker baseline scan bundles this into a repeatable, low-impact workflow.
- Combine Burp’s Proxy/Target views and ZAP’s Sites tree/reports to produce a clean, scoped list of endpoints and parameters for later testing phases.