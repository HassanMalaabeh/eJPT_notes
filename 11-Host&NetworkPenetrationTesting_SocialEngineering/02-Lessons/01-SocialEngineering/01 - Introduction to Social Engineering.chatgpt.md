# 01 - Introduction to Social Engineering

Note: No transcript was provided. The notes below are inferred conservatively from the filename and typical eJPT coverage of Social Engineering. Where concrete commands are shown, they are safe, lab-only examples intended for authorized training environments.

## What the video covers (Introduction / big picture)

- Definition and scope
  - Social engineering: manipulating human factors to achieve security objectives (for testing or attack)
  - Common modalities: email (phishing/spear-phishing/whaling), phone (vishing), SMS (smishing), in-person (tailgating, impersonation), media drops (USB)
- Psychology and influence
  - Typical triggers: authority, urgency/scarcity, reciprocity, liking, consistency/commitment, social proof, curiosity, fear
- Ethical and legal guardrails
  - Explicit written authorization, rules of engagement (ROE), scope boundaries, safety and “stop” conditions
  - Data handling and privacy (PII minimization, consent, evidence control), non-repudiation, approvals
- A practical lifecycle you can follow in eJPT labs/client engagements
  1) Plan and scope; 2) Recon/OSINT; 3) Pretext design; 4) Infrastructure prep; 5) Risk review and approvals; 6) Limited pilot; 7) Execute; 8) Monitor and handle responses; 9) Cleanup; 10) Reporting
- Outcomes and measurement
  - Metrics: delivery rate, click rate, credential submission rate, report rate, time-to-report, MFA bypass attempts blocked
- Defensive context
  - Controls that reduce risk: security awareness, MFA, email authentication (SPF/DKIM/DMARC), domain monitoring, anti-phishing gateways, process controls (out-of-band verification)

## Flow (ordered)

1. Authorization and scope
   - Obtain written permission, define who/what is in scope, channels permitted, time windows, disallowed techniques (e.g., safety-critical, payroll changes)
2. Reconnaissance (OSINT)
   - Identify org structure, technologies, branding, email patterns, public processes, current campaigns, holidays, and vendor relationships
3. Threat modeling and pretext selection
   - Choose believable scenarios aligned to business processes (e.g., HR policy update, IT ticket follow-up)
   - Map influence triggers ethically and minimally necessary for test goals
4. Content and infrastructure preparation
   - Draft lures (email/call scripts), benign landing pages, consent banners for training, tracking and logging in a lab context
5. Risk review and approvals
   - Validate with stakeholders (legal, HR, security) and set “panic button”/stop criteria
6. Pilot on a small, authorized subset
   - Validate deliverability and clarity; tune content and reduce false positives
7. Execute the campaign (as authorized)
   - Controlled send/call windows; monitor in real time; respect opt-outs
8. Handle responses
   - Capture metrics and evidence; never exfiltrate sensitive data beyond ROE; simulate success without creating business impact
9. Cleanup
   - Tear down infra, revoke tokens, invalidate test credentials, collect and sanitize logs
10. Report and remediate
   - Share metrics, examples, and actionable improvements; propose training and control changes

## Tools highlighted

Because the transcript is unavailable, this list reflects commonly referenced tools in introductory eJPT social engineering modules:

- OSINT and footprinting
  - theHarvester (open-source email/subdomain harvesting)
  - Amass (passive subdomain enumeration)
  - Search engines and site operators (Google/Bing dorking)
  - LinkedIn and public org charts for role mapping
- Content and web hosting (for benign, lab-only landing pages)
  - Python’s built-in http.server
  - Any static web server (Apache/Nginx) in a lab
  - ExifTool (sanitize document metadata)
- Email/authentication posture checks (defensive understanding)
  - dig/nslookup/whois for SPF/DKIM/DMARC/MX records
- Simulation frameworks (lab-only, with authorization)
  - Gophish or SET (Social-Engineer Toolkit) often referenced in courses; use only in controlled labs and with explicit permission

## Typical command walkthrough (detailed, copy-paste friendly)

Important: Use only against assets you own or have explicit permission to test. These examples are lab-safe and avoid payload creation or real phishing sends.

1) Basic org DNS footprint (MX/SPF/DMARC/NS)
```
# Replace example.com with an authorized test domain
whois example.com

dig +short NS example.com
dig +short MX example.com

# Check SPF
dig TXT example.com +short | grep -i spf || echo "No SPF record found"

# Check DMARC
dig TXT _dmarc.example.com +short || echo "No DMARC record found"
```

2) Passive OSINT for emails/subdomains (lab/authorized)
```
# theHarvester: collects public emails, hosts, and sources (passive)
theHarvester -d example.com -b all -f example.com-harvest

# Amass passive subdomain enumeration
amass enum -passive -d example.com -o subs.txt
```

3) Create a benign training/landing page and local server
```
# Create a simple static page for awareness testing in a lab
mkdir -p ~/lab/phish-sim && cd ~/lab/phish-sim
cat > index.html << 'EOF'
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Security Awareness Test (Lab)</title></head>
<body>
  <h1>Security Awareness Test</h1>
  <p>This is a benign page used only for authorized lab training.</p>
  <p>If you arrived here, report this to the awareness team as instructed.</p>
</body>
</html>
EOF

# Start a simple local server and log to file
python3 -m http.server 8080 2>&1 | tee server.log
```

4) Local verification of the server (no external distribution)
```
# From the same host (or an allowed lab client)
curl -I http://127.0.0.1:8080/
# Or open in a browser
xdg-open http://127.0.0.1:8080/ 2>/dev/null || open http://127.0.0.1:8080/
```

5) Sanitize document metadata (if sharing benign attachments in a lab)
```
# Remove all metadata from a PDF or DOCX before use
exiftool -all= -overwrite_original awareness.pdf
exiftool -all= -overwrite_original awareness.docx
```

6) Simple metric extraction (requests observed by your local server)
```
# Count hits to the root page from server.log
grep -E '"GET /( |HTTP)' server.log | wc -l

# Show unique client IPs (in a lab network)
awk '{print $1}' server.log | sort -u
```

## Practical tips

- Always get explicit written authorization with clear scope and stop conditions.
- Pick pretexts that align with real business processes; avoid topics that cause undue stress or touch protected classes/PII.
- Start with a small pilot group; iterate to reduce ambiguity and unintended harm.
- Minimize data collection; capture only what’s needed for metrics and evidence.
- Prepare response paths: how targets can report suspicious messages and how you’ll triage safely.
- Coordinate with IT/Helpdesk to prevent confusion during the test window.
- Log everything and ensure time synchronization across systems for reliable metrics.
- After action, focus on constructive improvement: training, process changes, and technical controls (MFA, DMARC alignment, reporting buttons).

## Minimal cheat sheet (one-screen flow)

- Scope and ROE: define targets, channels, timing, disallowed tactics, stop word.
- OSINT (authorized):
  - theHarvester: theHarvester -d example.com -b all -f out
  - DNS posture: dig MX/TXT _dmarc.example.com; whois example.com
- Pretext: believable, minimal data, clear objectives and metrics.
- Infra (lab-only):
  - mkdir ~/lab/phish-sim && cd ~/lab/phish-sim
  - create index.html (benign content)
  - python3 -m http.server 8080 2>&1 | tee server.log
  - curl -I http://127.0.0.1:8080/
- Execute (authorized): run pilot, then controlled send/calls; monitor.
- Metrics: delivery, click, report rates; parse server.log as needed.
- Cleanup: stop services, sanitize logs, revoke lab credentials.
- Report: findings, examples, remediation steps, training recommendations.

## Summary

This introductory module frames social engineering as the exploitation of human factors within strict ethical and legal boundaries. It walks through a practical lifecycle—planning and scope, OSINT, pretext design, infrastructure setup, controlled execution, monitoring, cleanup, and reporting—while highlighting psychological principles and success metrics. In an eJPT context, you’re expected to understand these phases, recognize common channels (phishing, vishing, smishing, in-person), and apply safe, authorized techniques to measure and improve organizational resilience. The example commands above focus on lab-only reconnaissance and benign infrastructure so you can practice the workflow responsibly.