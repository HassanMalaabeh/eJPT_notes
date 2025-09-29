# Phishing with Gophish – Part 1 (eJPT Study Notes)

Note: The transcript is not provided. The following is a careful, conservative summary inferred from the filename and typical eJPT/social engineering lab flow using Gophish. Commands and steps reflect common, documented Gophish usage for authorized training only.

## What the video covers (Introduction / big picture)
- The core workflow of running an internal, authorized phishing campaign with Gophish.
- Installing Gophish (Docker or native binary), initial access to the admin UI, and safe exposure of interfaces.
- Building the essential pieces: Sending Profile (SMTP), Landing Page (credential capture), Email Template (with tracking), Users & Groups (targets), and Campaign creation.
- Launching a test campaign in a lab and monitoring results (delivered/opened/clicked/submitted data).

## Flow (ordered)
1. Prepare infra: a Linux host, DNS/hosts record for your phishing domain, and an SMTP relay you’re allowed to use.
2. Install Gophish (Docker or binary).
3. Secure/limit admin access (127.0.0.1 + SSH tunnel) and expose the phish server on 80/443.
4. Login to the admin UI; retrieve the initial admin password from logs.
5. Create a Sending Profile (SMTP settings, test delivery).
6. Create a Landing Page (import/clone, enable credential capture, set redirect).
7. Create an Email Template (use variables and a tracked link {{.URL}}).
8. Create Users & Groups (import CSV).
9. Create and launch a Campaign (set URL to your phishing domain, pick objects).
10. Monitor results and export data for analysis.

## Tools highlighted
- Gophish (open-source phishing framework)
- Docker (optional, fastest install)
- curl/wget, unzip, OpenSSL (native install and certs)
- SSH local port forwarding (secure admin access)
- swaks or openssl s_client (SMTP testing)
- A DNS provider or /etc/hosts (lab-only resolution)

## Typical command walkthrough (detailed, copy-paste friendly)

Authorized lab only. Replace placeholders like <server_ip>, <phish_domain>, <smtp_host>, <smtp_user>, etc.

- Prepare host and firewall (Ubuntu/Kali)
```
sudo apt update
sudo apt install -y unzip curl ca-certificates libcap2-bin
# If using UFW, open needed ports (adjust as needed)
sudo ufw allow 80,443,3333/tcp
```

- Optional: Local lab name resolution (lab-only)
```
# Replace with your server IP and phishing domain
echo "<server_ip> <phish_domain>" | sudo tee -a /etc/hosts
```

### Option A: Run Gophish via Docker (recommended quick start)
```
# Install Docker if needed (Ubuntu)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Pull and run (persist DB to a named volume)
docker volume create gophish-data
docker run -d --name gophish \
  -p 3333:3333 -p 80:80 -p 443:443 \
  -v gophish-data:/opt/gophish \
  gophish/gophish:latest

# Get the initial admin password from logs (look for "Please login" line)
docker logs gophish | sed -n '1,160p'
```
- Admin UI: https://<server_ip or name>:3333 (self-signed cert; proceed to the page)
- If admin UI isn’t reachable remotely, tunnel it:
```
# From your workstation to the server
ssh -N -L 3333:127.0.0.1:3333 user@<server_ip>
# Then browse https://127.0.0.1:3333
```

### Option B: Run Gophish from the native binary
```
# Download a release (example version; check https://github.com/gophish/gophish/releases)
GOPHISH_VER=0.12.1
curl -L -o gophish.zip \
  https://github.com/gophish/gophish/releases/download/v${GOPHISH_VER}/gophish-v${GOPHISH_VER}-linux-64bit.zip
unzip gophish.zip -d ~/gophish
cd ~/gophish

# Allow binding to 80/443 without root
sudo setcap 'cap_net_bind_service=+ep' ./gophish

# Start Gophish and note the printed admin password and URLs
./gophish
```
- Admin UI: by default https://127.0.0.1:3333
- Phish server: by default http://0.0.0.0:80 (defaults may vary by version; adjust config.json as needed)
- Tunnel if running on a remote host:
```
ssh -N -L 3333:127.0.0.1:3333 user@<server_ip>
# then browse https://127.0.0.1:3333
```

### Optional: Enable HTTPS for the phishing server
- Self-signed cert (lab use):
```
mkdir -p ~/gophish/certs
cd ~/gophish/certs
openssl req -x509 -newkey rsa:2048 -keyout phish.key -out phish.crt -days 365 -nodes -subj "/CN=<phish_domain>"
```
- Edit config.json (phish_server section):
  - "listen_url": "0.0.0.0:443"
  - "use_tls": true
  - "cert_path": "certs/phish.crt"
  - "key_path": "certs/phish.key"
- Restart Gophish and set Campaign URL to https://<phish_domain>

### Test your SMTP relay (before configuring Gophish)
- With swaks:
```
sudo apt install -y swaks
swaks --to you@yourlab.tld --from sender@<yourdomain> \
  --server <smtp_host>:587 --tls \
  --auth LOGIN --auth-user '<smtp_user>' --auth-password '<smtp_pass>' \
  --data 'Subject: SMTP test from lab

Hello from swaks.'
```
- Or with openssl s_client:
```
openssl s_client -starttls smtp -connect <smtp_host>:587
EHLO test
AUTH LOGIN
# (base64 user/pass)
QUIT
```

### Build campaign assets (copypasta ready)
- Users & Groups CSV (import under “Users & Groups → New Group → Import CSV”)
```
cat > targets.csv <<'CSV'
First Name,Last Name,Email,Position
Alice,Anderson,alice@victim.lab,Engineer
Bob,Brown,bob@victim.lab,IT
Carol,Clark,carol@victim.lab,HR
CSV
```

- Email Template (use {{.FirstName}} and insert tracked link using {{.URL}})
```
cat > template.html <<'HTML'
<!doctype html>
<html>
  <body style="font-family:Arial, sans-serif">
    <p>Hi {{.FirstName}},</p>
    <p>We detected a sign-in from a new device. For your security, please verify your account using the link below:</p>
    <p><a href="{{.URL}}">Verify your account</a></p>
    <p>Thanks,<br>IT Support</p>
    <img src="{{.Tracker}}" style="display:none" alt=""/>
  </body>
</html>
HTML
```
- Create the Template in Gophish: “Email Templates → New Template → paste HTML”. Ensure the tracking image is present or enable “Add Tracking Image.”

- Landing Page (simple credential capture; enable “Capture Submitted Data” and “Capture Passwords”, set a redirect)
```
cat > landing.html <<'HTML'
<!doctype html>
<html>
  <body style="font-family:Arial, sans-serif">
    <h2>Single Sign-On</h2>
    <form method="POST" action="">
      <label>Email</label><br/>
      <input type="email" name="email" required /><br/><br/>
      <label>Password</label><br/>
      <input type="password" name="password" required /><br/><br/>
      <button type="submit">Sign in</button>
    </form>
  </body>
</html>
HTML
```
- In Gophish: “Landing Pages → New Page → HTML (paste) → check ‘Capture Submitted Data’ and ‘Capture Passwords’ → set Redirect to: https://www.example.com/ (or your legit portal) → Save.”

### Configure Sending Profile (SMTP)
- In Gophish: “Sending Profiles → New Profile”
  - Name: Lab SMTP
  - Host: <smtp_host>:587
  - Username: <smtp_user>
  - Password: <smtp_pass>
  - From: “IT Support <it-support@yourdomain.tld>”
  - Enable TLS
  - Use “Send Test Email” to confirm delivery.

### Create and launch Campaign
- Campaigns → New Campaign:
  - Name: Lab Test 1
  - Email Template: (select your template)
  - Landing Page: (select your landing page)
  - URL: http://<phish_domain> (or https://<phish_domain> if TLS enabled)
  - SMTP Sending Profile: (select)
  - Groups: (select imported group)
  - Launch

### Monitor and export results
- Campaign Dashboard:
  - Track Sent, Delivered, Opened (tracking image), Clicked (link), Submitted Data (credentials).
  - Export via “Export CSV/Results” for reporting.

## Practical tips
- Authorized use only: get written permission and limit scope/recipients in labs.
- Admin UI security: keep admin on 127.0.0.1 and access via SSH tunnel. Don’t expose :3333 publicly.
- Deliverability:
  - Use a proper domain with SPF/DKIM/DMARC aligned to your SMTP provider if testing real mail flow.
  - For labs, use a test SMTP (e.g., MailHog/smtp4dev) or a dedicated relay; always send to controlled inboxes first.
- Campaign URL must be reachable by targets and match your phish server/port and scheme (http/https).
- Landing Pages:
  - Prefer cloning/importing the real login page via Gophish’s “Import Site” and then enabling capture + redirect to the legitimate site.
  - Test end-to-end with a test target to ensure form capture works.
- Templates:
  - Use variables: {{.FirstName}}, {{.LastName}}, {{.Email}}.
  - Always include {{.URL}} for the tracked link and {{.Tracker}} or the “Add Tracking Image” option for open tracking.
- Ports and permissions:
  - If you can’t bind 80/443, use setcap or run behind a reverse proxy (Nginx) that terminates TLS and forwards to Gophish.
- Troubleshooting:
  - Emails not sending: verify SMTP creds, port 587, STARTTLS, swaks test.
  - Links don’t work: fix Campaign URL; ensure DNS/hosts resolve <phish_domain>.
  - “Connection refused” on :3333: use tunnel or change admin_server.listen_url to 0.0.0.0 (only if you’re protecting access another way).

## Minimal cheat sheet (one-screen flow)
- Run Gophish (Docker):
```
docker run -d --name gophish \
  -p 3333:3333 -p 80:80 -p 443:443 \
  -v gophish-data:/opt/gophish \
  gophish/gophish:latest
docker logs gophish | sed -n '1,160p'
# Admin: https://<server>:3333  (use printed password)
```
- SSH tunnel (if admin bound locally):
```
ssh -N -L 3333:127.0.0.1:3333 user@<server_ip>
```
- Test SMTP:
```
swaks --to you@lab.tld --server <smtp_host>:587 --tls \
  --auth LOGIN --auth-user '<smtp_user>' --auth-password '<smtp_pass>'
```
- Group CSV:
```
cat > targets.csv <<'CSV'
First Name,Last Name,Email,Position
Alice,Anderson,alice@victim.lab,Engineer
CSV
```
- Template snippet:
```
<a href="{{.URL}}">Verify your account</a>
<img src="{{.Tracker}}" style="display:none" alt=""/>
```
- Landing: enable Capture Submitted Data + Redirect.
- Campaign: set URL to http(s)://<phish_domain>, select Template, Landing Page, SMTP, Group → Launch → Monitor.

## Summary
Part 1 focuses on getting Gophish running and assembling the core components of a phishing campaign in an authorized lab: install/start Gophish, secure the admin UI, configure SMTP, build a landing page with capture/redirect, create an email template with tracking, import target users, and launch a campaign. The keys to success are controlling access to the admin interface, ensuring deliverability via a valid SMTP relay, setting the correct Campaign URL to your phishing domain, and validating end-to-end capture before launching to your test group.