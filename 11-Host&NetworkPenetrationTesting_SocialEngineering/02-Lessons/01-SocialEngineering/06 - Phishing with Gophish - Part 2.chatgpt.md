# Phishing with Gophish – Part 2 (eJPT)

Note: The transcript for “06 - Phishing with Gophish - Part 2.mp4” was not provided. The notes below are inferred conservatively from the filename and the Social Engineering module context. They reflect a typical eJPT lab workflow for creating, launching, and monitoring a controlled phishing campaign in Gophish. Use strictly in a lab or with explicit written authorization.

## What the video covers (Introduction / big picture)
- Building an end-to-end phishing simulation in a controlled environment using Gophish.
- Creating a Sending Profile (SMTP), Email Template, Landing Page (capture credentials), and Target Group(s).
- Launching a campaign, setting the correct “URL” for tracking, and monitoring results (sent/opened/clicked/submitted).
- Safe, lab-only setup with a local SMTP sink to avoid sending real email.

## Flow (ordered)
1. Start Gophish admin and phishing servers (admin on 127.0.0.1:3333 by default; phish on 0.0.0.0:80/443).
2. Configure a lab-only SMTP Sending Profile (e.g., MailHog/smtp4dev) and test a message.
3. Create an Email Template:
   - Use {{.FirstName}} and other fields for personalization.
   - Insert {{.URL}} as the phishing link.
   - Add {{.Tracker}} to count opens (optional).
4. Create a Landing Page:
   - Import HTML or use a simple login form.
   - Enable “Capture Submitted Data” (and “Capture Passwords” if needed).
   - Set a benign “Redirect to” URL after submission (e.g., https://example.com/).
5. Create a Users & Groups list (test accounts only).
6. Set up hostnames for lab realism (e.g., intranet.test mapped in /etc/hosts).
7. Create and launch a Campaign:
   - Choose Sending Profile, Template, Landing Page, and Group.
   - Set the Campaign “URL” to the phishing server’s external address/hostname recipients will click (e.g., http://intranet.test).
8. Monitor campaign results in Gophish dashboard (timeline and per-recipient status).
9. Export results (CSV) if needed, and tear down lab services.

## Tools highlighted
- Gophish (open-source phishing framework with admin GUI and phishing web server).
- MailHog (or smtp4dev/Mailtrap) as a lab SMTP sink to safely capture emails.
- swaks (or openssl s_client) to test SMTP connectivity.
- Docker (optional) to run MailHog quickly.
- A text editor and browser for templates/landing pages.

## Typical command walkthrough (detailed, copy-paste friendly)
The commands below assume a Linux lab host. Adapt paths/versions/ports as needed.

- Start a safe lab SMTP sink (MailHog) with Docker:
```
docker run -d --name mailhog -p 1025:1025 -p 8025:8025 mailhog/mailhog
```
- Verify MailHog UI (open http://127.0.0.1:8025) and SMTP (listening on 127.0.0.1:1025).

- Optional: Test SMTP delivery to MailHog using swaks:
```
sudo apt-get update && sudo apt-get install -y swaks
swaks --server 127.0.0.1:1025 --to alice@lab.test --from it@lab.test \
      --header "Subject: Test via MailHog" --body "This is a lab test email."
```

- Run Gophish (if already extracted). Bind to low ports without root:
```
# From inside the Gophish directory (adjust path to the binary)
sudo setcap 'cap_net_bind_service=+ep' ./gophish
./gophish
```
- On first run, Gophish prints the admin login (username and a generated password) and the admin URL (default: https://127.0.0.1:3333). If you don’t see credentials, check the console output. Keep the admin interface bound to 127.0.0.1 for safety.

- Optional: Edit config.json to confirm/administer interfaces (restart Gophish after changes):
```
# Sample snippet — adjust as needed
{
  "admin_server": {
    "listen_url": "127.0.0.1:3333",
    "use_tls": true,
    "cert_path": "gophish_admin.crt",
    "key_path": "gophish_admin.key"
  },
  "phish_server": {
    "listen_url": "0.0.0.0:80",
    "use_tls": false
  }
}
```

- Configure a lab hostname to make links look realistic (maps to your Gophish host IP):
```
# Replace 10.10.10.5 with your Gophish phishing server IP
echo "10.10.10.5 intranet.test" | sudo tee -a /etc/hosts
```

- Gophish GUI steps (summarized for copy/paste content):
  1) Sending Profiles → New Profile (use MailHog SMTP)
     - Name: Lab-MH
     - SMTP Host: 127.0.0.1:1025
     - Username/Password: leave blank (MailHog typically doesn’t require auth)
     - Use TLS: off (MailHog default)
     - Send Test Email to yourself; confirm it appears in MailHog UI.
  2) Email Templates → New Template
     - Name: Password Reset
     - Subject: Action Required: Password Reset
     - Body (HTML). Example:
```
<p>Hi {{.FirstName}},</p>
<p>We detected a login from a new device. Please verify your account:</p>
<p><a href="{{.URL}}">Verify your account</a></p>
{{.Tracker}}
<p>Thanks,<br>IT Support</p>
```
  3) Landing Pages → New Page
     - Name: Simple Login
     - Check: Capture Submitted Data, Capture Passwords
     - Redirect to: https://example.com/
     - HTML (minimal example that Gophish can rewrite to capture):
```
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Sign In</title></head>
<body>
  <h2>Sign In</h2>
  <form method="POST">
    <label>Username <input type="text" name="username"></label><br>
    <label>Password <input type="password" name="password"></label><br>
    <button type="submit">Sign In</button>
  </form>
</body>
</html>
```
  4) Users & Groups → New Group → Add users or import CSV:
```
First Name,Last Name,Email
Alice,Example,alice@lab.test
Bob,Example,bob@lab.test
```
  5) Campaigns → New Campaign
     - Name: Lab Campaign 01
     - Email Template: Password Reset
     - Landing Page: Simple Login
     - URL: http://intranet.test
       - Important: This must be the exact host/port users will click and that resolves to your Gophish phishing server.
     - Sending Profile: Lab-MH
     - Groups: Select the test group
     - Launch

- Monitor results:
  - Campaigns → click your campaign → see per-user events (Email Sent, Opened, Clicked Link, Submitted Data).
  - Export results via the “Export” button (CSV).

- Tear down lab services (when done):
```
docker stop mailhog && docker rm mailhog
# Stop Gophish with Ctrl+C in its terminal
```

## Practical tips
- Ethics and scope:
  - Do this only in a lab or with explicit, written authorization. Use test accounts/domains.
  - Keep the Gophish admin interface bound to 127.0.0.1 and change the initial admin password immediately.
- SMTP and delivery:
  - Use a sink (MailHog, smtp4dev, Mailtrap) for labs to avoid sending real emails.
  - If you test a real relay in a permitted environment, ensure the SMTP creds are scoped and revocable.
- Campaign URL accuracy:
  - The Campaign “URL” must match what recipients will resolve/click (hostname and port). Mismatches break tracking and form capture.
- Landing page fidelity:
  - Complex JavaScript or CSRF tokens on imported pages can prevent capture. Use a simplified login form when learning.
  - Use “Redirect to” a benign site after capture to simulate user flow without causing harm.
- Tracking expectations:
  - {{.Tracker}} relies on images loading. Many mail clients block images; opens may be undercounted.
  - Click and submit events are more reliable for measurement.
- Data handling:
  - Only capture what is authorized. Securely store and delete lab data after exercises.
- Troubleshooting:
  - If “Send Test Email” fails, verify firewall rules and test SMTP with swaks.
  - If clicks aren’t recorded, confirm DNS/hosts mapping and that the rid parameter remains intact in the URL.
  - Check Gophish logs in the terminal for errors.

## Minimal cheat sheet (one-screen flow)
- Start MailHog:
```
docker run -d --name mailhog -p 1025:1025 -p 8025:8025 mailhog/mailhog
```
- Run Gophish:
```
sudo setcap 'cap_net_bind_service=+ep' ./gophish
./gophish
```
- Hosts mapping:
```
echo "10.10.10.5 intranet.test" | sudo tee -a /etc/hosts
```
- Gophish GUI:
  1) Sending Profile → 127.0.0.1:1025 (no TLS, no auth) → Test to MailHog.
  2) Email Template → subject + body with {{.URL}} and {{.Tracker}}.
  3) Landing Page → enable “Capture Submitted Data/Passwords” + Redirect.
  4) Users & Groups → add test recipients.
  5) Campaign → select above + URL: http://intranet.test → Launch.
  6) Monitor results → Export → Tear down.

## Summary
This session (inferred Part 2) completes the hands-on Gophish workflow: creating SMTP profiles, email templates, landing pages with data capture, target groups, and launching a campaign. The key technical details are setting a safe lab SMTP sink, ensuring the Campaign “URL” matches the hostname users resolve, and using {{.URL}} and {{.Tracker}} in templates. Monitoring in Gophish provides visibility into sent/opened/clicked/submitted events. Always keep activities strictly within authorized scope and a lab environment.