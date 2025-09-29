# What the video covers (Introduction / big picture)
Note: No transcript was provided for “07 - Types of Security Audits.mp4” (folder: 01-IntroductiontoSecurityAuditing). The following is a conservative, experience-based summary of what this lesson typically covers in an eJPT-style introduction.

Big picture: The lesson distinguishes the major types of security audits and assessments, why they exist, how they differ (goals, scope, knowledge model, and evidence), and when to choose each. It positions penetration testing as one of several audit/assessment types and explains how rules of engagement, assurance party, and compliance drivers shape methodology and deliverables.

# Flow (ordered)
1. Define “security audit” vs “security assessment” vs “penetration test”
   - Audit: formal, evidence-based conformance check against a standard or control set.
   - Assessment: broader evaluation of risk and control effectiveness.
   - Penetration test: goal-oriented technical test to identify exploitable weaknesses.
2. Assurance party and independence
   - First-party (internal), second-party (customer-to-supplier), third-party (independent/attestation).
3. Scope perspective
   - Internal vs external; target classes (network, application, cloud, identity/AD, physical, social engineering).
4. Knowledge model
   - Black-box (no prior knowledge), gray-box (limited knowledge/credentials), white-box (full design/credentials).
5. Objective-based types
   - Compliance audits (e.g., ISO 27001, SOC 2, PCI DSS, HIPAA, NIST CSF/800-53, CIS Controls).
   - Risk/controls audits (policy-to-practice, ITGC, configuration/hardening reviews).
   - Technical testing (vulnerability assessments vs penetration tests vs red/purple team).
6. Specialized audits
   - Web/API/mobile, wireless, cloud (AWS/Azure/GCP), Active Directory, network device config, physical security, social engineering.
7. Rules of engagement and constraints
   - Authorization, scope, timeboxing, safety, data handling, success criteria.
8. Evidence and reporting
   - What constitutes sufficient evidence, risk rating, reproducibility, remediation guidance, executive summary vs technical detail.
9. Selecting the right type
   - Match business goals and constraints (regulatory deadlines, M&A, incident response, new product launch, supplier assurance).
10. Next steps
   - Plan scope, map controls, choose methodology, select tools, define deliverables and communication cadence.

# Tools highlighted
(Representative examples; exact tools may vary. Use only with explicit authorization.)
- Compliance/control assessment
  - CIS-CAT (CIS Benchmarks), OpenSCAP/SCAP Workbench, Lynis (Linux), Microsoft Security Compliance Toolkit (Policy Analyzer, LGPO), Nipper (network device configs).
- Evidence/logging
  - SIEMs (Splunk, ELK/OpenSearch), OSQuery, Windows Event Viewer/wevtutil, auditd.
- Technical assessment (names only; methodology depends on scope/authorization)
  - Network/service discovery and vulnerability management: Nessus, OpenVAS/Greenbone.
  - Web testing: Burp Suite, OWASP ZAP, dirsearch/gobuster (content discovery).
  - Traffic analysis: Wireshark.
  - Identity/AD posture: PingCastle, BloodHound (authorized environments).
- Cloud posture (read-only, compliance-driven)
  - ScoutSuite, Prowler (AWS), Steampipe + compliance mods.

# Typical command walkthrough (detailed, copy-paste friendly)
Run only on systems and accounts you are explicitly authorized to audit. These examples focus on configuration/evidence collection and posture verification, not exploitation.

Windows host posture/evidence (cmd/PowerShell)
```bat
:: System/OS and patch status
systeminfo
wmic qfe list brief /format:table

:: Or PowerShell (run as admin if possible)
powershell -NoProfile -Command "Get-HotFix | Sort-Object InstalledOn | Select-Object -Last 10"

:: Password and lockout policy (local or domain policy that applies)
net accounts

:: Export local security policy for review
secedit /export /cfg %USERPROFILE%\Desktop\secpol.cfg

:: Audit policy (verify auditing is enabled for key categories)
auditpol /get /category:*

:: Firewall profiles
netsh advfirewall show allprofiles

:: Running services (PowerShell)
powershell -NoProfile -Command "Get-Service | Where-Object {$_.Status -eq 'Running'} | Sort-Object Name | Format-Table -AutoSize"

:: Listening ports (PowerShell)
powershell -NoProfile -Command "Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Format-Table -AutoSize"

:: RDP setting (0 = allowed, 1 = denied)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections

:: SMB signing settings (server/workstation)
reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature
reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature

:: Windows Defender core status (PowerShell)
powershell -NoProfile -Command "Get-MpComputerStatus | Select AMServiceEnabled,AntispywareEnabled,RealTimeProtectionEnabled,AntimalwareEngineVersion"

:: BitLocker status (if applicable)
manage-bde -status

:: Recent Security log entries (read-only glance)
wevtutil qe Security /c:10 /f:text /rd:true

:: Effective Group Policy result (HTML report)
gpresult /H %USERPROFILE%\Desktop\gpresult.html
```

Linux host posture/evidence (bash; use sudo where needed)
```bash
# OS and kernel
uname -a
cat /etc/os-release

# Account policy (CIS-aligned parameters)
grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)' /etc/login.defs

# PAM hardening (presence of password quality / lockout)
grep -R "pam_pwquality|pam_cracklib|pam_faillock" /etc/pam.d 2>/dev/null

# SSH server hardening snapshot
sudo grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|KbdInteractiveAuthentication|MaxAuthTries|ClientAliveInterval|X11Forwarding)' /etc/ssh/sshd_config

# Services and sockets
systemctl --type=service --state=running --no-pager
ss -tulpen

# Firewall status (one of these will apply)
sudo ufw status verbose || sudo firewall-cmd --list-all || sudo iptables -S

# Update status (Debian/Ubuntu)
sudo apt update && apt list --upgradable

# Update status (RHEL/CentOS/Rocky/Alma)
sudo yum check-update || sudo dnf check-update

# Logging/auditing quick checks
sudo journalctl -p 3 -xb | head -n 100
sudo auditctl -s

# Critical file permissions
ls -l /etc/passwd /etc/shadow
```

Web/TLS spot-checks (authorized endpoints only)
```bash
# HTTP response headers (sanity checks: redirects, security headers)
curl -I https://your.app.example.com

# TLS certificate dates and subject/issuer
openssl s_client -connect your.app.example.com:443 -servername your.app.example.com -showcerts < /dev/null 2>/dev/null \
| openssl x509 -noout -dates -subject -issuer
```

Active Directory (from a domain-joined Windows endpoint; read-only)
```bat
:: Current user privileges and groups
whoami /all

:: Domain password policy
net accounts /domain

:: High-privileged groups (examples)
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain

:: Verify DC discovery
nltest /dsgetdc:yourdomain.local

:: Computer-scope GPO summary (text)
gpresult /R /SCOPE COMPUTER
```

Cloud (AWS) posture spot-checks (read-only; requires AWS CLI configured for your account)
```bash
# High-level account summary
aws iam get-account-summary --output table

# Users and roles (review for least privilege/MFA status via additional reports)
aws iam list-users --output table
aws iam list-roles --output table

# Generate and download IAM credential report (CSV for governance review)
aws iam generate-credential-report >/dev/null 2>&1; sleep 2
aws iam get-credential-report --query 'Content' --output text | base64 -d > credential-report.csv
```

# Practical tips
- Start with the objective: compliance attestation, risk reduction, or breach simulation dictates the type (audit vs assessment vs pentest vs red team).
- Fix scope and rules of engagement in writing. Define in-scope systems, time windows, data handling, and what “stop” conditions look like.
- Choose the knowledge model to match realism and constraints (white-box for depth and speed; black-box for realism; gray-box for balance).
- For compliance/control audits, map evidence to specific clauses (e.g., CIS, ISO, NIST) and be explicit about sampling and exceptions.
- Separate findings by business impact and likelihood; avoid tool-only severity. Add clear remediation steps and owners.
- Maintain a defensible evidence trail: screenshots, config exports, hashes of artifacts, timestamps, and where applicable, change tickets.
- Communicate early and often: pre-brief, daily syncs during testing, and an out-brief with prioritized remediation.
- Avoid scope creep; log out-of-scope issues separately for future cycles.
- Protect sensitive data: minimize collection, encrypt at rest, restrict access, and define a data destruction date.

# Minimal cheat sheet (one-screen flow)
- Pick the audit type by goal
  - Prove conformance → Compliance audit (ISO 27001, SOC 2, PCI DSS, HIPAA, CIS)
  - Validate control effectiveness → Security/controls audit (ITGC, config/hardening)
  - Find vulnerabilities broadly → Vulnerability assessment (non-exploit, breadth)
  - Demonstrate exploitability → Penetration test (goal/scenario-driven)
  - Test detection/response → Red team (adversary emulation), Purple team (collab)
  - Narrow technical scope → Web/API, Cloud, AD, Wireless, Physical, Social Eng.
- Scope dimensions
  - Party: internal, customer (2nd), independent (3rd)
  - Perspective: internal vs external
  - Knowledge: black / gray / white box
- Core deliverables
  - Executive summary, methodology, scope, evidence, reproducible steps (as applicable), risk ratings, remediation, and roadmap
- Safe, read-only posture checks (examples)
  - Windows: auditpol /get /category:*; net accounts; secedit /export
  - Linux: grep login.defs; inspect sshd_config; systemctl/ss; auditctl -s
  - Web/TLS: curl -I; openssl s_client | x509 -dates
  - AD: whoami /all; net accounts /domain; gpresult
  - Cloud (AWS): iam get-account-summary; credential report
- Reporting
  - Link each finding to a control/risk, add business impact, and provide practical remediation and verification steps.

# Summary
This lesson classifies the major types of security audits and assessments, contrasts them by goal, scope, knowledge model, and evidence requirements, and explains how to choose the right approach for a given business need. Compliance/control audits validate conformance and effectiveness; technical assessments and penetration tests identify weaknesses and demonstrate impact; specialized audits target domains like web, cloud, and identity. Success hinges on clear scope and authorization, appropriate methodology, disciplined evidence collection, and actionable reporting that aligns findings to business risk and remediation.