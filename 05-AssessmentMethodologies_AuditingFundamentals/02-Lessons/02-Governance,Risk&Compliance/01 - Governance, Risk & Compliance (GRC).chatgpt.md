# What the video covers (Introduction / big picture)

Note: The transcript for “01 - Governance, Risk & Compliance (GRC).mp4” isn’t available. The following summary is a conservative, eJPT-aligned reconstruction based on the filename and typical GRC fundamentals taught to junior pentesters.

- Introduces Governance, Risk, and Compliance (GRC) and why it matters to penetration testers.
- Clarifies how policy/standards/procedures guide technical security work.
- Explains risk fundamentals (threats, vulnerabilities, likelihood, impact), risk appetite/tolerance, and treatment options (accept, avoid, mitigate, transfer).
- Overviews common frameworks (NIST CSF, ISO/IEC 27001, CIS Controls, NIST SP 800-53, PCI DSS) and mapping findings to controls.
- Distinguishes vulnerability scanning vs penetration testing in a governance context.
- Covers ethics, scope, Rules of Engagement (ROE), and legal documentation (NDA, SOW, permission to test).
- Shows how to translate technical findings into risk for business stakeholders (CVSS, severity, control gaps, POA&M, risk register).

# Flow (ordered)

1. Why GRC matters to pentesting: aligning security activities with business objectives and legal obligations.
2. Governance basics:
   - Policy vs Standard vs Procedure vs Guideline.
   - Data classification and ownership.
   - Roles/responsibilities (Board, CISO, system owners, risk owners).
3. Risk fundamentals:
   - CIA triad; threat vs vulnerability vs risk.
   - Likelihood × Impact; qualitative vs quantitative assessments.
   - Risk appetite/tolerance; KRIs/KPIs.
   - Control types: administrative, technical, physical; and classes: preventive, detective, corrective, deterrent, compensating.
4. Risk management lifecycle:
   - Identify assets → threats → vulnerabilities → assess → treat → monitor.
   - Residual risk and acceptance criteria.
5. Compliance overview:
   - Regulatory, contractual, and internal compliance (e.g., GDPR, HIPAA, PCI DSS).
   - Evidence, audits, and control testing.
6. Frameworks and control mapping:
   - NIST CSF functions (Identify, Protect, Detect, Respond, Recover).
   - ISO/IEC 27001 Annex A; NIST 800-53; CIS Critical Security Controls.
7. Pre-engagement for pentesters:
   - Legal docs: NDA, SOW, MSA, ROE, Permission to Test letter.
   - Scope, out-of-scope, time windows, limitations, escalation paths.
8. Execution with GRC mindset:
   - Minimal-impact testing, logging, evidence handling/chain-of-custody.
   - Deconfliction and secure storage of data.
9. Reporting and risk translation:
   - CVSS scoring, business impact, affected assets, likelihood, exploitability.
   - Control gap mapping and actionable remediation tied to frameworks.
10. Vulnerability management vs pentesting:
    - Continuous scan/patch vs goal-oriented exploitation and validation.
    - POA&M and risk register updates.
11. Communication:
    - Executive summary for leadership; technical appendix for engineers.
    - Metrics and continuous improvement.
12. Wrap-up: ethical responsibility and adding business value with clear, risk-focused outputs.

# Tools highlighted

- Frameworks/standards:
  - NIST Cybersecurity Framework (CSF), NIST SP 800-53
  - ISO/IEC 27001/27002
  - CIS Critical Security Controls
  - PCI DSS, HIPAA, GDPR (examples of regulatory/contractual obligations)
- Risk and severity:
  - CVSS v3.1 (for consistent severity ratings)
  - Risk matrix (likelihood × impact)
- Pentest-support tools tied to GRC evidence:
  - Nmap (service/port discovery, vuln and TLS scripts)
  - curl (HTTP headers/security posture)
  - openssl (certificate/cipher inspection)
  - OS-native checks: Linux (sshd -T, systemctl, iptables/nft), Windows (systeminfo, auditpol, net accounts)
  - Optional: authenticated scanners (Nessus, OpenVAS/Greenbone) for vulnerability management context

# Typical command walkthrough (detailed, copy-paste friendly)

Replace TARGET or TARGETS as needed. These commands help gather evidence that maps to common controls (inventory, hardening, patching, encryption, logging).

Asset discovery and service inventory
```
# Fast baseline: top-ports, service/version, default NSE scripts, OS guess
nmap -Pn -T4 -sS -sV -sC -O -oA scans/initial TARGET

# Full TCP sweep then targeted service/version on discovered ports
nmap -Pn -T4 -p- --min-rate 2000 -oA scans/full_tcp TARGET
ports=$(awk -F/ '/open/ {print $1}' scans/full_tcp.nmap | paste -sd, -)
[ -n "$ports" ] && nmap -Pn -T4 -sV -sC -p "$ports" -oA scans/versions TARGET
```

Vulnerability-oriented enumeration
```
# Use Nmap vuln scripts for a quick, light check (not a replacement for scanners)
[ -n "$ports" ] && nmap -Pn -sV --script vuln -p "$ports" -oA scans/vuln TARGET

# HTTP quick posture: server banner and security headers (CIS/PCI-aligned hints)
curl -s -I http://TARGET | egrep -i 'server|x-powered-by|strict-transport|content-security|x-frame|x-content|referrer|permissions'
curl -s -I https://TARGET | egrep -i 'server|x-powered-by|strict-transport|content-security|x-frame|x-content|referrer|permissions'
```

TLS/cipher and certificate checks
```
# Enumerate TLS ciphers on common HTTPS ports
nmap -Pn --script ssl-enum-ciphers -p 443,8443,9443 TARGET -oA scans/ssl_ciphers

# Inspect certificate chain and parameters
openssl s_client -connect TARGET:443 -servername TARGET </dev/null 2>/dev/null | openssl x509 -noout -text
```

Linux configuration/compliance spot checks
```
# OS build and kernel
uname -a
cat /etc/os-release

# Accounts and password policy (maps to access control/hardening)
grep -E 'PASS_(MAX|MIN)_DAYS|PASS_WARN_AGE' /etc/login.defs
chage -l root 2>/dev/null || true
grep -R "pam_pwquality" /etc/pam.d/ 2>/dev/null | head

# SSH hardening snapshot (controls: secure configuration, remote access)
sshd -T 2>/dev/null | egrep 'permitrootlogin|passwordauthentication|challenge|ciphers|kexalgorithms|macs'
grep -E '^(PermitRootLogin|PasswordAuthentication|ChallengeResponseAuthentication|Ciphers|KexAlgorithms|MACs)' /etc/ssh/sshd_config 2>/dev/null

# Network exposure and firewall (controls: boundary defense)
ss -tulpen | head -n 50
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null

# Services and autostart (reduce attack surface)
systemctl list-unit-files --type=service --state=enabled | sed -n '1,40p'

# Patch status (Debian/Ubuntu)
sudo apt update >/dev/null 2>&1 && sudo apt -s upgrade | grep -E 'upgraded|newly installed|to remove|not upgraded'
# Patch status (RHEL/CentOS/Alma/Rocky)
sudo yum -q check-update || sudo dnf -q check-update
```

Windows configuration/compliance spot checks (run in an elevated prompt)
```
:: System build and hotfixes
systeminfo
wmic qfe list brief /format:table

:: Password policy
net accounts

:: Audit policy (logging/monitoring controls)
auditpol /get /category:*

:: Services (autostart and running)
wmic service get Name,State,StartMode | findstr /R /C:"Auto.*Running"

:: SMB encryption posture (example hardening evidence)
powershell -NoProfile -Command "Get-SmbServerConfiguration | Select EncryptData,RejectUnencryptedAccess | Format-List"
```

Evidence packaging and notes
```
# Create a dated evidence bundle (adjust path)
mkdir -p evidence/scans && cp scans/* evidence/scans/ 2>/dev/null || true
date +"%F_%T" > evidence/collection_timestamp.txt
tar -czf evidence_bundle.tgz evidence/
```

Reporting tie-ins (risk and controls)
- Rate findings with CVSS v3.1; capture AV/AC/PR/UI/S/C/I/A vectors explicitly.
- Map each finding to control frameworks (e.g., CIS 4.1 for secure configurations; NIST CSF Protect/PR.AC).
- Provide risk statement: Asset + Vulnerability + Threat + Impact + Likelihood + Business consequence.

# Practical tips

- Always secure written authorization (ROE, SOW, Permission to Test) before any activity.
- Align tests to business scope and data classification; minimize impact and avoid out-of-scope assets.
- Keep precise timestamps, commands run, and raw outputs for auditability and chain of custody.
- Translate tech to risk: for each issue, state affected control(s), exploitability, business impact, and remediation with priority.
- Use CVSS consistently but adjust overall risk with business context (compensating controls, exposure window).
- Offer control-mapped remediation: reference CIS, NIST CSF, or ISO 27002 items to guide hardening.
- Distinguish vulnerability scanning (breadth, continuous) from pentesting (depth, validation).
- Maintain a simple risk register or POA&M entry per finding: owner, due date, status, residual risk.

# Minimal cheat sheet (one-screen flow)

- Governance: Policy → Standard → Procedure → Guideline; data classification; roles.
- Risk: Threat × Vulnerability × Likelihood × Impact; appetite/tolerance; treatment (accept/avoid/mitigate/transfer); residual risk.
- Controls: administrative, technical, physical; preventive, detective, corrective, deterrent, compensating.
- Frameworks: NIST CSF, ISO 27001/27002, CIS Controls, NIST 800-53; regulatory: PCI, HIPAA, GDPR.
- Pre-engagement: NDA, SOW, ROE, Permission to Test, scope/time windows.

Quick commands
```
# Discovery and services
nmap -Pn -T4 -sS -sV -sC -O -oA scans/initial TARGET
nmap -Pn -T4 -p- --min-rate 2000 -oA scans/full_tcp TARGET
ports=$(awk -F/ '/open/ {print $1}' scans/full_tcp.nmap | paste -sd, -); [ -n "$ports" ] && nmap -Pn -sV -sC -p "$ports" -oA scans/versions TARGET

# Vuln/TLS/HTTP posture
[ -n "$ports" ] && nmap -Pn -sV --script vuln -p "$ports" -oA scans/vuln TARGET
nmap -Pn --script ssl-enum-ciphers -p 443,8443 TARGET -oA scans/ssl_ciphers
curl -s -I https://TARGET | egrep -i 'strict-transport|content-security|x-frame|x-content|referrer|permissions'
```

- Linux checks: sshd -T; grep in /etc/ssh/sshd_config; ss -tulpen; iptables -S or nft list ruleset; apt -s upgrade or yum/dnf check-update.
- Windows checks: systeminfo; wmic qfe; net accounts; auditpol /get /category:*; services list.

Reporting
- Use CVSS v3.1; map to controls (e.g., CIS 5.2, NIST PR.AC).
- Provide remediation and POA&M entry; track residual risk and owner.

# Summary

This GRC intro ties pentesting to business risk. Governance provides policy and direction; risk processes prioritize what matters; compliance ensures legal and contractual obligations are met. As a junior pentester, you must operate within clear scope and authorization, gather defensible evidence, and translate technical findings into actionable, control-mapped risk insights (CVSS, likelihood/impact, remediation). Use lightweight commands to collect posture evidence (services, configuration, patching, crypto), then report clearly to support risk owners and continuous improvement.