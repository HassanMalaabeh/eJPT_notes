# What the video covers (Introduction / big picture)
Note: The transcript isn’t provided; this summary is inferred conservatively from the filename and course context “03-FromAuditingtoPenetrationTesting”.

The video introduces Phase 1 of a security program: developing a security policy. It connects auditing and penetration testing by showing how a well-defined, risk-based security policy establishes the baseline for audits and sets the rules of engagement and scope for penetration tests. It clarifies policy vs standards vs procedures, outlines core policy components (access control, acceptable use, logging, incident response, vulnerability/patch management, remote access, third-party, etc.), and maps policy to frameworks (ISO 27001/27002, NIST, CIS Controls). It likely closes with how testers use policies to validate control effectiveness and how auditors measure compliance.

# Flow (ordered)
1) Identify business and legal drivers
- Business objectives, regulatory requirements (e.g., GDPR, HIPAA, PCI DSS), contractual obligations.

2) Establish governance and scope
- Define policy owners, approvers, stakeholders, and scope (org units, systems, cloud, third-parties).
- Clarify Policy vs Standard vs Procedure vs Guideline.

3) Asset inventory and data classification
- Catalog assets, define data classes (Public, Internal, Confidential, Restricted).

4) Risk assessment and threat modeling
- Use a lightweight method (e.g., NIST SP 800-30, CIS Risk Assessment). Prioritize risks.

5) Draft the top-level Security Policy
- High-level, mandatory statements covering key domains: acceptable use, access control, identity and auth, password, endpoint, network, remote access/VPN, wireless, logging/monitoring, incident response, vulnerability/patch, change management, backup/DR, physical, cloud/SaaS, encryption/key management, third-party/vendor, secure software development, data handling/retention.

6) Derive standards and procedures
- Concrete, testable requirements (e.g., password length ≥ 14, MFA required, SSH hardening), and step-by-step procedures.

7) Define enforcement, exceptions, and metrics
- Exception process, disciplinary/sanction statement, KPIs/KRIs (patch SLA, failed logins, incident MTTR), audit cadence.

8) Map to frameworks and controls
- Cross-reference ISO 27001 Annex A, NIST 800-53, CIS Controls v8. Ensure traceability.

9) Formal approval and communication
- Versioning, ownership, effective date, training and awareness plan.

10) Implement baseline configurations
- Golden images, GPOs, CIS Benchmarks, IaC baselines.

11) Validate via audit and penetration testing
- Rules of Engagement (scope, in/out of scope, time windows, contacts, data handling), testing frequency, remediation loop.

12) Continuous review and improvement
- Annual review or upon major change, lessons learned from incidents/tests.

# Tools highlighted
- Frameworks/standards: ISO/IEC 27001/27002, NIST SP 800-53, 800-30 (Risk), 800-61 (IR), CIS Controls v8, CIS Benchmarks, MITRE ATT&CK (threat-informed defense).
- Policy templates: SANS Security Policy Templates.
- Compliance baselining: CIS-CAT Lite, OpenSCAP (oscap), Lynis (Linux), Microsoft Security Compliance Toolkit (GPO baselines).
- Configuration/audit on endpoints:
  - Windows: secpol.msc, gpedit.msc, secedit, auditpol, net accounts, netsh advfirewall, Get-HotFix, PowerShell cmdlets.
  - Linux: grep/awk for config, pam_pwquality/pam_faillock, sshd -T, auditctl/ausearch, ufw/iptables, Lynis.
- Vulnerability management: Nessus/Greenbone (OpenVAS).
- Logging/monitoring: Windows Event Logs, Sysmon, auditd, SIEM (e.g., Wazuh/ELK).

# Typical command walkthrough (detailed, copy-paste friendly)
Use these to verify policy compliance during an audit or to prepare a penetration test against declared controls.

Linux (Debian/Ubuntu/RHEL-like)
```bash
# Password aging policy
grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)' /etc/login.defs

# PAM password complexity (Debian/Ubuntu)
grep -E '^\s*password\s+requisite\s+pam_pwquality' /etc/pam.d/common-password
grep -E '^\s*minlen|dcredit|ucredit|lcredit|ocredit' /etc/security/pwquality.conf 2>/dev/null

# PAM account lockout (RHEL/Rocky)
grep -E 'pam_faillock' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null
grep -E '^(deny|unlock_time|fail_interval)' /etc/security/faillock.conf 2>/dev/null

# SSH hardening
sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|kexalgorithms|ciphers|macs'
grep -E '^(PermitRootLogin|PasswordAuthentication|X11Forwarding|ClientAliveInterval|ClientAliveCountMax)' /etc/ssh/sshd_config

# Firewall status (Ubuntu)
ufw status verbose

# iptables (legacy firewall rules)
iptables -S
ip6tables -S

# Audit daemon status and rules
auditctl -s
auditctl -l 2>/dev/null

# Logging configuration
grep -E '^\s*space_left|action|max_log_file' /etc/audit/auditd.conf 2>/dev/null
grep -E '^\s*\*\.info' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null

# Installed security updates (Debian/Ubuntu)
apt list --upgradable 2>/dev/null | grep -i security

# Patch history (RPM-based)
rpm -qa --last | head

# Services exposure (compare against policy)
ss -tulpn

# World-writable or SUID files (baseline hardening)
find / -xdev -type f -perm -4000 -print 2>/dev/null | head -n 50

# Banner (legal notice)
grep -E 'Authorized uses only|unauthorized' /etc/issue /etc/issue.net 2>/dev/null

# Time sync (logging integrity)
timedatectl status
```

Windows (CMD)
```cmd
:: Local/Domain password policy
net accounts
net accounts /domain

:: Export Local Security Policy
secedit /export /cfg %USERPROFILE%\Desktop\secpol.inf

:: Audit policy (Advanced Audit Policy)
auditpol /get /category:*

:: Firewall profiles
netsh advfirewall show allprofiles

:: Hotfixes/patches
wmic qfe list brief

:: Local users and status
net user

:: Effective group policies applied
gpresult /r /scope computer

:: RDP configuration (Network Level Authentication)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication

:: SMB signing and LM/NTLM settings
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel
reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature
reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature
```

Windows (PowerShell)
```powershell
# Installed updates
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15

# Defender/AV status
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, RealTimeProtectionEnabled, NISEnabled, ISEnabled

# Local accounts and last logon
Get-LocalUser | Select-Object Name, Enabled, PasswordLastSet, LastLogon

# Firewall status
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# TLS/SSL protocol hardening (SCHANNEL)
Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" | Get-ChildItem

# Log sizes and retention
wevtutil el | ForEach-Object { wevtutil gl $_ } | Select-String -Pattern "channelName|maxSize"

# BitLocker status
Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus, VolumeStatus, KeyProtector
```

Cloud/SaaS policy spot-checks (illustrative)
```bash
# AWS: ensure MFA on root, no access keys on root
aws iam get-account-summary --query 'SummaryMap.{MFADevices:MFADevicesInUse,RootKeys:AccountAccessKeysPresent}'

# AWS: list users without MFA
aws iam list-virtual-mfa-devices --assignment-status Unassigned

# Microsoft 365: list users without MFA (requires MSOnline module)
powershell -Command "Import-Module MSOnline; Connect-MsolService; Get-MsolUser -All | Select DisplayName,UserPrincipalName,StrongAuthenticationMethods | Where-Object { -not $_.StrongAuthenticationMethods }"
```

# Practical tips
- Keep the top-level policy concise and technology-agnostic; push specifics to standards and procedures.
- Make controls testable: measurable requirements (e.g., “14+ char passwords, 3 failed attempts lockout for 15 min”).
- Use established baselines (CIS Benchmarks) to derive hardening standards; automate with GPOs, Ansible, or cloud policies.
- Define a clear exception process with risk acceptance by appropriate authority and expiry dates.
- Tie every policy statement to one or more risks and controls (traceability matrix improves audits).
- Include a sanction statement and user acknowledgment; display login banners where appropriate.
- For pentests, insist on written authorization and Rules of Engagement (scope, out-of-scope, time windows, credentials, data handling, stop conditions, PoC limits).
- Measure and iterate: set KPIs (patch SLA, MFA coverage, audit log coverage) and review at least annually or after major changes/incidents.
- Centralize logs and ensure time synchronization; without logs and correct time, incident response and testing evidence suffer.
- Vendor/third-party: require security clauses (MFA, logging, breach notification SLAs, data location) and perform due diligence.

# Minimal cheat sheet (one-screen flow)
- Drivers: regs + business goals → scope + owners
- Inventory + classify data
- Assess risk, prioritize
- Write top-level policy (mandatory, high-level)
- Derive standards/procedures (specific, testable)
- Map to ISO/NIST/CIS; define metrics/KPIs
- Approve, version, publish, train
- Implement baselines (GPO/CIS/Lynis/OpenSCAP)
- Validate: audit + pentest (ROE, scope, cadence)
- Exceptions with risk acceptance + expiry
- Monitor, report, improve (annual review)

# Summary
Phase 1 establishes the foundation: a clear, risk-based security policy that defines what must be protected and how. It distinguishes policy from standards and procedures, identifies key control areas, and aligns with recognized frameworks. The policy then drives baselines, auditing, and penetration testing—where ROE and scope are rooted in the policy, and testing validates that controls are not just documented, but effective. The included command sets let you quickly verify common policy requirements on Linux and Windows, bridging the gap from “paper” policy to real-world enforcement.