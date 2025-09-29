# What the video covers (Introduction / big picture)

Note: No transcript was provided. The following is inferred conservatively from the filename and module context (02-Governance, Risk & Compliance). Details may vary slightly from the actual video.

This session introduces the role of common security standards, frameworks, and guidelines in Governance, Risk, and Compliance (GRC) and shows how a junior penetration tester can align their methodology, scope, evidence, and reporting to them. It distinguishes between standards vs frameworks vs guidelines, surveys widely referenced bodies of knowledge (e.g., NIST, ISO/IEC, CIS, OWASP, MITRE), and highlights assessment-specific methodologies such as PTES, NIST SP 800-115, OSSTMM, and OWASP Testing Guide. It also touches on regulatory regimes (PCI DSS, HIPAA, GDPR) and how to map findings and recommendations to control frameworks (e.g., NIST CSF, CIS Controls) for business value and audit-readiness.

# Flow (ordered)

1. Why standards/frameworks/guidelines matter to pentesters (consistency, legality, business alignment)
2. Terminology and differences
   - Standard vs Framework vs Guideline vs Baseline vs Regulation vs Control vs Policy/Procedure
3. Governance and risk context
   - Control categories (administrative/technical/physical), risk reduction, auditability
4. Key enterprise frameworks
   - NIST Cybersecurity Framework (CSF), ISO/IEC 27001/27002, CIS Critical Security Controls, COBIT
5. Risk frameworks
   - NIST RMF (SP 800-37), NIST SP 800-30 (Risk Assessment), ISO 31000, FAIR (high level)
6. Assessment and testing methodologies
   - PTES, NIST SP 800-115, OSSTMM, OWASP Testing Guide, OWASP ASVS/MASVS
7. Threat-informed testing references
   - MITRE ATT&CK and common TTP mapping
8. Industry/regulatory baselines
   - PCI DSS, HIPAA, GDPR, SOC 2, FedRAMP (as context drivers for scope and evidence)
9. Practical application for eJPT engagements
   - Scoping/RoE, selecting a methodology, mapping findings to controls, referencing standards in reports
10. Takeaways and how to keep a personal reference pack

# Tools highlighted

- None (conceptual video). It references documents and methodologies rather than software tools.
- Practitioner resources frequently referenced:
  - NIST SP 800-115, NIST CSF, NIST SP 800-53/30/37/61
  - ISO/IEC 27001/27002
  - CIS Critical Security Controls, CIS Benchmarks
  - OWASP WSTG, OWASP ASVS, OWASP Top 10, MASVS
  - PTES, OSSTMM
  - MITRE ATT&CK
  - PCI DSS, HIPAA, GDPR (regulatory context)

# Typical command walkthrough (detailed, copy-paste friendly)

Because this is a GRC/standards topic, the “commands” are about assembling and searching a local reference pack, plus generating engagement templates you can reuse.

- Create a local reference folder and fetch key documents/pages

```
mkdir -p ~/eJPT/GRC-refs && cd ~/eJPT/GRC-refs

# Core testing methodologies
curl -L -o NIST_SP_800-115.pdf https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf
curl -L -o OSSTMM_3.pdf https://www.isecom.org/OSSTMM.3.pdf
curl -L -o PTES_Main.html http://www.pentest-standard.org/index.php/Main_Page

# OWASP references
curl -L -o OWASP_WSTG.html https://owasp.org/www-project-web-security-testing-guide/
curl -L -o OWASP_ASVS_v4.0.3.pdf https://github.com/OWASP/ASVS/releases/download/v4.0.3/OWASP_Application_Security_Verification_Standard_4.0.3-en.pdf
curl -L -o OWASP_Top10.html https://owasp.org/www-project-top-ten/

# Governance frameworks
curl -L -o NIST_CSF.html https://www.nist.gov/cyberframework
curl -L -o NIST_SP_800-53.html https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

# Threat-informed testing
curl -L -o MITRE_ATTACK.html https://attack.mitre.org/

# Regulatory context pages (overview pages)
curl -L -o PCI_DSS.html https://www.pcisecuritystandards.org/standards/pci-dss
curl -L -o CIS_Controls.html https://www.cisecurity.org/controls
```

- Convert NIST SP 800-115 to text and search key scoping/reporting terms

```
sudo apt-get update && sudo apt-get install -y poppler-utils
pdftotext NIST_SP_800-115.pdf NIST_SP_800-115.txt

# Find references to scope, authorization, evidence, reporting, rules of engagement
grep -niE 'scope|authorization|rules of engagement|evidence|report' NIST_SP_800-115.txt | head -n 40
```

- Generate a Penetration Testing Methodology (PTES-aligned) template you can tailor per engagement

```
cat > pentest-methodology.md <<'EOF'
# Penetration Testing Methodology (PTES-aligned)

1. Pre-Engagement
   - Objectives, success criteria, in/out of scope, RoE, legal authorization, data handling, contacts.

2. Intelligence Gathering (Recon)
   - Passive/active recon, OSINT, service enumeration.

3. Threat Modeling
   - Identify likely adversaries/TTPs (map to MITRE ATT&CK where relevant).

4. Vulnerability Analysis
   - Identify and validate weaknesses; align with OWASP WSTG/ASVS for web.

5. Exploitation
   - Controlled exploitation per RoE. Avoid prohibited techniques. Record evidence.

6. Post-Exploitation
   - Privilege escalation, pivoting (if allowed), data handling, cleanup.

7. Reporting
   - Executive summary; technical details; risk rating; business impact; remediation mapped to:
     - NIST CSF functions/categories
     - CIS Controls (where applicable)
     - Relevant regulatory requirements (PCI/HIPAA/GDPR, if applicable)
   - Methodology references: PTES, NIST SP 800-115, OSSTMM, OWASP WSTG/ASVS.

EOF
```

- Create a Rules of Engagement (RoE) template with key GRC elements

```
cat > rules-of-engagement_template.md <<'EOF'
# Rules of Engagement (RoE) - Template

Authorization
- Written authorization granted by: [Name/Title]
- Effective dates/times (timezone):
- Emergency stop phrase:

Scope
- In-scope systems/hosts/domains:
- Out-of-scope systems:
- Testing windows/change freeze periods:
- Third-party owned assets (approval attached?):

Permitted/Prohibited Actions
- Permitted: [e.g., password spraying, phishing if approved, limited DoS?]
- Prohibited: [e.g., destructive tests, production data exfiltration, long DoS]

Data Handling
- Sensitive data categories expected (PCI, PHI, PII):
- Data minimization, storage encryption, retention period, destruction method:
- Evidence handling and chain of custody:

Operational Safety
- Service impact coordination, maintenance windows, point-of-contact on-call:
- Incident handling/notification path:

Legal/Compliance
- Applicable frameworks/regulations (e.g., PCI DSS, HIPAA, GDPR):
- Liability, confidentiality, export compliance:

Deliverables
- Reporting format, interim updates cadence, final presentation:
- Mapping to frameworks (NIST CSF, CIS Controls, OWASP ASVS):
EOF
```

- Optional: simple evidence log you can fill during testing

```
cat > evidence_log.csv <<'EOF'
Timestamp,Asset,Finding,Method/Tool,Evidence Path,Severity,Framework Mapping,Notes
2025-01-01T10:00Z,web1.example.com,Reflected XSS,WSTG-CLNT-02,./evidence/xss-web1.png,Medium,OWASP Top10:A03,Session not invalidated
EOF
```

# Practical tips

- Ask first: Which framework(s) does the client already use? Tailor your scope, depth, and reporting to those (e.g., ASVS L2/L3 for web, PCI DSS for cardholder data).
- Pick a testing standard and cite it: PTES or NIST SP 800-115 for overall methodology; OWASP WSTG/ASVS for web; OSSTMM for network/systems.
- Be precise with terminology:
  - Standard = specific, testable requirements (e.g., PCI DSS).
  - Framework = structured model to organize controls/processes (e.g., NIST CSF, ISO 27001).
  - Guideline = recommended practices/best effort (e.g., OWASP Top 10, CIS Benchmarks).
  - Baseline = minimum configuration/security level (e.g., CIS Benchmarks, DISA STIGs).
  - Regulation = law/mandatory (e.g., GDPR, HIPAA).
- Map findings and fixes: For each issue, include business impact, likelihood, and remediation tied to controls (e.g., CIS 6.3: centralize MFA; NIST CSF PR.AC).
- Don’t claim compliance: As a pentest, you provide evidence and recommendations; formal certification/audit is a separate process.
- Document authorization and data handling: RoE must explicitly authorize the test, define prohibited actions, and define how you protect client data.
- Use threat-informed language: Reference MITRE ATT&CK TTPs for exploited behaviors to help defenders link findings to detection engineering.
- Provide control-aligned remediation: Recommend CIS Controls or ISO 27002 practices so fix owners can trace your advice to recognized controls.
- Maintain a personal “reference pack” offline: PDFs/links for NIST SP 800-115, OWASP WSTG/ASVS, OSSTMM, NIST CSF, CIS Controls.

# Minimal cheat sheet (one-screen flow)

- Terms
  - Standard: specific requirement (PCI DSS)
  - Framework: structure for controls/processes (NIST CSF, ISO 27001)
  - Guideline: best practice (OWASP Top 10, CIS Benchmarks)
  - Baseline: minimum config (CIS Benchmarks, STIGs)
  - Regulation: legal mandate (GDPR, HIPAA)
- Pick a methodology
  - Overall: PTES or NIST SP 800-115
  - Web: OWASP WSTG + ASVS (choose level)
  - Network/Systems: OSSTMM
- Scope and RoE must include
  - In/Out of scope; permitted/prohibited actions; testing windows; authorization; data handling; emergency contacts
- Map findings to
  - NIST CSF: Identify/Protect/Detect/Respond/Recover
  - CIS Controls v8: specific safeguards (e.g., 6.3 MFA)
  - OWASP Top 10/ASVS items for app vulns
  - Regulatory relevance if applicable (PCI/HIPAA/GDPR)
- Cite references in report
  - Methodology: PTES/NIST 800-115/OWASP WSTG
  - Control mapping: NIST CSF/CIS Controls/ISO 27002
  - Threat model: MITRE ATT&CK TTPs

# Summary

This session orients you to the ecosystem of security standards, frameworks, and guidelines and how to use them to make your penetration tests scoped, defensible, and valuable to the business. Know the differences in terms, select an appropriate testing methodology (PTES, NIST SP 800-115, OWASP WSTG/ASVS, OSSTMM), and align your findings and recommendations to control frameworks (NIST CSF, CIS Controls, ISO 27002), with regulatory awareness (PCI, HIPAA, GDPR). Use a solid RoE, keep an offline reference pack, and consistently map findings to recognized controls and TTPs to aid remediation and detection.