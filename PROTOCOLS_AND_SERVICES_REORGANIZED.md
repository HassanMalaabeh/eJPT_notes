# Protocols and Services Covered in eJPT Notes (Consolidated)

This reorganized outline deduplicates the topics from `PROTOCOLS_AND_SERVICES.md` while preserving their original context.

## Assessment Methodologies

### Footprinting & Scanning
- Active Information Gathering
- Networking Primer
  - Networking Fundamentals
  - Network Layer
  - Transport Layer (Part 1 & Part 2)
- Host Discovery Workflow
  - Network Mapping
  - Host Discovery Techniques
  - Ping Sweeps
  - Host Discovery with Nmap (Parts 1 & 2)
- Port Scanning Strategies
  - Port Scanning with Nmap (Parts 1 & 2)
  - Service Version & OS Detection
  - Nmap Scripting Engine (NSE) Overview
- Scan Evasion & Optimization
  - Firewall Detection & IDS Evasion
  - Optimizing Nmap Scans
  - Nmap Output Formats

### Enumeration
- Introduction to Enumeration
- Advanced Nmap Usage
  - Port Scanning & Enumeration with Nmap
  - Importing Nmap Scan Results into Metasploit
  - Port Scanning with Metasploit Auxiliary Modules
- Service Enumeration Playbooks
  - FTP Enumeration
  - SMB Enumeration
  - Web Server Enumeration
  - MySQL Enumeration
  - SSH Enumeration
  - SMTP Enumeration

### Vulnerability Assessment
- Windows Exposure Review
  - Overview of Windows Vulnerabilities
  - Frequently Exploited Windows Services
  - WebDAV Vulnerabilities
- Linux Exposure Review
  - Frequently Exploited Linux Services
  - Shellshock (CVE-2014-6271) Analysis
- Scanner Tooling
  - Vulnerability Scanning with Metasploit
  - Vulnerability Scanning with Nessus
  - Web Application Scanning with WMAP
- Threat Case Studies
  - EternalBlue (MS17-010)
  - BlueKeep (CVE-2019-0708)

### Auditing Fundamentals
- Security Auditing Foundations
  - Overview of Security Auditing
  - Essential Terminology
- Security Auditing Process
  - Lifecycle
  - Types of Security Audits
  - Relationship to Penetration Testing
- Governance, Risk & Compliance (GRC)
  - Frameworks, Standards & Guidelines
- Transitioning to Penetration Testing
  - Developing a Security Policy
  - Security Auditing with Lynis
  - Conducting a Penetration Test

## Host & Network Penetration Testing

### Network-Based Attacks
- Networking Fundamentals Refresher
- Firewall Detection & IDS Evasion Techniques
- Network Enumeration
- SMB & NetBIOS Enumeration
- SNMP Enumeration
- SMB Relay Attack Walkthrough

### Host-Based Attacks (System)
- Host-Based Attack Mindset
- Windows Attack Surface
  - Exploiting Microsoft IIS WebDAV
  - Exploiting WebDAV with Metasploit
  - Exploiting SMB with PsExec
  - Exploiting MS17-010 (EternalBlue)
  - Exploiting RDP
  - Exploiting BlueKeep (CVE-2019-0708)
  - Exploiting WinRM
- Windows Privilege Escalation Techniques
  - Windows Kernel Exploits
  - Bypassing UAC with UACMe
  - Access Token Impersonation
- Windows File & Credential Access
  - Alternate Data Streams Abuse
  - Windows Password Hashes & Storage
  - Searching Configuration Files for Secrets
  - Dumping Hashes with Mimikatz
  - Pass-the-Hash Attacks
- Linux Attack Surface
  - Exploiting FTP Services
  - Exploiting SSH Services
  - Exploiting SAMBA
  - Exploiting Bash (Shellshock)
- Linux Privilege Escalation Techniques
  - Linux Kernel Exploits
  - Misconfigured Cron Jobs
  - SUID Binary Abuse
- Linux Credential Access
  - Dumping Linux Password Hashes

### Metasploit Framework (MSF)
- Framework Overview
  - Introduction to the Metasploit Framework
  - Metasploit Architecture
  - Penetration Testing Workflows with Metasploit
- Installation & Console Usage
  - Installing and Configuring Metasploit
  - MSFconsole Fundamentals
  - Workspace Management
- Information Gathering with Metasploit
  - Integrating Nmap Results
  - Service Enumeration via Auxiliary Modules
- Vulnerability Scanning with Metasploit Ecosystem
  - Metasploit Scanner Modules
  - Nessus Integration
  - WMAP for Web Application Scanning
- Payloads & Automation
  - Generating Payloads with Msfvenom
  - Encoding Payloads with Msfvenom
  - Injecting Payloads into PE Files
  - Automating Tasks with Resource Scripts
- Exploitation Routines
  - HTTP File Server Exploitation
  - MS17-010 SMB Exploitation
  - WinRM Exploitation
  - Apache Tomcat Exploitation
  - FTP, Samba, SSH & SMTP Exploitation Modules
- Post-Exploitation with Metasploit
  - Meterpreter Fundamentals
  - Upgrading Shells to Meterpreter
  - Windows Post-Exploitation Modules
  - Privilege Escalation (UAC Bypass & Token Impersonation)
  - Dumping Hashes with Mimikatz
  - Pass-the-Hash with PsExec
  - Establishing Persistence (Windows & Linux)
  - Enabling RDP
  - Keylogging
  - Clearing Event Logs
  - Pivoting Techniques
- Graphical Front-Ends
  - Port Scanning & Enumeration with Armitage
  - Exploitation & Post-Exploitation via Armitage

### Exploitation Tactics
- Exploitation Mindset & Workflow
- Reconnaissance & Vulnerability Scanning
  - Banner Grabbing
  - Nmap Script-Based Scanning
  - Metasploit Vulnerability Checks
- Exploit Research & Customization
  - Searching Public Exploit Repositories
  - Using SearchSploit
  - Fixing and Cross-Compiling Exploits
- Shell Handling
  - Netcat Fundamentals
  - Bind Shells
  - Reverse Shells
  - Reverse Shell Cheat Sheet
- Additional Frameworks & Tooling
  - Metasploit Framework (Reference)
  - PowerShell Empire Overview
- Windows Case Study
  - Black Box Penetration Test Walkthrough
  - Port Scanning & Enumeration for Windows Targets
  - Targeting IIS FTP, OpenSSH, SMB & MySQL
- Linux Case Study
  - Black Box Penetration Test Walkthrough
  - Port Scanning & Enumeration for Linux Targets
  - Targeting vsFTPd, PHP & SAMBA
- Obfuscation & Evasion
  - AV Evasion with Shellter
  - Obfuscating PowerShell Code

### Post-Exploitation Operations
- Post-Exploitation Methodology
  - Introduction to Post-Exploitation
  - Structured Workflow
- Windows Local Enumeration
  - System Information
  - Users & Groups
  - Network Information
  - Processes & Services
  - Automation Techniques
- Linux Local Enumeration
  - System Information
  - Users & Groups
  - Network Information
  - Processes & Cron Jobs
  - Automation Techniques
- Cross-Platform File Transfer
  - Hosting Files with Python
  - Transferring to Windows Targets
  - Transferring to Linux Targets
- Shell Management
  - Upgrading Non-Interactive Shells
- Privilege Escalation Playbooks
  - Identifying Windows Privilege Escalation Opportunities
  - Windows Privilege Escalation Techniques
  - Linux Privilege Escalation via Weak Permissions
  - Linux Privilege Escalation via Sudo
- Persistence Mechanisms
  - Windows Persistence via Services & RDP
  - Linux Persistence via SSH Keys & Cron Jobs
- Credential Dumping & Cracking
  - Windows NTLM Hash Dumping & Cracking
  - Linux Password Hash Dumping & Cracking
- Pivoting Techniques
- Covering Tracks
  - Clearing Artifacts on Windows
  - Clearing Artifacts on Linux

### Social Engineering
- Introduction to Social Engineering
- Pretexting Techniques
- Phishing Campaigns with GoPhish (Parts 1 & 2)

## Web Application Penetration Testing

### Introduction to Web Applications
- Introduction to Web Application Security
- Web Application Security Testing Methodology
- Common Web Application Threats & Risks
- Web Application Architecture
- Web Application Technologies (Parts 1 & 2)

### HTTP Protocol
- HTTP Protocol Fundamentals
  - Introduction to HTTP
  - HTTP Requests (Parts 1 & 2)
  - HTTP Responses
  - HTTP Basics Lab (Parts 1 & 2)
  - HTTPS Overview

### Web Discovery
- Passive Crawling & Spidering with Burp Suite and OWASP ZAP
