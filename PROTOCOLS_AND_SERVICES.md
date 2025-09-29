# Protocols and Services Covered in eJPT Notes

## Assessment Methodologies Footprinting & Scanning

### Lessons

#### Introduction

    - Active Information Gathering

#### Networking Primer

    - Networking Fundamentals
    - Network Layer
    - Transport Layer - Part 1
    - Transport Layer - Part 2

#### Host Discovery

    - Network Mapping
    - Host Discovery Techniques
    - Ping Sweeps
    - Host Discovery With Nmap - Part 1
    - Host Discovery With Nmap - Part 2

#### Port Scanning

    - Port Scanning With Nmap - Part 1
    - Port Scanning With Nmap - Part 2
    - Service Version & OS Detection
    - Nmap Scripting Engine (NSE)

#### Evasion, Scan Performance & Output

    - Firewall Detection & IDS Evasion
    - Optimizing Nmap Scans
    - Nmap Output Formats

## Assessment Methodologies Enumeration

### Welcome

#### Introduction

    - Introduction To Enumeration

### Lessons

#### Nmap Scripting Engine (NSE)

    - Port Scanning & Enumeration with Nmap
    - Importing Nmap Scan Results into MSF
    - Port Scanning with Auxiliary Modules

#### Service Enumeration

    - FTP Enumeration
    - SMB Enumeration
    - Web Server Enumeration
    - MySQL Enumeration
    - SSH Enumeration
    - SMTP Enumeration

## Assessment Methodologies Vulnerability Assessment

### Lessons

#### Vulnerability Assessment

    - Overview of Windows Vulnerabilities
    - Frequently Exploited Windows Services
    - Vulnerability Scanning with MSF
    - WebDAV Vulnerabilities

#### Vulnerability Analysis

    - Vulnerability Analysis Eternal Blue
    - Vulnerability Analysis Blue Keep
    - Pass-the-Hash Attacks
    - Frequently Exploited Linux Services
    - Vulnerability Analysis Shellshock

#### Vulnerability Scanning

    - Vulnerability Scanning with Nessus
    - Web App Vulnerability Scanning with WMAP

## Assessment Methodologies Auditing Fundamentals

### Lessons

#### Introduction to Security Auditing

    - Overview of Security Auditing
    - Essential Terminology

##### Security Auditing Process

      - Lifecycle
    - Types of Security Audits
    - Security Auditing & Penetration Testing

#### Governance, Risk & Compliance

    - Governance, Risk & Compliance (GRC)
    - Common Standards, Frameworks & Guidelines

#### From Auditing to Penetration Testing

    - Phase 1 - Develop a Security Policy
    - Phase 2 - Security Auditing with Lynis
    - Phase 3 - Conduct Penetration Test

## Host & Network Penetration Testing Network-Based Attacks

### Lessons

#### Networking

    - Networking Fundamentals
    - Firewall Detection & IDS Evasion

#### Network Attacks

    - Network Enumeration
    - SMB & NetBIOS Enumeration
    - SNMP Enumeration
    - SMB Relay Attack

## Host & Network Penetration Testing System

### Host Based Attacks

#### Introduction to Attacks

##### Host Based Attacks

###### Introduction To System

        - Host Based Attacks

#### Windows

##### Windows Vulnerabilities

      - Overview Of Windows Vulnerabilities
      - Frequently Exploited Windows Services

##### Exploiting Windows Vulnerabilities

      - Exploiting Microsoft IIS WebDAV
      - Exploiting WebDAV With Metasploit
      - Exploiting SMB With Ps Exec
      - Exploiting Windows MS17-010 SMB Vulnerability (Eternal Blue)
      - Exploiting RDP
      - Exploiting Windows CVE-2019-0708 RDP Vulnerability (Blue Keep)
      - Exploiting WinRM

##### Windows Privilege Escalation

      - Windows Kernel Exploits
      - Bypassing UAC With UAC Me
      - Access Token Impersonation

##### Windows File System Vulnerabilities

      - Alternate Data Streams

##### Windows Credential Dumping

      - Windows Password Hashes
      - Searching For Passwords In Windows Configuration Files
      - Dumping Hashes With Mimikatz
      - Pass-The-Hash Attacks

#### Linux

##### Linux Vulnerabilities

      - Frequently Exploited Linux Services

##### Exploiting Linux Vulnerabilities

      - Exploiting Bash CVE-2014-6271 Vulnerability (Shellshock)
      - Exploiting FTP
      - Exploiting SSH
      - Exploiting SAMBA

##### Linux Privilege Escalation

      - Linux Kernel Exploits
      - Exploiting Misconfigured Cron Jobs
      - Exploiting SUID Binaries

##### Linux Credential Dumping

      - Dumping Linux Password Hashes

## Host & Network Penetration Testing The Metasploit Framework (MSF)

### Metasploit

#### Metasploit Framework Overview

    - Introduction to the Metasploit Framework
    - Metasploit Framework Architecture
    - Penetration Testing With The Metasploit Framework

#### Metasploit Fundamentals

    - Installing & Configuring The Metasploit Framework
    - MSFconsole Fundamentals
    - Creating & Managing Workspaces

### Information Gathering & Enumeration

#### Nmap

    - Port Scanning & Enumeration With Nmap
    - Importing Nmap Scan Results Into MSF

#### Enumeration

    - Port Scanning With Auxiliary Modules
    - FTP Enumeration
    - SMB Enumeration
    - Web Server Enumeration
    - MySQL Enumeration
    - SSH Enumeration
    - SMTP Enumeration

### Vulnerability Scanning

#### MSF

    - Vulnerability Scanning With MSF

#### Nessus

    - Vulnerability Scanning With Nessus

#### Web Apps

    - Web App Vulnerability Scanning With WMAP

### Client-Side Attacks

#### Payloads

    - Generating Payloads With Msfvenom
    - Encoding Payloads With Msfvenom
    - Injecting Payloads Into Windows Portable Executables

#### Automating

    - Automating Metasploit With Resource Scripts

### Exploitation

#### Windows Exploitation

    - Exploiting A Vulnerable HTTP File Server
    - Exploiting Windows MS17-010 SMB Vulnerability
    - Exploiting WinRM (Windows Remote Management Protocol)
    - Exploiting A Vulnerable Apache Tomcat Web Server

#### Linux Exploitation

    - Exploiting A Vulnerable FTP Server
    - Exploiting Samba
    - Exploiting A Vulnerable SSH Server
    - Exploiting A Vulnerable SMTP Server

#### Post Exploitation Fundamentals

    - Meterpreter Fundamentals
    - Upgrading Command Shells To Meterpreter Shells

#### Windows Post Exploitation

    - Windows Post Exploitation Modules
    - Windows Privilege Escalation Bypassing UAC
    - Windows Privilege Escalation Token Impersonation With Incognito
    - Dumping Hashes With Mimikatz
    - Pass-the-Hash With PS Exec
    - Establishing Persistence On Windows
    - Enabling RDP
    - Windows Keylogging
    - Clearing Windows Event Logs
    - Pivoting

#### Linux Post Exploitation

    - Linux Post Exploitation Modules
    - Linux Privilege Escalation Exploiting A Vulnerable Program
    - Dumping Hashes With Hashdump
    - Establishing Persistence On Linux

### Armitage

#### Metasploit GUIs

    - Port Scanning & Enumeration With Armitage
    - Exploitation & Post Exploitation With Armitage

## Host & Network Penetration Testing Exploitation

### Lessons

#### Introduction To Exploitation

    - Introduction To Exploitation

### Vulnerability Scanning Overview

#### Vulnerability Scanning

    - Banner Grabbing
    - Vulnerability Scanning With Nmap Scripts
    - Vulnerability Scanning With Metasploit

### Exploits

#### Searching For Exploits

    - Searching For Publicly Available Exploits
    - Searching For Exploits With Search Sploit

#### Fixing Exploits

    - Fixing Exploits
    - Cross-Compiling Exploits

### Shells

#### Bind & Reverse Shells

    - Netcat Fundamentals
    - Bind Shells
    - Reverse Shells
    - Reverse Shell Cheatsheet

### Frameworks

#### Exploitation Frameworks

    - The Metasploit Framework (MSF)
    - Power Shell-Empire

### Windows

#### Windows Exploitation

    - Windows Black Box Penetration Test
    - Port Scanning & Enumeration - Windows
    - Targeting Microsoft IIS FTP
    - Targeting OpenSSH
    - Targeting SMB
    - Targeting MySQL Database Server

### Linux

#### Linux Exploitation

    - Linux Black Box Penetration Test
    - Port Scanning & Enumeration - Linux
    - Targeting vsFT Pd
    - Targeting PHP
    - Targeting SAMBA

### Obfuscation

#### AV Evasion & Obfuscation

    - AV Evasion With Shellter
    - Obfuscating Power Shell Code

## Host & Network Penetration Testing Post-Exploitation

### Introduction

#### Post-Exploitation

    - Introduction To Post-Exploitation
    - Post-Exploitation Methodology

### Windows Enumeration

#### Windows Local Enumeration

    - Enumerating System Information - Windows
    - Enumerating Users & Groups - Windows
    - Enumerating Network Information - Windows
    - Enumerating Processes & Services
    - Automating Windows Local Enumeration

### Linux Enumeration

#### Linux Local Enumeration

    - Enumerating System Information - Linux
    - Enumerating Users & Groups - Linux
    - Enumerating Network Information - Linux
    - Enumerating Processes & Cron Jobs
    - Automating Linux Local Enumeration

### Transferring Files

#### Transferring Files To Windows & Linux Targets

    - Setting Up A Web Server With Python
    - Transferring Files To Windows Targets
    - Transferring Files To Linux Targets

### Shells

#### Upgrading Shells

    - Upgrading Non-Interactive Shells

### Escalation

#### Windows Privilege Escalation

    - Identifying Windows Privilege Escalation Vulnerabilities
    - Windows Privilege Escalation

#### Linux Privilege Escalation

    - Linux Privilege Escalation - Weak Permissions
    - Linux Privilege Escalation - SUDO Privileges

### Persistence

#### Windows Persistence

    - Persistence Via Services
    - Persistence Via RDP

#### Linux Persistence

    - Persistence Via SSH Keys
    - Persistence Via Cron Jobs

### Dumping & Cracking

#### Dumping & Cracking Windows Hashes

    - Dumping & Cracking NTLM Hashes

#### Dumping & Cracking Linux Hashes

    - Dumping & Cracking Linux Password Hashes

### Pivoting Lesson

#### Pivoting Overview

    - Pivoting

### Clearing

#### Clearing Your Tracks

    - Clearing Your Tracks On Windows
    - Clearing Your Tracks On Linux

## Host & Network Penetration Testing Social Engineering

### Lessons

#### Social Engineering

    - Introduction to Social Engineering
    - Pretexting
    - Phishing with Gophish - Part 1
    - Phishing with Gophish - Part 2

## Web Application Penetration Testing Introduction to the Web & HTTP Protocol

### Web Applications

#### Introduction to Web App Security Testing

    - Introduction to Web Application Security
    - Web Application Security Testing
    - Common Web Application Threats & Risks

#### Web Application Architecture & Components

    - Web Application Architecture
    - Web Application Technologies - Part 1
    - Web Application Technologies - Part 2

### HTTP Protocol

#### HTTP

##### HTTP Protocol Fundamentals

      - Introduction to HTTP
      - HTTP Requests - Part 1
      - HTTP Requests - Part 2
      - HTTP Responses
      - HTTP Basics Lab - Part 1
      - HTTP Basics Lab - Part 2
      - HTTPS

#### Website Crawling & Spidering

    - Passive Crawling & Spidering with Burp Suite & OWASP ZAP
