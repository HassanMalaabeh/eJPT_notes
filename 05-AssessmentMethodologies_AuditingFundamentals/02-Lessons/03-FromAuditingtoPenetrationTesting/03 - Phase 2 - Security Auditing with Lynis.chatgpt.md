# 03 – Phase 2 – Security Auditing with Lynis

Note: The transcript for this video was not provided. The summary below is based on the filename and typical eJPT workflows for “Security Auditing with Lynis.” Commands, flags, and paths are drawn from standard Lynis usage on Kali/Parrot/Ubuntu. Adjust to your distro as needed.

## What the video covers (Introduction / big picture)
- How to use Lynis, a host-based Linux auditing tool, to quickly assess a system’s security posture.
- Running a baseline system audit and interpreting hardening index, warnings, and suggestions.
- Focusing findings that translate into penetration-testing leads (e.g., weak SSH config, missing firewall, outdated packages).
- Producing repeatable, exportable reports and targeted audits to accelerate Phase 2 (From Auditing to Penetration Testing).

## Flow (ordered)
1. Install/verify Lynis on your attack box or target (with permission).
2. Update Lynis data files and confirm version.
3. Run a baseline audit: lynis audit system (as root).
4. Locate and read the outputs: log and report files.
5. Extract actionable items: warnings, suggestions, hardening index.
6. Run targeted audits for specific groups (e.g., ssh, authentication, malware).
7. Customize behavior via a custom profile (skip known false positives or irrelevant tests).
8. Tie findings back to pentest actions (weak SSH, missing hardening, vulnerable services).
9. Save/compare reports over time or across hosts.

## Tools highlighted
- Lynis (system security auditing for Linux/Unix)
- Package manager (apt/dnf/pacman) to install Lynis
- Standard CLI utilities: grep, awk, sed, less, diff
- SSH for remote execution (optional)

## Typical command walkthrough (detailed, copy-paste friendly)

Install (Debian/Ubuntu/Kali/Parrot):
```bash
sudo apt update
sudo apt install -y lynis
lynis --version
```

Update Lynis data info (checks what Lynis knows about tests/definitions):
```bash
lynis update info
```

Quick help and available groups/tests:
```bash
lynis --help
lynis show groups
lynis show tests | less
```

Baseline audit (run as root for full coverage):
```bash
sudo lynis audit system
```

Add your name to the report (useful in team settings):
```bash
sudo lynis audit system --auditor "eJPT Student"
```

Non-interactive/cron-friendly run with explicit output files:
```bash
sudo lynis audit system --cronjob \
  --report-file /var/log/lynis-report-$(hostname)-$(date +%F).dat \
  --logfile /var/log/lynis-$(hostname)-$(date +%F).log
```

Where to find results (defaults):
```bash
# Main log and machine-readable report
sudo ls -l /var/log/lynis.log /var/log/lynis-report.dat
```

Extract the hardening index, warnings, and suggestions:
```bash
# Hardening index (overall score)
sudo awk -F= '/^hardening_index=/{print "Hardening Index: "$2}' /var/log/lynis-report.dat

# List warnings and suggestions (quick view)
sudo grep -E '^(warning|suggestion)' /var/log/lynis-report.dat

# Cleaner output (remove key names)
sudo awk -F= '/^(warning|suggestion)/{print $1": "$2}' /var/log/lynis-report.dat
```

Targeted audits by group (focus areas for pentest leads):
```bash
# See available groups first
lynis show groups

# Example: SSH configuration checks
sudo lynis audit system --tests-from-group ssh

# Example: Authentication and password policy checks
sudo lynis audit system --tests-from-group authentication

# Example: Malware/AV-related checks
sudo lynis audit system --tests-from-group malware
```

Narrow to a single test by ID (find IDs via `lynis show tests`):
```bash
# Example structure; replace TEST-ID with an actual test ID from `lynis show tests`
sudo lynis audit system --tests TEST-ID
```

Skip tests you’ve validated as false positives (use a custom profile):
```bash
# Create/append to custom profile (do not edit /etc/lynis/default.prf)
echo "# eJPT custom profile" | sudo tee -a /etc/lynis/custom.prf

# Example: skip a specific test by ID (find ID via `lynis show tests | grep -i <keyword>`)
echo "skip-test=TEST-ID" | sudo tee -a /etc/lynis/custom.prf
```

Remote execution (collect a report from a host you’re authorized to audit):
```bash
# SSH into the host and run Lynis, then pull the report locally
ssh user@target 'sudo lynis audit system --cronjob --report-file /tmp/lynis-report.dat'
scp user@target:/tmp/lynis-report.dat ./lynis-report-$(date +%F)-target.dat
```

Compare two runs (before/after or host A vs. host B):
```bash
diff -u lynis-report-2025-01-01-target.dat lynis-report-2025-01-15-target.dat | less
```

## Practical tips
- Run as root: Many checks are skipped if not root (you’ll get partial coverage).
- Network access: Some checks and update info work best with outbound network allowed.
- Read the Suggestions first: They often map directly to hardening items or pentest leads (e.g., “PermitRootLogin” in SSH, missing firewall, world-writable files).
- Tie to exploitation:
  - SSH weak config → attempt protocol/cipher downgrade checks, brute-force protections, root login policy.
  - Missing firewall → expanded attack surface/extra services to enumerate.
  - Outdated packages/kernel → search CVEs for versions in use.
  - Weak PAM/login.defs → password complexity/aging weaknesses.
  - Kernel/sysctl hardening gaps (e.g., ASLR, core dumps) → post-exploitation and privesc reliability.
- Keep custom.prf minimal: Only add overrides/skip-test lines you truly need.
- Use groups for speed: Target only relevant areas when time-boxed (ssh, authentication, firewall, networking, malware).
- Preserve artifacts: Save both the .log and .dat files in your engagement notes for traceability.
- Ethics and scope: Only audit systems you own or are explicitly authorized to test.

## Minimal cheat sheet (one-screen flow)
```bash
# Install and verify
sudo apt update && sudo apt install -y lynis
lynis --version
lynis update info

# Baseline audit
sudo lynis audit system --auditor "eJPT Student"

# Outputs
sudo awk -F= '/^hardening_index=/{print "Hardening Index: "$2}' /var/log/lynis-report.dat
sudo grep -E '^(warning|suggestion)' /var/log/lynis-report.dat

# Targeted checks
lynis show groups
sudo lynis audit system --tests-from-group ssh
sudo lynis audit system --tests-from-group authentication

# Custom profile (skip a known-irrelevant test)
echo "skip-test=TEST-ID" | sudo tee -a /etc/lynis/custom.prf

# Save with explicit files (cron-friendly)
sudo lynis audit system --cronjob \
  --report-file /var/log/lynis-report-$(hostname)-$(date +%F).dat \
  --logfile /var/log/lynis-$(hostname)-$(date +%F).log
```

## Summary
- Lynis provides a fast, comprehensive snapshot of a Linux system’s security posture.
- For eJPT workflows, run a baseline audit, extract warnings/suggestions, and immediately translate them into pentest leads (SSH, auth, firewall, outdated software).
- Use targeted groups for time efficiency, and maintain a minimal custom profile to suppress noise.
- Always store and compare reports to track changes and justify next steps.