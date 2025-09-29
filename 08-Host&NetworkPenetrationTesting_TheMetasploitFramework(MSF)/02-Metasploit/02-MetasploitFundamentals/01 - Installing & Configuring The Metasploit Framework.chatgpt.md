# Installing & Configuring The Metasploit Framework

Note: The transcript isn’t provided. The following is a conservative, eJPT‑oriented summary inferred from the filename/context and common lab setups for “Metasploit Fundamentals.”

## What the video covers (Introduction / big picture)
- How to install Metasploit Framework cleanly on common lab platforms (Kali/Parrot, Ubuntu/Debian, Windows via WSL2/Docker).
- How to initialize and verify the PostgreSQL-backed Metasploit database (faster searches, host/service tracking).
- First‑run configuration inside msfconsole: workspaces, global options, saving settings.
- Quick update/maintenance steps and where important files live.

## Flow (ordered)
1. Choose platform (Kali/Parrot recommended for eJPT; Ubuntu/WSL2 workable).
2. Install Metasploit Framework and dependencies.
3. Enable and start PostgreSQL.
4. Initialize Metasploit’s database (msfdb) and verify connectivity.
5. Launch msfconsole and create a workspace.
6. Set useful global options (LHOST, RHOSTS, THREADS) and save them.
7. Validate the DB integration with db_nmap / db_import and hosts/services commands.
8. Optional: create a resource (.rc) file to auto‑apply your defaults.
9. Keep Metasploit up to date via your package manager.

## Tools highlighted
- Metasploit Framework core tools:
  - msfconsole (main CLI)
  - msfvenom (payload generator)
  - msfdb (DB helper; initializes/controls the database)
- PostgreSQL (backing database)
- Nmap (via db_nmap integration inside msfconsole)
- Workspaces and resource scripts (.rc)

## Typical command walkthrough (detailed, copy‑paste friendly)

### A) Kali/Parrot OS (recommended for eJPT)
```bash
# 1) Update and install
sudo apt update
sudo apt -y install metasploit-framework

# 2) Enable/start PostgreSQL (Metasploit DB backend)
sudo systemctl enable --now postgresql

# 3) Initialize Metasploit database (creates user/db/config)
sudo msfdb init

# 4) Launch msfconsole (quiet) and verify DB connection
msfconsole -q
```

Inside msfconsole (first run):
```bash
db_status
# Expected: "Connected to msf. Connection type: postgresql."

# Create/select a workspace for your lab
workspace -a eJPT
workspace eJPT

# Set useful global options (adjust interfaces/targets to your lab)
setg LHOST 10.10.14.5      # often your VPN/tun0 IP in eJPT labs
setg RHOSTS 10.10.10.0/24  # example target scope
setg THREADS 32
save                       # persist global datastore across sessions

# Quick Nmap scan that stores results in the DB:
db_nmap -sV -T4 -Pn 10.10.10.0/24

# Review enumerated hosts/services
hosts
services -c host,port,proto,name,state,info

# Exit when done
exit
```

Common fixes:
```bash
# If db_status shows "not connected"
sudo systemctl restart postgresql
sudo msfdb reinit
msfconsole -qx "db_status; exit"
```

### B) Ubuntu/Debian (non‑Kali) or WSL2 Ubuntu
Option 1 (Ubuntu repo; may not be the newest):
```bash
sudo apt update
sudo apt -y install metasploit-framework postgresql
sudo systemctl enable --now postgresql
sudo msfdb init
msfconsole -q
```

Option 2 (Rapid7 installer; adds Rapid7 repo then installs package):
```bash
sudo apt update && sudo apt -y install curl ca-certificates gnupg postgresql
curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfinstall -o msfinstall
chmod +x msfinstall
sudo ./msfinstall
sudo systemctl enable --now postgresql
sudo msfdb init
msfconsole -q
```

Then repeat the same msfconsole steps as in the Kali section.

### C) Windows users (recommended: WSL2 or Docker)
WSL2 (Ubuntu) then follow “Ubuntu” steps above:
```powershell
# In PowerShell (as admin)
wsl --install -d Ubuntu
# Reboot when prompted, then inside Ubuntu shell do the Ubuntu steps.
```

Docker (official metasploit image):
```bash
docker pull metasploitframework/metasploit-framework
docker run -it --rm --net host metasploitframework/metasploit-framework
# Inside container: msfconsole (DB support is limited in ephemeral containers)
```

### D) Quick resource script to auto‑configure your lab defaults
```bash
# Set LHOST dynamically to your tun0 (change tun0 if needed)
LHOST=$(ip -o -4 addr show tun0 | awk '{print $4}' | cut -d/ -f1)

mkdir -p ~/.msf4
cat > ~/.msf4/eJPT_setup.rc << EOF
workspace -a eJPT
workspace eJPT
setg LHOST $LHOST
setg RHOSTS 10.10.10.0/24
setg THREADS 32
save
db_status
EOF

msfconsole -r ~/.msf4/eJPT_setup.rc
```

### E) Updating Metasploit
```bash
# Kali/Ubuntu/Debian
sudo apt update
sudo apt -y full-upgrade
```

## Practical tips
- Always ensure PostgreSQL is running before launching msfconsole; check with db_status.
- Use workspaces per target/scope to keep data clean: workspace -a <name>.
- Save global options once (save). Unset with unsetg <var>.
- Use db_nmap (inside msfconsole) or db_import nmap.xml to keep hosts/services in the DB.
- Populate RHOSTS from your DB:
  - hosts -R sets RHOSTS to all hosts in the workspace.
  - services -p 445 -R sets RHOSTS to hosts with port 445 open.
- Prefer LHOST as your VPN interface IP (often tun0) for eJPT labs.
- Logs and data live under ~/.msf4 (config, logs, loot). Modules live under /usr/share/metasploit-framework/modules.
- If msfupdate is mentioned elsewhere, on modern Kali/Ubuntu you update via apt, not msfupdate.
- If you see “The database appears to be invalid,” try: sudo msfdb reinit.
- For Windows, prefer WSL2/VM over native installs for fewer Ruby/DB quirks.

## Minimal cheat sheet (one‑screen flow)
```bash
# Install (Kali/Parrot)
sudo apt update && sudo apt -y install metasploit-framework
sudo systemctl enable --now postgresql
sudo msfdb init

# Start and verify
msfconsole -q
db_status

# First-time setup
workspace -a eJPT
setg LHOST $(ip -o -4 addr show tun0 | awk '{print $4}' | cut -d/ -f1)
setg RHOSTS 10.10.10.0/24
setg THREADS 32
save

# Test DB integration
db_nmap -sV -T4 -Pn 10.10.10.0/24
hosts
services -c host,port,proto,name,state,info
exit
```

## Summary
- Install Metasploit via your distro’s package manager (Kali/Parrot recommended), enable/start PostgreSQL, and run msfdb init.
- Launch msfconsole, verify db_status, create a workspace, and set/save global options (LHOST/RHOSTS/THREADS).
- Use db_nmap/db_import to keep enumeration results in the database; manage targets via hosts/services and -R helpers.
- Maintain via apt updates; use resource (.rc) files to standardize setup across sessions.