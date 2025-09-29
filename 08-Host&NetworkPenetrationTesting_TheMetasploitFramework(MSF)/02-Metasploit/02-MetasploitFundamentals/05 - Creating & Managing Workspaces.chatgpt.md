# 05 - Creating & Managing Workspaces (Metasploit Fundamentals)

Note: No transcript was provided. The following summary is inferred from the filename and typical Metasploit usage. Commands and flags are the standard ones you’ll find in msfconsole; verify with `workspace -h` in your environment.

## What the video covers (Introduction / big picture)
- What Metasploit workspaces are and why to use them: cleanly separate hosts, services, creds, loot, notes, and vulns for each engagement.
- How to create, list, select, rename, and delete workspaces inside msfconsole.
- Checking database connectivity so workspaces can store data.
- Demonstrating that data (e.g., from `db_nmap` imports or scans) stays isolated per workspace.

## Flow (ordered)
1. Start msfconsole and check database status.
2. List existing workspaces and identify the current one.
3. Create a new workspace for a target/client.
4. Switch/select the new workspace.
5. Populate it with data (e.g., `db_nmap` or `db_import`) and view hosts/services.
6. Switch back to another workspace to show isolation.
7. Rename a workspace if needed.
8. Delete an old/unneeded workspace (not the one you’re currently in).
9. Practical notes: naming conventions, avoiding accidental deletion, verifying with `workspace -h`.

## Tools highlighted
- msfconsole (Metasploit Framework)
- Metasploit’s PostgreSQL database backend
- db_nmap (Nmap integration with automatic DB import)
- hosts, services, creds, loot, notes, vulns (data viewers inside Metasploit)

## Typical command walkthrough (detailed, copy-paste friendly)

Shell (optional, only if DB isn’t connected):
```bash
# Optional: ensure PostgreSQL is running (platform-dependent)
sudo systemctl status postgresql

# Optional: initialize/start Metasploit DB helper if available on your distro
msfdb status
msfdb init   # or: msfdb start
```

Inside msfconsole:
```bash
# 1) Verify DB connectivity
db_status

# 2) List workspaces and see the current one (has an asterisk)
workspace
# or
workspace -l

# 3) Create a new workspace
workspace -a acme_q1

# 4) Select/switch to the new workspace
workspace acme_q1
# (Alternative: workspace -S acme_q1, if supported)

# 5) Bring data into the workspace (example using db_nmap)
db_nmap -sV -Pn 10.10.10.0/24

# 6) View stored data in this workspace
hosts
services
creds
notes
loot
vulns

# 7) Switch back to the default workspace and confirm isolation
workspace default
hosts
services

# 8) Rename a workspace (not the current one)
workspace -r acme_q1 acme_2025_q1

# 9) Delete a workspace (must not be the current workspace)
workspace -d temp_workspace

# 10) Need help / confirm options
workspace -h
```

Notes:
- Selecting a workspace can be done by `workspace <name>`. Some versions also support `-S <name>`.
- Renaming typically uses `workspace -r <old_name> <new_name>`.
- You cannot delete the currently selected workspace; switch first.

## Practical tips
- Use clear, consistent names per engagement, e.g., `clientname_year_quarter` or `client_networkA`.
- Avoid spaces/special characters in names; prefer underscores.
- Always confirm DB connectivity (`db_status`) before relying on workspaces.
- Keep “default” as a scratch or lab workspace; do real engagements in dedicated workspaces.
- To demonstrate isolation, run `hosts`/`services` after switching; lists should differ across workspaces.
- Before deleting, list workspaces (`workspace`), switch away, then `workspace -d <name>`.
- If using imports, `db_import <file>` supports nmap XML and other formats; the data lands in the current workspace.
- Backups: consider exporting data before destructive changes (e.g., `db_export -f xml msf_export.xml` on versions that support it; verify with `db_export -h`).

## Minimal cheat sheet (one-screen flow)
```bash
# In msfconsole
db_status                    # ensure connected
workspace -l                 # list workspaces
workspace -a acme            # add workspace
workspace acme               # select workspace

db_nmap -sV -Pn 10.10.10.0/24
hosts                        # show data in current workspace
services

workspace default            # switch back
hosts                        # confirm isolation

workspace -r acme acme_q1    # rename
workspace -d acme_q1         # delete (not current)
workspace -h                 # help
```

## Summary
- Workspaces segment all Metasploit DB-backed data by project/engagement.
- Core actions: list (`workspace/-l`), add (`-a`), select (`workspace <name>`), rename (`-r old new`), delete (`-d name`).
- Always verify database connectivity with `db_status` and check options with `workspace -h`.
- Populate and verify per-workspace data using `db_nmap`, `db_import`, and viewers like `hosts` and `services`.