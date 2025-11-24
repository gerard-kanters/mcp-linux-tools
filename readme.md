# MCP Linux Tools - Complete Tool Reference for LLMs

## 🔒 SECURITY OVERVIEW

**LINUX SERVER Tools** with limited write operations:

### ✅ WHAT IS ALLOWED:
- **READ Files** (in allowed directories)
- **VIEW Logs** (system logs)
- **CHECK Service STATUS** and **RESTART** (only whitelisted services)
- **EXECUTE Python CODE** (sandboxed, no network, 8s timeout)
- **MANAGE Cron JOBS** (only within MCP-managed section)

### ❌ WHAT IS NOT ALLOWED:
- Access to arbitrary directories (strict whitelisting)
- Services **STOP/START/ENABLE** (only restart allowed)
- Sudo/root operations
- Python with network access
- Modifying system crontab outside MCP section

---

## 📂 ALLOWED DIRECTORIES

### Read Access (ALLOWED_READ_DIRS):
- `/var/log` - System logs
- `/etc` - Configuration files
- `/tmp` - Temporary files
- `/opt/` - Optional software
- `/root/scripts` - Root scripts
- `/var/www` - Web roots

### Log Access (ALLOWED_LOG_DIRS):
- `/var/log` - System logs
- `/tmp` - Temporary logs
- `/var/www` - Web application logs

---

## 🛠️ ALLOWED SERVICES (SERVICE_WHITELIST)

Only these services can be checked for status or restarted:

### Web & Application Services:
- `apache2` - Apache webserver
- `nginx` - Nginx webserver
- `php8.4-fpm` - PHP FastCGI Process Manager
- `docker` - Container runtime
- `memcached` - Memory cache daemon

### Mail Services:
- `postfix` - Mail server
- `opendkim` - DomainKeys email authentication

### Network Services:
- `sshd` - SSH daemon
- `systemd-resolved` - Systemd DNS resolver
- `bind9` - BIND DNS server
- `named` - BIND DNS server (alternative name)
- `isc-dhcp-server` - ISC DHCP server
- `dhcpd` - DHCP daemon (alternative name)

### Database Services:
- `mysql` - MySQL database server
- `mariadb` - MariaDB database server
- `mysqld` - MySQL daemon (alternative name)
- `postgresql` - PostgreSQL database server

### File Sharing:
- `smbd` - Samba SMB daemon
- `samba` - Samba service

### Application Services:
- `odoo` - Odoo ERP system

---

## 📚 TOOL CATEGORIES

### 1️⃣ METADATA & DISCOVERY (Read-Only)
- `get_service_whitelist()` - List manageable services

### 2️⃣ FILE OPERATIONS
- `list_dir(path, pattern, include_files, include_dirs, max_items)` - Directory listing (Read-Only)
- `read_file(path, max_bytes)` - Read file (max 512KB, Read-Only)
- `head(path, n)` - First N lines (Read-Only)
- `tail(path, n)` - Last N lines (for logs, Read-Only)
- `log_tail(path, n)` - Alias for tail (clearer for logs, Read-Only)
- `create_directory(path, owner, group, mode, parents)` - Create directory ⚠️ (only /var/www and /opt/)
- `chmod_file(path, mode)` - Change file permissions ⚠️ (only /var/www and /opt/)
- `chown_path(path, owner, group)` - Change owner ⚠️ (only /var/www and /opt/)

### 3️⃣ SYSTEM SERVICES
- `service_status(name)` - Check status (Read-Only)
- `restart_service(name)` - Restart service ⚠️ (Live impact!)

### 4️⃣ PYTHON EXECUTION
- `python_run(code)` - Sandboxed Python (no network, 8s timeout)

### 5️⃣ CRON MANAGEMENT
- `cron_list()` - View crontab (Read-Only)
- `cron_add(job_id, schedule, command)` - Add job ⚠️ (Live impact!)
- `cron_remove(job_id)` - Remove job ⚠️ (Live impact!)
- `cron_enable(job_id, enabled)` - Enable/disable job ⚠️ (Live impact!)
- `cron_next_runs(schedule, n)` - Validate schedule (Read-Only)

### 6️⃣ DATABASE OPERATIONS
- `mysql_query(query, database)` - Execute MySQL query (Read-Only, dangerous queries blocked)

### 7️⃣ NETWORK OPERATIONS
- `ping_host(host, count)` - Test network connectivity (Read-Only)

### 8️⃣ GIT OPERATIONS
- `git_command(path, command)` - Execute Git commands (only safe commands, no push/force)

### 9️⃣ SYSTEM COMMANDS
- `execute_shell_command(command, user)` - Execute shell command ⚠️ (Live impact!)

---

## 💡 USAGE EXAMPLES

### Service Status:
```json
{"tool": "service_status", "args": {
  "name": "nginx"
}}
```

### Restart Service:
```json
{"tool": "restart_service", "args": {
  "name": "mysql"
}}
```

### View Log File:
```json
{"tool": "log_tail", "args": {
  "path": "/var/log/nginx/error.log",
  "n": 100
}}
```

### Execute Python:
```json
{"tool": "python_run", "args": {
  "code": "import sys; print(sys.version)"
}}
```

### MySQL Query:
```json
{"tool": "mysql_query", "args": {
  "query": "SHOW DATABASES;",
  "database": ""
}}
```

### Network Ping:
```json
{"tool": "ping_host", "args": {
  "host": "8.8.8.8",
  "count": 4
}}
```

### Git Status:
```json
{"tool": "git_command", "args": {
  "path": "/var/www/example",
  "command": "status"
}}
```

### Add Cron Job:
```json
{"tool": "cron_add", "args": {
  "job_id": "backup_daily",
  "schedule": "0 3 * * *",
  "command": "/usr/bin/backup.sh"
}}
```

---

## ⚠️ IMPORTANT NOTES FOR LLMs

1. **Read-Only Default**: Most tools are read-only. Write operations are limited to:
   - `restart_service()` - Restart services
   - `cron_add/remove/enable()` - Cron modifications
   - `create_directory()` - Create directory (only /var/www and /opt/)
   - `chmod_file()` - Change file permissions (only /var/www and /opt/)
   - `chown_path()` - Change owner (only /var/www and /opt/)
   - `execute_shell_command()` - Shell commands (use with caution!)

2. **Whitelisting**: Everything is whitelisted. Tools return "Denied" if you work outside the whitelist.

3. **Service Names**: Different distributions use different service names. For example:
   - DNS: `systemd-resolved`, `bind9`, or `named`
   - DHCP: `isc-dhcp-server` or `dhcpd`
   - MySQL: `mysql`, `mariadb`, or `mysqld`
   - SMB: `smbd` or `samba`

4. **Security First**: 
   - No blind `rm -rf` possible
   - No arbitrary file writes
   - Python is sandboxed
   - Cron commands must use absolute paths

5. **Error Handling**: Tools return clear errors:
   - "Denied" = outside whitelist
   - "Not found" = file/service does not exist
   - {"error": "..."} = specific error

6. **Return Types**:
   - Strings for simple output
   - Dicts for structured data (Python, MySQL, etc.)
   - Lists for directories and cron schedules

---

## 🎯 BEST PRACTICES

1. **Check whitelists first**: Call `get_service_whitelist()` before managing services
2. **Read-only first**: Check status/logs before restarting services
3. **Validate cron schedules**: Use `cron_next_runs()` to validate schedules
4. **Service names**: Check which service name is used on the system (e.g. `mysql` vs `mariadb`)
5. **Error handling**: Always check for "Denied" or {"error": ...} in responses
6. **Log locations**: Use `list_dir()` to explore log directories before reading logs

---

## 📊 TESTED & VERIFIED

All tools have been tested and work correctly:
✅ Service status en restart functionaliteit
✅ Log file reading
✅ Python 3.13 execution (sandboxed)
✅ Cron schedule validation
✅ File operations (read-only)
✅ Directory listing

**Last Updated**: 2025-11-XX
**Server**: Linux (generic)
**Environment**: Production/Development

