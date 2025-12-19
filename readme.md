# MCP Linux Tools - Complete Tool Reference for LLMs

## 📦 INSTALLATION

### Requirements
- Python 3.13 or higher
- Root access (for systemctl and crontab)
- Linux system with systemd

### Step 1: Clone Repository
```bash
# Clone the MCP server repository to /opt/mcp
sudo mkdir -p /opt
cd /opt
sudo git clone https://github.com/gerard-kanters/mcp-linux-tools.git mcp
cd /opt/mcp
```

### Step 2: Create Python Virtual Environment
```bash
# Create virtual environment
sudo python3.13 -m venv /opt/mcp/venv

# Install dependencies
sudo /opt/mcp/venv/bin/pip install --upgrade pip
sudo /opt/mcp/venv/bin/pip install -r requirements.txt --break-system-packages
```

### Step 3: Configure
Edit `config.json` and adjust the settings for your server:
- Set `server_type` (development or production)
- Set `server_ip` to your server's IP address
- Set `server_name` to identify this server
- Configure directory whitelists, service whitelist, and other settings as needed

See the [Configuration](#-configuration) section below for detailed information about all configuration options.

### Step 4: Create Sandbox Directory
```bash
sudo mkdir -p /opt/mcp/sandbox
sudo chown root:root /opt/mcp/sandbox
sudo chmod 755 /opt/mcp/sandbox
```

### Step 5: Install Systemd Service
Create a service file: `/etc/systemd/system/mcp-linux-tools.service`

```ini
[Unit]
Description=MCP Linux Tools Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mcp
ExecStart=/opt/mcp/venv/bin/python /opt/mcp/server.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log /opt/mcp/sandbox

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable mcp-linux-tools.service
sudo systemctl start mcp-linux-tools.service
sudo systemctl status mcp-linux-tools.service
```

### Step 6: Cursor MCP Configuration
Add to your Cursor MCP configuration (usually `~/.cursor/mcp.json` or in Cursor settings):

```json
{
  "mcpServers": {
    "linux-tools": {
      "command": "curl",
      "args": [
        "-X", "POST",
        "http://192.168.1.22:8765/mcp",
        "-H", "Content-Type: application/json",
        "-d", "@-"
      ]
    }
  }
}
```

Or use direct HTTP transport in Cursor MCP settings with:
- URL: `http://192.168.1.22:8765/mcp`
- Transport: HTTP

### Verification
Check if the server is running:
```bash
# Check service status
sudo systemctl status mcp-linux-tools.service

# Check logs
sudo journalctl -u mcp-linux-tools.service -f

# Test HTTP endpoint
curl -X POST http://localhost:8765/mcp -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

### Installing Updates
To update the MCP server:

```bash
cd /opt/mcp
sudo git pull origin main  # or master, depending on your branch
sudo /opt/mcp/venv/bin/pip install -r requirements.txt --break-system-packages
sudo systemctl restart mcp-linux-tools.service
```

**Important**: After an update, check if `config.json` is still correct. New configuration options may have been added.

---

## ⚙️ CONFIGURATION

All configuration is done via `config.json` in the root of the MCP server directory (`/opt/mcp/config.json`).

### Configuration Sections

#### Server Identification
- `server_type`: "development" or "production"
- `server_ip`: IP address of the server
- `server_name`: Name for the MCP server

#### Logging
- `logging.log_file`: Path to log file

#### Limits
- `limits.max_bytes`: Maximum file size for reading (default: 524288 = 512KB)
- `limits.max_items`: Maximum items in directory listings (default: 500)

#### Python Sandbox
- `python.bin`: Path to Python interpreter (must be in venv)
- `directories.sandbox_cwd`: Working directory for Python sandbox

#### Directory Whitelists
- `directories.allowed_read`: Directories from which files can be read
- `directories.allowed_log`: Directories where log files can be read
- `directories.allowed_write`: Directories where write operations are allowed

#### Services
- `services.whitelist`: List of service names that can be managed

#### WordPress
- `wordpress.allowed_sites`: Absolute paths to WordPress roots
- `wordpress.bin_candidates`: Possible locations for WP-CLI binary
- `wordpress.log_candidates`: Possible locations for WordPress debug logs

**Important**: After changes to `config.json`, the service must be restarted:
```bash
sudo systemctl restart mcp-linux-tools.service
```

---

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

Directory whitelists are configured in `config.json` under `directories`.

### Read Access (allowed_read):
Default: `/var/log`, `/etc`, `/tmp`, `/opt/`, `/root/scripts`, `/var/www`

### Log Access (allowed_log):
Default: `/var/log`, `/tmp`, `/opt/ai_trading_bot`, `/opt/finbert`, `/var/www`

### Write Access (allowed_write):
Default: `/var/www`, `/opt/`

**Note**: All directory paths are configurable via `config.json`. Changes require a service restart.

---

## 🛠️ ALLOWED SERVICES (SERVICE_WHITELIST)

The service whitelist is configured in `config.json` under `services.whitelist`. Only services in this list can be checked or restarted.

**Default whitelist** (as configured in config.json):
- `apache2` - Apache webserver
- `php8.4-fpm` - PHP FastCGI Process Manager
- `postfix` - Mail server
- `opendkim` - DomainKeys email authentication
- `sshd` - SSH daemon
- `docker` - Container runtime
- `memcached` - Memory cache daemon
- `postgresql` - PostgreSQL database server
- `odoo` - Odoo ERP system
- `ai-trading-dashboard.service` - Custom application service

**Note**: Service names may vary by distribution. Use `get_service_whitelist()` to query the active whitelist.

---

## 📚 TOOL CATEGORIES

### 1️⃣ METADATA & DISCOVERY (Read-Only)
- `get_server_info()` - Server identification (type, IP, name)
- `get_service_whitelist()` - List of manageable services
- `get_wp_allowed_sites()` - List of allowed WordPress sites

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

### 6️⃣ WORDPRESS OPERATIONS
- `wp_cli(site_path, args, as_www_data)` - WP-CLI runner for allowed sites
- `wp_cache_flush(site_path, as_www_data)` - WordPress cache flush
- `wp_plugin_list(site_path, as_www_data)` - List all plugins (JSON)
- `wp_user_list(site_path, as_www_data)` - List all users (JSON)
- `log_pick_path()` - Find WordPress debug log path
- `log_tail_ai(n)` - Tail WP-log filtered on 'ai-translate:'
- `log_tail_flow(n)` - Tail WP-log filtered on mapping-flow events
- `log_tail_keywords(keywords, n)` - Tail WP-log filtered on keywords

### 7️⃣ DATABASE OPERATIONS
- `mysql_query(query, database)` - Execute MySQL query (Read-Only, dangerous queries blocked)

### 8️⃣ NETWORK OPERATIONS
- `ping_host(host, count)` - Test network connectivity (Read-Only)

### 9️⃣ GIT OPERATIONS
- `git_command(path, command)` - Execute Git commands (only safe commands, no push/force)

### 🔟 SYSTEM COMMANDS
- `execute_shell_command(command, user)` - Execute shell command ⚠️ (Live impact!)

---

## 💡 USAGE EXAMPLES

### Server Info:
```json
{"tool": "get_server_info", "args": {}}
```

### Service Whitelist:
```json
{"tool": "get_service_whitelist", "args": {}}
```

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

### WordPress Cache Flush:
```json
{"tool": "wp_cache_flush", "args": {
  "site_path": "/var/www/netcare.nl"
}}
```

### WordPress Plugin List:
```json
{"tool": "wp_plugin_list", "args": {
  "site_path": "/var/www/netcare.nl"
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

1. **Server identification**: Use `get_server_info()` to verify which server you're working on
2. **Check whitelists first**: Call `get_service_whitelist()` before managing services
3. **Read-only first**: Check status/logs before restarting services
4. **Validate cron schedules**: Use `cron_next_runs()` to validate schedules
5. **Service names**: Check which service name is used on the system
6. **Error handling**: Always check for "Denied" or {"error": ...} in responses
7. **Log locations**: Use `list_dir()` to explore log directories before reading logs
8. **Config changes**: Always restart the service after changes to `config.json`

---

## 📊 TESTED & VERIFIED

All tools have been tested and work correctly:
✅ Service status and restart functionality
✅ Log file reading
✅ Python 3.13 execution (sandboxed)
✅ Cron schedule validation
✅ File operations (read-only)
✅ Directory listing

**Last Updated**: 2025-01-XX
**Server**: Linux (generic)
**Environment**: Production/Development
**Configuration**: Via `config.json` (no hardcoded values)

