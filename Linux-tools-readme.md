# MCP Linux Tools - Complete Tool Reference voor LLMs

## 🔒 SECURITY OVERVIEW

**LINUX SERVER Tools** met beperkte write operaties:

### ✅ WAT KAN WEL:
- **Files LEZEN** (in toegestane directories)
- **Logs BEKIJKEN** (WordPress, system logs)
- **Services STATUS** bekijken en **RESTART** (alleen whitelisted services)
- **WP-CLI** uitvoeren (alleen op whitelisted sites)
- **Python CODE** uitvoeren (sandboxed, geen netwerk, 8s timeout)
- **Cron JOBS** beheren (alleen binnen MCP-managed sectie)

### ❌ WAT NIET KAN:
- Toegang tot willekeurige directories (strict whitelisting)
- Services **STOPPEN/STARTEN/ENABLEN** (alleen restart)
- Sudo/root operaties (buiten WP-CLI)
- Python met netwerk toegang
- Wijzigen van system crontab buiten MCP-sectie

---

## 📂 TOEGESTANE DIRECTORIES

### Read Access (ALLOWED_READ_DIRS):
- `/var/log` - System logs
- `/etc` - Configuratie files
- `/tmp` - Temporary files
- `/opt/` - Optional software
- `/root/scripts` - Root scripts
- `/var/www` - Web roots (WordPress)

### Log Access (ALLOWED_LOG_DIRS):
- `/var/log` - System logs
- `/tmp` - Temporary logs
- `/opt/ai_trading_bot` - AI Trading Bot logs
- `/opt/finbert` - FinBERT logs
- `/var/www` - WordPress debug logs

---

## 🛠️ TOEGESTANE SERVICES (SERVICE_WHITELIST)

Alleen deze services kunnen ge-status/restart worden:
- `apache2` - Webserver
- `php8.4-fpm` - PHP FastCGI Process Manager
- `postfix` - Mail server
- `opendkim` - DomainKeys email authentication
- `sshd` - SSH daemon
- `docker` - Container runtime
- `memcached` - Memory cache daemon
- `ai-trading-dashboard.service` - AI Trading Dashboard

---

## 🌐 WORDPRESS SITES (WP_ALLOWED_SITES)

WP-CLI alleen toegestaan voor:
- `/var/www/myvox.eu`
- `/var/www/netcare.nl` ⭐ (primary development site)
- `/var/www/vioolles.net`
- `/var/www/heksenendraken`

---

## 📚 TOOL CATEGORIEËN

### 1️⃣ METADATA & DISCOVERY (Read-Only)
- `get_service_whitelist()` - Lijst beheerbare services
- `get_wp_allowed_sites()` - Lijst WordPress sites

### 2️⃣ FILE OPERATIONS (Read-Only)
- `list_dir(path, pattern, include_files, include_dirs, max_items)` - Directory listing
- `read_file(path, max_bytes)` - Bestand lezen (max 512KB)
- `head(path, n)` - Eerste N regels
- `tail(path, n)` - Laatste N regels (voor logs)
- `log_tail(path, n)` - Alias voor tail (duidelijker voor logs)

### 3️⃣ WORDPRESS LOGS (Read-Only)
- `log_pick_path()` - Vindt beste WP log pad
- `log_tail_ai(n)` - Filter op 'ai-translate:' keywords
- `log_tail_flow(n)` - Filter op flow events
- `log_tail_keywords(keywords, n)` - Filter op custom keywords

### 4️⃣ SYSTEM SERVICES
- `service_status(name)` - Status bekijken (Read-Only)
- `restart_service(name)` - Service herstarten ⚠️ (Live impact!)

### 5️⃣ PYTHON EXECUTION
- `python_run(code)` - Sandboxed Python (geen netwerk, 8s timeout)

### 6️⃣ WP-CLI OPERATIONS
- `wp_cli(site_path, args, as_www_data)` - Algemene WP-CLI runner
- `wp_cache_flush(site_path, as_www_data)` - Cache flush
- `wp_plugin_list(site_path, as_www_data)` - Lijst plugins (JSON)
- `wp_user_list(site_path, as_www_data)` - Lijst users (JSON)

### 7️⃣ CRON MANAGEMENT
- `cron_list()` - Bekijk crontab (Read-Only)
- `cron_add(job_id, schedule, command)` - Job toevoegen ⚠️ (Live impact!)
- `cron_remove(job_id)` - Job verwijderen ⚠️ (Live impact!)
- `cron_enable(job_id, enabled)` - Job aan/uit ⚠️ (Live impact!)
- `cron_next_runs(schedule, n)` - Valideer schedule (Read-Only)

---

## 💡 GEBRUIK VOORBEELDEN

### WordPress Database Query:
```json
{"tool": "wp_cli", "args": {
  "site_path": "/var/www/netcare.nl",
  "args": "db tables",
  "as_www_data": false
}}
```

### Plugin Lijst Ophalen:
```json
{"tool": "wp_plugin_list", "args": {
  "site_path": "/var/www/netcare.nl",
  "as_www_data": false
}}
```

### Debug Log Bekijken:
```json
{"tool": "log_tail", "args": {
  "path": "/var/www/netcare.nl/wp-content/debug.log",
  "n": 100
}}
```

### Service Status:
```json
{"tool": "service_status", "args": {
  "name": "apache2"
}}
```

### Python Uitvoeren:
```json
{"tool": "python_run", "args": {
  "code": "import sys; print(sys.version)"
}}
```

---

## ⚠️ BELANGRIJKE OPMERKINGEN VOOR LLMs

1. **Read-Only Default**: De meeste tools zijn read-only. Write operaties zijn beperkt tot:
   - `restart_service()` - Herstart services
   - `cron_add/remove/enable()` - Cron modificaties
   - WP-CLI kan database wijzigen (wees voorzichtig!)

2. **Whitelisting**: Alles is gewhitelisted. Tools retourneren "Denied" als je buiten whitelist werkt.

3. **WordPress Sites**: netcare.nl is de primaire development site met ai-translate plugin.

4. **PHP Deprecation Warnings**: netcare.nl draait PHP 8.4, dus stderr bevat veel deprecation warnings. Dit is normaal en geen error.

5. **Security First**: 
   - Geen blind `rm -rf` mogelijk
   - Geen willekeurige file writes
   - Python is gesandboxed
   - Cron commands moeten absolute paden zijn

6. **Error Handling**: Tools retourneren duidelijke errors:
   - "Denied" = buiten whitelist
   - "Not found" = bestand/site bestaat niet
   - {"error": "..."} = specifieke fout

7. **Return Types**:
   - Strings voor simpele output
   - Dicts voor gestructureerde data (WP-CLI, Python, etc.)
   - Lists voor directories en cron schedules

---

## 🎯 BEST PRACTICES

1. **Gebruik specifieke tools**: Gebruik `wp_plugin_list()` ipv algemene `wp_cli()`
2. **Check whitelists eerst**: Roep `get_wp_allowed_sites()` aan voordat je WP-CLI gebruikt
3. **Read-only eerst**: Bekijk status/logs voordat je services restart
4. **Validate cron schedules**: Gebruik `cron_next_runs()` om schedules te valideren
5. **Filter logs**: Gebruik `log_tail_keywords()` voor specifieke zoektermen
6. **Error handling**: Check altijd op "Denied" of {"error": ...} in responses

---

## 📊 TESTED & VERIFIED

Alle tools zijn getest en werken correct:
✅ netcare.nl WordPress v6.8.3
✅ 23 plugins (incl. ai-translate v2.0.4)
✅ Database toegang via WP-CLI
✅ Debug log reading (1.3 MB)
✅ Service status (apache2, php8.4-fpm active)
✅ Python 3.13 execution
✅ Cron schedule validation

**Last Updated**: 2025-10-27
**Server**: ai-server (Linux)
**Environment**: Production

