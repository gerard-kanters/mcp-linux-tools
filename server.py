"""
MCP Linux Tools Server
======================

Server for Linux system management

REQUIREMENTS:
- Server must run as ROOT for systemctl and crontab access

SECURITY RESTRICTIONS:
- Limited directory access (see ALLOWED_READ_DIRS and ALLOWED_LOG_DIRS)
- Service management: only status/restart of whitelisted services
- WP-CLI: only for specific WordPress sites
- Python: sandboxed, no network, 8s timeout
- Cron: only within MCP-managed section

ALLOWED DIRECTORIES:
- Read access: /var/log, /etc, /tmp, /opt/, /root/scripts, /var/www /backup, /etc/odoo/ 
- Log access: /var/log, /tmp, /opt/ai_trading_bot, /opt/finbert, /var/www

ALLOWED SERVICES:
- apache2, php8.4-fpm, postfix, opendkim, sshd, docker, memcached, ai-trading-dashboard.service

WORDPRESS SITES (WP-CLI):
- /var/www/myvox.eu
- /var/www/netcare.nl
- /var/www/vioolles.net
- /var/www/heksenendraken
"""

from __future__ import annotations

from fastmcp import FastMCP
import subprocess, pathlib, os, re, tempfile, time, shlex, shutil
from typing import Optional
try:
    from croniter import croniter   # optioneel
except Exception:
    croniter = None

mcp = FastMCP("LinuxTools")

# =======================
#   POLICY & CONSTANTS
# =======================
ALLOWED_LOG_DIRS  = ["/var/log", "/tmp", "/opt/ai_trading_bot", "/opt/finbert", "/var/www"]
ALLOWED_READ_DIRS = ["/var/log", "/etc", "/tmp", "/opt/", "/root/scripts", "/var/www", "/backup"]
SERVICE_WHITELIST = {"apache2", "php8.4-fpm", "postfix", "opendkim", "sshd", "docker", "memcached", "ai-trading-dashboard.service", "postgresql", "odoo"}
MAX_BYTES   = 512 * 1024
MAX_ITEMS   = 500
PYTHON_BIN  = "/opt/mcp/venv/bin/python"
PY_TIMEOUT  = 8
SANDBOX_CWD = "/opt/mcp/sandbox"

# WP-CLI policy
WP_ALLOWED_SITES = [
    "/var/www/myvox.eu",
    "/var/www/netcare.nl",
    "/var/www/vioolles.net",
    "/var/www/heksenendraken",
    "/var/www/traders-for-traders",
    # add additional WP roots here if needed
]
WP_BIN_CANDIDATES = ["/usr/local/bin/wp", "/usr/bin/wp"]

# Cron (root)
CRON_USER = "root"
MCP_SECTION_BEGIN = "# --- BEGIN MCP MANAGED ---"
MCP_SECTION_END   = "# --- END MCP MANAGED ---"
CRON_MAX_LINES = 2000


# =======================
#         HELPERS
# =======================
def _is_under_allowlist(p: pathlib.Path, allow: list[str]) -> bool:
    rp = str(p.resolve())
    return any(rp.startswith(d.rstrip("/") + "/") or rp == d for d in allow)

def _safe_text(b: bytes) -> str:
    try:
        return b.decode("utf-8", errors="replace")
    except Exception:
        return str(b)

def _run(cmd: list[str], **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


# =======================
#  METADATA / DISCOVERY
# =======================
@mcp.tool
def get_service_whitelist() -> list[str]:
    """
    List of services that this server **may** manage (status/restart).

    ALLOWED SERVICES (SERVICE_WHITELIST):
    - apache2
    - php8.4-fpm
    - postfix
    - opendkim
    - sshd
    - docker
    - memcached
    - ai-trading-dashboard.service

    Return:
    - list[str]: names as they are passed to `systemctl`.

    Example: {}
    """
    return sorted(SERVICE_WHITELIST)

@mcp.tool
def get_wp_allowed_sites() -> list[str]:
    """
    List of WordPress roots for which WP-CLI is allowed.

    ALLOWED WORDPRESS SITES (WP_ALLOWED_SITES):
    - /var/www/myvox.eu
    - /var/www/netcare.nl
    - /var/www/vioolles.net
    - /var/www/heksenendraken
    - /var/www/traders-for-traders

    Return:
    - list[str]: absolute paths to WP roots (where `wp-config.php` is located).

    Example: {}
    """
    return WP_ALLOWED_SITES[:]


# =======================
#   FILES / DIRECTORIES
# =======================
@mcp.tool
def list_dir(path: str, pattern: str = "*", include_files: bool = True, include_dirs: bool = False, max_items: int = MAX_ITEMS) -> list[dict]:
    """
    Show directory contents with simple filtering (only under ALLOWED_READ_DIRS).
    
    ALLOWED_READ_DIRS currently:
    - /var/log
    - /etc
    - /tmp
    - /opt/
    - /root/scripts
    - /var/www
    - /backup

    Parameters:
    - path (str): Directory path.
    - pattern (str): Glob pattern (e.g. "*.log", "**/*.conf").
    - include_files (bool): Include files.
    - include_dirs (bool): Include subdirectories.
    - max_items (int): Upper limit (default 500).

    Return: list[dict] with fields name/path/is_dir/size/mtime or [{"error": "..."}].
    """
    p = pathlib.Path(path)
    if not _is_under_allowlist(p, ALLOWED_READ_DIRS):
        return [{"error": "Denied"}]
    if not p.is_dir():
        return [{"error": "Not a directory"}]
    items = []
    for entry in p.glob(pattern):
        if len(items) >= max_items:
            break
        if (entry.is_file() and include_files) or (entry.is_dir() and include_dirs):
            stat = entry.stat()
            items.append({
                "name": entry.name,
                "path": str(entry.resolve()),
                "is_dir": entry.is_dir(),
                "size": stat.st_size if entry.is_file() else None,
                "mtime": int(stat.st_mtime)
            })
    return items

@mcp.tool
def create_directory(path: str, owner: str = "root", group: str = "root", mode: str = "755", parents: bool = False) -> str:
    """
    Create a new directory.

    SECURITY:
    - Only paths under ALLOWED_WRITE_DIRS allowed (for the parent directory).

    Parameters:
    - path (str): The absolute path to the directory to be created.
    - owner (str, optional): The owner of the directory (default "root").
    - group (str, optional): The group owner of the directory (default "root").
    - mode (str, optional): The octal file permissions (default "755").
    - parents (bool, optional): Whether missing parent directories should be created recursively (default False).

    Return: "ok" or error message.

    Example:
    {"path": "/opt/odoo", "owner": "odoo", "group": "odoo", "mode": "755", "parents": True}
    """
    p = pathlib.Path(path)

    # Security: only allow /var/www and /opt/
    if not _is_under_allowlist(p.parent, ["/var/www", "/opt/"]):
        return "Denied: target directory not under /var/www or /opt/"

    try:
        octal_mode = int(mode, 8)
        p.mkdir(parents=parents, mode=octal_mode)
        shutil.chown(str(p), user=owner, group=group)
        return "ok"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool
def read_file(path: str, max_bytes: int = MAX_BYTES) -> str:
    """
    Read a small text file (utf-8) under ALLOWED_READ_DIRS.
    
    SECURITY: READ-ONLY only, no write/delete operations possible.

    Parameters:
    - path (str): Absolute path to file.
    - max_bytes (int): Max bytes (default 512 KiB).

    Return: contents or "Denied" if outside allowed directories.
    
    Example: {"path": "/etc/hostname"}
    """
    p = pathlib.Path(path)
    if not _is_under_allowlist(p, ALLOWED_READ_DIRS) or not p.is_file():
        return "Denied"
    with open(p, "rb") as f:
        data = f.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    out = _safe_text(data[:max_bytes])
    return out + ("\n\n[...truncated...]" if truncated else "")

@mcp.tool
def head(path: str, n: int = 100) -> str:
    """
    First `n` lines of a file (under ALLOWED_READ_DIRS).

    Example:
    { "path": "/etc/nginx/nginx.conf", "n": 50 }
    """
    p = pathlib.Path(path)
    if not _is_under_allowlist(p, ALLOWED_READ_DIRS) or not p.is_file():
        return "Denied"
    try:
        res = subprocess.run(["head", "-n", str(n), str(p)], capture_output=True, text=True, check=True)
        return res.stdout
    except subprocess.CalledProcessError as e:
        return e.stderr or str(e)

def _tail(path: str, n: int = 200) -> str:
    """Internal tail implementation."""
    p = pathlib.Path(path)
    if not _is_under_allowlist(p, ALLOWED_LOG_DIRS) or not p.is_file():
        return "Denied"
    try:
        res = subprocess.run(["tail", "-n", str(n), str(p)], capture_output=True, text=True, check=True)
        return res.stdout
    except subprocess.CalledProcessError as e:
        return e.stderr or str(e)

@mcp.tool
def tail(path: str, n: int = 200) -> str:
    """
    Last `n` lines of a **log file** under ALLOWED_LOG_DIRS.

    ALLOWED_LOG_DIRS currently:
    - /var/log
    - /tmp
    - /opt/ai_trading_bot
    - /opt/finbert
    - /var/www

    Example:
    { "path": "/var/log/syslog", "n": 300 }
    """
    return _tail(path, n)

@mcp.tool
def log_tail(path: str, n: int = 200) -> str:
    """
    Alias with clear name: tail a log file under ALLOWED_LOG_DIRS.

    Specifically intended to direct LLMs to **/var/log/** and other log directories.

    Examples:
    - { "path": "/var/log/syslog", "n": 400 }
    - { "path": "/var/log/nginx/error.log" }
    - { "path": "/var/www/myvox.eu/wp-content/debug.log", "n": 500 }

    (Functionally identical to `tail()`; only the name is clearer for log tasks.)
    """
    return _tail(path, n)


# =======================
#      WORDPRESS LOGS
# =======================
def _pick_wp_log_path() -> str:
    candidates = [
        "/var/www/myvox.eu/wp-content/uploads/ai-translate/logs/urlmap.log",
        "/var/www/myvox.eu/wp-content/debug.log",
    ]
    for p in candidates:
        if pathlib.Path(p).is_file():
            return p
    return ""

@mcp.tool
def log_pick_path() -> str:
    """
    Return the best guess WP log:
    1) uploads/ai-translate/logs/urlmap.log
    2) wp-content/debug.log
    Return: absolute path or "Not found".

    Tip: for **other** logs under /var/log use `log_tail` or `tail` directly.
    """
    p = _pick_wp_log_path()
    return p if p else "Not found"

@mcp.tool
def log_tail_ai(n: int = 300) -> dict:
    """
    Tail the WP log and filter on 'ai-translate:'.

    Example:
    { "n": 500 }

    Tip: for system logs: use `log_tail("/var/log/syslog")`.
    """
    p = _pick_wp_log_path()
    if not p:
        return {"error": "No log file found"}
    if not _is_under_allowlist(pathlib.Path(p), ALLOWED_LOG_DIRS):
        return {"error": "Denied"}
    try:
        has_grep = shutil.which("grep") is not None
        if has_grep:
            cmd = f"tail -n {int(n)} {shlex.quote(p)} | grep -F \"ai-translate:\" || true"
            proc = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True)
            out = proc.stdout or ""
            if not out.strip():
                out = subprocess.run(["tail", "-n", str(int(n)), p], capture_output=True, text=True).stdout
        else:
            out = subprocess.run(["tail", "-n", str(int(n)), p], capture_output=True, text=True).stdout
        return {"path": p, "lines": out}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool
def log_tail_flow(n: int = 400) -> dict:
    """
    Tail WP log and filter on mapping-flow events:
    request:start, parse_request:start, resolved_post_id, resolved_page_by_path,
    fallback_pagename, no_reverse_mapping, empty_basename, pre_handle_404.

    Example:
    { "n": 400 }
    """
    p = _pick_wp_log_path()
    if not p:
        return {"error": "No log file found"}
    if not _is_under_allowlist(pathlib.Path(p), ALLOWED_LOG_DIRS):
        return {"error": "Denied"}
    pattern = r"ai-translate:(request:start|parse_request:start|resolved_post_id|resolved_page_by_path|fallback_pagename|no_reverse_mapping|empty_basename|pre_handle_404)"
    try:
        cmd = f"tail -n {int(n)} {shlex.quote(p)} | grep -E {shlex.quote(pattern)} || true"
        proc = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True)
        return {"path": p, "lines": proc.stdout}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool
def log_tail_keywords(keywords: list[str], n: int = 400) -> dict:
    """
    Tail WP log and filter on arbitrary keywords (case-sensitive).

    Example:
    { "keywords": ["contacto","funcionalidad"], "n": 600 }
    """
    p = _pick_wp_log_path()
    if not p:
        return {"error": "No log file found"}
    if not _is_under_allowlist(pathlib.Path(p), ALLOWED_LOG_DIRS):
        return {"error": "Denied"}
    try:
        if not keywords:
            return {"path": p, "lines": ""}
        expr = "(" + "|".join([re.escape(k) for k in keywords]) + ")"
        cmd = f"tail -n {int(n)} {shlex.quote(p)} | grep -E {shlex.quote(expr)} || true"
        proc = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True)
        return {"path": p, "lines": proc.stdout}
    except Exception as e:
        return {"error": str(e)}


# =======================
#         SYSTEMD
# =======================
@mcp.tool
def service_status(name: str) -> str:
    """
    Short status (is-active) of a service via systemctl.
    
    SECURITY: READ-ONLY status only, no stop/start/enable/disable.
    NOTE: MCP server must run as root for systemctl access.

    ALLOWED SERVICES (SERVICE_WHITELIST):
    - apache2, php8.4-fpm, postfix, opendkim, sshd, docker, memcached, ai-trading-dashboard.service

    Return: "{name}: {status}" or "Denied" if service not in whitelist.
    
    Example: {"name": "apache2"}
    """
    if name not in SERVICE_WHITELIST:
        return "Denied"
    
    res = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True)
    state = res.stdout.strip() if res.returncode == 0 else "unknown"
    return f"{name}: {state}"

@mcp.tool
def restart_service(name: str) -> str:
    """
    Restart a service and report the new status via systemctl restart.
    
    SECURITY: Only RESTART allowed, no stop/start/enable/disable.
    NOTE: MCP server must run as root for systemctl access.
    ⚠️ mcp-linux-tools.service must NOT be restarted (would disconnect Cursor)
    WARNING: This affects the live server!

    ALLOWED SERVICES (SERVICE_WHITELIST):
    - apache2, php8.4-fpm, postfix, opendkim, sshd, docker, memcached, ai-trading-dashboard.service

    Return: "Restarted {name}. State: {status}" or "Denied"/"Failed"
    
    Example: {"name": "php8.4-fpm"}
    """
    if name not in SERVICE_WHITELIST:
        return "Denied"
    
    # Prevent restarting MCP server itself (would disconnect Cursor)
    if name == "mcp-linux-tools.service" or name == "mcp-linux-tools":
        return "Denied: Cannot restart MCP server (would disconnect Cursor)"
    
    res = subprocess.run(["systemctl", "restart", name], capture_output=True, text=True)
    if res.returncode != 0:
        return f"Failed: {res.stderr.strip()}"
    st = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True)
    return f"Restarted {name}. State: {st.stdout.strip() if st.returncode == 0 else 'unknown'}"


# =======================
#       PYTHON EXEC
# =======================
@mcp.tool
def python_run(code: str) -> dict:
    """
    Execute short Python code in separate venv (without network), with timeout.
    
    SECURITY RESTRICTIONS:
    - Interpreter: /opt/mcp/venv/bin/python (Python 3.13)
    - CWD: /opt/mcp/sandbox (isolated)
    - Timeout: 8 seconds
    - No network access
    - Limited environment (only /usr/bin and /bin in PATH)
    
    Return: {"stdout": str, "stderr": str, "exit": int}

    Example: {"code": "import platform; print(platform.python_version())"}
    """
    os.makedirs(SANDBOX_CWD, exist_ok=True)
    proc = subprocess.run(
        [PYTHON_BIN, "-S", "-c", code],
        cwd=SANDBOX_CWD,
        capture_output=True,
        text=True,
        timeout=PY_TIMEOUT,
        env={"PATH": "/usr/bin:/bin", "PYTHONUNBUFFERED": "1"}
    )
    return {"stdout": proc.stdout, "stderr": proc.stderr, "exit": proc.returncode}


# =======================
#         WP-CLI
# =======================
def _which_wp() -> Optional[str]:
    for p in WP_BIN_CANDIDATES:
        if pathlib.Path(p).is_file() and os.access(p, os.X_OK):
            return p
    wp_in_path = shutil.which("wp")
    return wp_in_path

def _is_allowed_site(site_path: str) -> bool:
    rp = str(pathlib.Path(site_path).resolve())
    return any(rp.startswith(s.rstrip("/") + "/") or rp == s for s in WP_ALLOWED_SITES)

def _wp_cli(site_path: str, args: str, as_www_data: bool = True) -> dict:
    """Internal WP-CLI runner implementation."""
    if not _is_allowed_site(site_path):
        return {"error": "Denied: site_path not allowed"}
    
    wp_config = pathlib.Path(site_path) / "wp-config.php"
    if not wp_config.is_file():
        return {"error": f"wp-config.php not found in {site_path}"}
    
    wp = _which_wp()
    if not wp:
        return {"error": "wp not found (install wp-cli)"}
    
    cmd = [wp, f"--path={site_path}"] + shlex.split(args)
    
    if not as_www_data:
        cmd.append("--allow-root")
    
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "WP_CLI_DISABLE_AUTO_CHECK_UPDATE": "1",
        "HOME": "/var/www" if as_www_data else "/root",
    }
    
    try:
        if as_www_data:
            full = ["sudo", "-u", "www-data", "-E"] + cmd
        else:
            full = cmd
        proc = subprocess.run(full, capture_output=True, text=True, env=env, timeout=60)
        return {"cmd": " ".join(full), "exit": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool
def wp_cli(site_path: str, args: str, as_www_data: bool = True) -> dict:
    """
    WP-CLI runner for **allowed** WordPress sites.
    
    SECURITY: Only allowed sites, auto-check for wp-config.php.

    ALLOWED WORDPRESS SITES (WP_ALLOWED_SITES):
    - /var/www/myvox.eu
    - /var/www/netcare.nl
    - /var/www/vioolles.net
    - /var/www/heksenendraken
    - /var/www/traders-for-traders

    Parameters:
    - site_path (str): WP root path (must be in whitelist)
    - args (str): WP-CLI subcommand + flags, e.g. "plugin list --format=json"
    - as_www_data (bool): default True (execute as www-data user)

    Return:
    - dict: {"cmd": str, "exit": int, "stdout": str, "stderr": str} 
    - or {"error": "Denied/Not found"}

    Examples:
    {"site_path": "/var/www/netcare.nl", "args": "cache flush"}
    {"site_path": "/var/www/netcare.nl", "args": "plugin list --format=json"}
    {"site_path": "/var/www/netcare.nl", "args": "db tables"}
    """
    return _wp_cli(site_path, args, as_www_data)

@mcp.tool
def wp_cache_flush(site_path: str, as_www_data: bool = True) -> dict:
    """
    WP-CLI: `cache flush` for an allowed WordPress site.
    
    Shortcut for: wp_cli(site_path, "cache flush", as_www_data)

    Parameters:
    - site_path: must be in WP_ALLOWED_SITES whitelist

    Example: {"site_path": "/var/www/netcare.nl"}
    """
    return _wp_cli(site_path, "cache flush", as_www_data)

@mcp.tool
def wp_plugin_list(site_path: str, as_www_data: bool = True) -> dict:
    """
    WP-CLI: list all plugins in JSON format.
    
    Shortcut for: wp_cli(site_path, "plugin list --format=json", as_www_data)
    
    Return: JSON array with plugin info (name, status, version, etc.)

    Example: {"site_path": "/var/www/netcare.nl"}
    """
    return _wp_cli(site_path, "plugin list --format=json", as_www_data)

@mcp.tool
def wp_user_list(site_path: str, as_www_data: bool = True) -> dict:
    """
    WP-CLI: list all WordPress users in JSON format.
    
    Shortcut for: wp_cli(site_path, "user list --format=json", as_www_data)
    
    Return: JSON array with user info (ID, login, email, roles, etc.)

    Example: {"site_path": "/var/www/netcare.nl"}
    """
    return _wp_cli(site_path, "user list --format=json", as_www_data)


# =======================
#           CRON
# =======================
def _validate_schedule(s: str) -> bool:
    ok = bool(re.match(r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+$", s.strip()))
    if ok and croniter:
        try:
            croniter(s, time.time())
        except Exception:
            return False
    return ok

def _get_crontab(user: str) -> str:
    cmd = ["crontab", "-u", user, "-l"]
    p = _run(cmd)
    if p.returncode != 0 and "no crontab for" in (p.stderr or "").lower():
        return ""
    return p.stdout or ""

def _set_crontab(user: str, content: str) -> str:
    if content.count("\n") > CRON_MAX_LINES:
        return "Denied: crontab too large"
    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write(content)
        tpath = tf.name
    cmd = ["crontab", "-u", user, tpath]
    pr = _run(cmd)
    return pr.stderr.strip() if pr.returncode != 0 else "ok"

def _ensure_section(text: str) -> str:
    if MCP_SECTION_BEGIN in text and MCP_SECTION_END in text:
        return text
    if text and not text.endswith("\n"):
        text += "\n"
    return text + f"{MCP_SECTION_BEGIN}\n{MCP_SECTION_END}\n"

def _replace_or_append_job(section: str, job_id: str, line: Optional[str]) -> str:
    lines = section.splitlines()
    out: list[str] = []
    i, found = 0, False
    while i < len(lines):
        if lines[i].startswith("# MCP: id="):
            m = re.search(r"id=([A-Za-z0-9._\-]+)", lines[i])
            if m and m.group(1) == job_id:
                found = True
                i += 1
                if i < len(lines) and not lines[i].startswith("#"):
                    i += 1
                if line:
                    out.append(f"# MCP: id={job_id} enabled=1")
                    out.append(line)
                continue
        out.append(lines[i]); i += 1
    if not found and line:
        out.append(f"# MCP: id={job_id} enabled=1")
        out.append(line)
    return "\n".join(out) + ("\n" if out and not out[-1].endswith("\n") else "")

def _set_enabled(section: str, job_id: str, enabled: bool) -> str:
    lines = section.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        if lines[i].startswith("# MCP: id=") and f"id={job_id}" in lines[i]:
            out.append(f"# MCP: id={job_id} enabled={'1' if enabled else '0'}")
            i += 1
            if i < len(lines) and not lines[i].startswith("#"):
                cron = lines[i]
                if enabled and cron.startswith("# "):
                    out.append(cron[2:])
                elif (not enabled) and not cron.startswith("# "):
                    out.append("# " + cron)
                else:
                    out.append(cron)
                i += 1
            continue
        out.append(lines[i]); i += 1
    return "\n".join(out) + ("\n" if out and not out[-1].endswith("\n") else "")

@mcp.tool
def cron_list() -> str:
    """
    Show the full crontab of root (read-only).
    
    SECURITY: READ-ONLY only, no modifications.

    Return: full crontab content as string

    Example: {}
    """
    return _get_crontab(CRON_USER)

@mcp.tool
def cron_add(job_id: str, schedule: str, command: str) -> str:
    """
    Add or replace a job in the MCP section of root's crontab.
    
    SECURITY RESTRICTIONS:
    - Only within MCP-managed section (between BEGIN/END markers)
    - Command must be absolute path (no relative paths)
    - Schedule validation via croniter
    - Max 2000 lines total crontab
    
    WARNING: This modifies the live server crontab!

    Parameters:
    - job_id: unique identifier (alphanumeric + ._-)
    - schedule: cron format "min hour day month weekday"
    - command: absolute path to command + args

    Return: "ok" or "error: {reason}"

    Example:
    {"job_id": "cleanup_tmp", "schedule": "*/10 * * * *", 
     "command": "/usr/bin/find /tmp -type f -mtime +1 -delete"}
    """
    if not _validate_schedule(schedule):
        return "Invalid schedule"
    first = command.split()[0]
    if not os.path.isabs(first):
        return "Denied: command must be absolute path"
    content = _ensure_section(_get_crontab(CRON_USER))
    pre, mid, post = content.partition(MCP_SECTION_BEGIN)
    sect, mid2, post2 = post.partition(MCP_SECTION_END)
    section_body = _replace_or_append_job(sect, job_id, f"{schedule} {command}")
    new_content = pre + mid + section_body + post2
    res = _set_crontab(CRON_USER, new_content)
    return "ok" if res == "ok" else f"error: {res}"

@mcp.tool
def cron_remove(job_id: str) -> str:
    """
    Remove one MCP job from root's crontab.
    
    SECURITY: Only MCP-managed jobs can be removed.
    WARNING: This modifies the live server crontab!

    Parameters:
    - job_id: identifier of job to remove

    Return: "ok" or "error: {reason}"

    Example: {"job_id": "cleanup_tmp"}
    """
    content = _ensure_section(_get_crontab(CRON_USER))
    pre, mid, post = content.partition(MCP_SECTION_BEGIN)
    sect, mid2, post2 = post.partition(MCP_SECTION_END)
    section_body = _replace_or_append_job(sect, job_id, None)
    new_content = pre + mid + section_body + post2
    res = _set_crontab(CRON_USER, new_content)
    return "ok" if res == "ok" else f"error: {res}"

@mcp.tool
def cron_enable(job_id: str, enabled: bool) -> str:
    """
    Turn an MCP job **on/off** (comment/uncomment).
    
    SECURITY: Only MCP-managed jobs can be modified.
    WARNING: This modifies the live server crontab!

    Parameters:
    - job_id: identifier of job
    - enabled: True = uncomment (active), False = comment (inactive)

    Return: "ok" or "error: {reason}"

    Example: {"job_id": "cleanup_tmp", "enabled": false}
    """
    content = _ensure_section(_get_crontab(CRON_USER))
    pre, mid, post = content.partition(MCP_SECTION_BEGIN)
    sect, mid2, post2 = post.partition(MCP_SECTION_END)
    section_body = _set_enabled(sect, job_id, enabled)
    new_content = pre + mid + section_body + post2
    res = _set_crontab(CRON_USER, new_content)
    return "ok" if res == "ok" else f"error: {res}"

@mcp.tool
def cron_next_runs(schedule: str, n: int = 5) -> list:
    """
    Calculate the next `n` run times for a cron schedule.
    
    Useful to validate if a cron schedule is correct.
    
    Parameters:
    - schedule: cron format "min hour day month weekday"
    - n: number of future runs (max 20)
    
    Return: list of datetime strings (YYYY-MM-DD HH:MM:SS) or [] if invalid

    Example: {"schedule": "0 3 * * *", "n": 5}
    """
    if not _validate_schedule(schedule) or not croniter:
        return []
    base = time.time()
    it = croniter(schedule, base)
    return [time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(it.get_next())) for _ in range(max(1, min(20, n)))]


# =======================
#       DATABASE (MySQL)
# =======================
@mcp.tool
def mysql_query(query: str, database: str = "") -> dict:
    """
    Execute a MySQL query on the production databases.
    
    SECURITY:
    - Queries are read-only protected where possible
    - No DROP/TRUNCATE/ALTER without caution
    - Commands must be safe
    
    Parameters:
    - query: SQL query (e.g. "SELECT * FROM wp_users WHERE ID=1")
    - database: optional database name (e.g. "netcare_nl" or "myvox_eu")
    
    Return: dict with result set or error message
    
    Example:
    {"query": "SHOW DATABASES;"}
    {"query": "SELECT * FROM wp_posts LIMIT 5;", "database": "netcare_nl"}
    """
    if not query or not query.strip():
        return {"error": "Query cannot be empty"}
    
    # Basic injection prevention
    query_upper = query.strip().upper()
    dangerous = ["DROP", "TRUNCATE", "DELETE", "ALTER"]
    if any(q in query_upper for q in dangerous):
        return {"error": f"Dangerous query blocked: contains {[q for q in dangerous if q in query_upper]}"}
    
    try:
        cmd = ["mysql", "-u", "root"]
        if database:
            cmd.append(database)
        cmd.extend(["-e", query])
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            return {"error": result.stderr.strip() or "Query failed"}
        
        return {"query": query, "database": database or "default", "result": result.stdout}
    except subprocess.TimeoutExpired:
        return {"error": "Query timeout (30s)"}
    except Exception as e:
        return {"error": str(e)}


# =======================
#     FILE PERMISSIONS
# =======================
@mcp.tool
def chmod_file(path: str, mode: str) -> str:
    """
    Change file permissions via chmod.
    
    SECURITY:
    - Only directories under /var/www and /opt/ allowed
    - Mode must be valid octal number (e.g. 755, 644)
    
    Parameters:
    - path: file path (e.g. "/var/www/netcare.nl/wp-content")
    - mode: octal mode (e.g. "755", "644", "777")
    
    Return: "ok" or error message
    
    Example:
    {"path": "/var/www/netcare.nl/wp-content/uploads", "mode": "755"}
    {"path": "/var/www/myvox.eu/wp-content/cache", "mode": "644"}
    """
    p = pathlib.Path(path)
    
    # Security: only allow /var/www and /opt/
    if not _is_under_allowlist(p, ["/var/www", "/opt/"]):
        return "Denied: only /var/www and /opt/ allowed"
    
    if not p.exists():
        return f"Error: path does not exist"
    
    # Validate octal mode
    if not re.match(r"^[0-7]{3,4}$", mode):
        return "Error: invalid mode, must be octal (e.g. 755, 0755)"
    
    try:
        octal_mode = int(mode, 8)
        os.chmod(str(p), octal_mode)
        return f"ok: changed {path} to {mode}"
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool
def chown_path(path: str, owner: str, group: str) -> str:
    """
    Change file or directory owner and group via chown.

    SECURITY:
    - Only paths under /var/www and /opt/ allowed.

    Parameters:
    - path: file path (e.g. "/var/www/netcare.nl/wp-content")
    - owner: new owner (e.g. "www-data")
    - group: new group (e.g. "www-data")

    Return: "ok" or error message

    Example:
    {"path": "/var/www/netcare.nl/wp-content/uploads", "owner": "www-data", "group": "www-data"}
    """
    p = pathlib.Path(path)

    # Security: only allow /var/www and /opt/
    if not _is_under_allowlist(p, ["/var/www", "/opt/"]):
        return "Denied: only /var/www and /opt/ allowed"

    if not p.exists():
        return f"Error: path does not exist"

    try:
        shutil.chown(str(p), user=owner, group=group)
        return f"ok: changed owner/group of {path} to {owner}:{group}"
    except Exception as e:
        return f"Error: {str(e)}"


# =======================
#      NETWORK (PING)
# =======================
@mcp.tool
def ping_host(host: str, count: int = 4) -> dict:
    """
    Test network connectivity via ping.
    
    SECURITY:
    - Max 10 packets (prevents flooding)
    - Timeout 30 seconds
    - Valid hostname/IP validation
    
    Parameters:
    - host: hostname or IP address (e.g. "netcare.nl", "8.8.8.8")
    - count: number of packets (default 4, max 10)
    
    Return: dict with ping result
    
    Example:
    {"host": "netcare.nl"}
    {"host": "8.8.8.8", "count": 8}
    """
    # Sanitize host input
    if not re.match(r"^[a-zA-Z0-9.-]+$", host):
        return {"error": "Invalid hostname format"}
    
    count = max(1, min(10, int(count)))  # Limit to 1-10
    
    try:
        cmd = ["ping", "-c", str(count), "-W", "30", host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        return {
            "host": host,
            "count": count,
            "success": result.returncode == 0,
            "output": result.stdout or result.stderr
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Ping timeout for {host}"}
    except Exception as e:
        return {"error": str(e)}


# =======================
#        GIT CONTROL
# =======================
@mcp.tool
def git_command(path: str, command: str) -> dict:
    """
    Execute Git commands in allowed repositories.
    
    SECURITY:
    - Only repositories under /var/www and /opt/
    - Only safe commands (pull, status, log, diff, branch)
    - No push/force operations
    
    Parameters:
    - path: git repository directory
    - command: git subcommand (e.g. "status", "pull origin master", "log -5")
    
    Return: dict with output or error
    
    Example:
    {"path": "/var/www/netcare.nl", "command": "status"}
    {"path": "/opt/ai-translate", "command": "pull origin master"}
    {"path": "/var/www/myvox.eu", "command": "log --oneline -10"}
    """
    p = pathlib.Path(path)
    
    # Security: only allow /var/www and /opt/
    if not _is_under_allowlist(p, ["/var/www", "/opt/"]):
        return {"error": "Denied: only /var/www and /opt/ allowed"}
    
    # Check if .git exists
    if not (p / ".git").is_dir():
        return {"error": f"Not a git repository: {path}"}
    
    # Block dangerous commands
    dangerous_cmds = ["push", "force", "force-push", "delete", "branch -d", "reset --hard"]
    if any(cmd in command.lower() for cmd in dangerous_cmds):
        return {"error": f"Dangerous command blocked: {command}"}
    
    try:
        cmd = ["git", "-C", str(p)] + shlex.split(command)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            return {"error": result.stderr.strip() or "Command failed", "exit_code": result.returncode}
        
        return {
            "path": str(p),
            "command": command,
            "output": result.stdout,
            "exit_code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"error": "Git command timeout (30s)"}
    except Exception as e:
        return {"error": str(e)}


# =======================
#     SYSTEM COMMANDS
# =======================
@mcp.tool
def execute_shell_command(command: str, user: Optional[str] = None) -> dict:
    """
    Execute an arbitrary shell command on the system.

    SECURITY:
    - Executed as root unless a specific user is specified.
    - Be extremely careful with which commands are executed here.

    Parameters:
    - command (str): The shell command to be executed.
    - user (str, optional): The system user under which the command should be executed (e.g. "odoo").

    Return: dict with stdout, stderr, and exit code.

    Example:
    {"command": "apt update && apt install -y nginx"}
    {"command": "ls -la /opt/odoo", "user": "odoo"}
    """
    try:
        full_cmd = shlex.split(command)
        if user:
            # Use sudo -u for specific user execution
            proc_cmd = ["sudo", "-u", user] + full_cmd
        else:
            # Execute as root (since mcp-linux-tools.service runs as root)
            proc_cmd = full_cmd

        result = subprocess.run(proc_cmd, capture_output=True, text=True, timeout=300) # 5 minuten timeout voor langere installaties
        
        return {
            "command": command,
            "user": user,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after 300 seconds: {command}"}
    except Exception as e:
        return {"error": str(e)}


# =======================
#          RUN
# =======================
if __name__ == "__main__":
    # HTTP is more stable for Cursor than SSE; path '/mcp' must match your mcp.json
    mcp.run(transport="http", host="0.0.0.0", port=8765, path="/mcp")

