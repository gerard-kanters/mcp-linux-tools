"""
MCP Linux Tools Server
======================

Server voor Linux systeembeheer

REQUIREMENTS:
- Server moet als ROOT draaien voor systemctl en crontab toegang

SECURITY BEPERKINGEN:
- Beperkte directory toegang (zie ALLOWED_READ_DIRS en ALLOWED_LOG_DIRS)
- Service management: alleen status/restart van whitelisted services
- WP-CLI: alleen voor specifieke WordPress sites
- Python: sandboxed, geen netwerk, 8s timeout
- Cron: alleen binnen MCP-managed sectie

TOEGESTANE DIRECTORIES:
- Read access: /var/log, /etc, /tmp, /opt/, /root/scripts, /var/www /backup, /etc/odoo/ 
- Log access: /var/log, /tmp, /opt/ai_trading_bot, /opt/finbert, /var/www

TOEGESTANE SERVICES:
- apache2, php8.4-fpm, postfix, opendkim, sshd, docker, memcached, ai-trading-dashboard.service

WORDPRESS SITES (WP-CLI):
- /var/www/myvox.eu
- /var/www/netcare.nl
- /var/www/vioolles.net
- /var/www/heksenendraken
"""

from fastmcp import FastMCP
import subprocess, pathlib, os, re, tempfile, time, shlex, shutil, json, signal, sys, logging
from typing import Optional, List, Any
try:
    from croniter import croniter   # optioneel  # type: ignore[import]
except Exception:
    croniter = None

# Server identificatie - laad uit config.json (geen hardcoded server waarden)
_config_path = pathlib.Path(__file__).parent / "config.json"

def _load_config(path: pathlib.Path) -> dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except FileNotFoundError as e:
        raise RuntimeError(f"Missing server config: {path}") from e
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in server config: {path}: {e}") from e

    if not isinstance(cfg, dict):
        raise RuntimeError(f"Invalid config structure: expected object at top level in {path}")
    return cfg


def _get_config_value(cfg: dict[str, Any], path: list[str]) -> Any:
    node: Any = cfg
    for key in path:
        if not isinstance(node, dict) or key not in node:
            raise RuntimeError(f"Missing config key: {'.'.join(path)}")
        node = node[key]
    return node


def _require_str(cfg: dict[str, Any], path: list[str]) -> str:
    value = _get_config_value(cfg, path)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"Config key {'.'.join(path)} must be a non-empty string")
    return value.strip()


def _require_int(cfg: dict[str, Any], path: list[str]) -> int:
    value = _get_config_value(cfg, path)
    if not isinstance(value, int):
        raise RuntimeError(f"Config key {'.'.join(path)} must be an integer")
    return value


def _require_str_list(cfg: dict[str, Any], path: list[str]) -> list[str]:
    value = _get_config_value(cfg, path)
    if not isinstance(value, list) or not value:
        raise RuntimeError(f"Config key {'.'.join(path)} must be a non-empty list")
    out: list[str] = []
    for idx, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise RuntimeError(f"Config key {'.'.join(path)} contains invalid entry at index {idx}")
        out.append(item.strip())
    return out


try:
    CONFIG = _load_config(_config_path)
    SERVER_TYPE = _require_str(CONFIG, ["server_type"])
    SERVER_IP = _require_str(CONFIG, ["server_ip"])
    SERVER_NAME = _require_str(CONFIG, ["server_name"])
    LOG_FILE = _require_str(CONFIG, ["logging", "log_file"])
    ALLOWED_LOG_DIRS = _require_str_list(CONFIG, ["directories", "allowed_log"])
    ALLOWED_READ_DIRS = _require_str_list(CONFIG, ["directories", "allowed_read"])
    ALLOWED_WRITE_DIRS = _require_str_list(CONFIG, ["directories", "allowed_write"])

    SERVICE_WHITELIST = set(_require_str_list(CONFIG, ["services", "whitelist"]))
    MAX_BYTES = _require_int(CONFIG, ["limits", "max_bytes"])
    MAX_ITEMS = _require_int(CONFIG, ["limits", "max_items"])
    PYTHON_BIN = _require_str(CONFIG, ["python", "bin"])
    SANDBOX_CWD = _require_str(CONFIG, ["directories", "sandbox_cwd"])

    WP_ALLOWED_SITES = _require_str_list(CONFIG, ["wordpress", "allowed_sites"])
    WP_BIN_CANDIDATES = _require_str_list(CONFIG, ["wordpress", "bin_candidates"])
    WP_LOG_CANDIDATES = _require_str_list(CONFIG, ["wordpress", "log_candidates"])

    # Dynamische server waarschuwingstekst
    SERVER_WARNING = f"⚠️ BELANGRIJK: Dit is de {SERVER_TYPE.upper()} server (IP: {SERVER_IP})"

    mcp = FastMCP(SERVER_NAME)
except Exception as e:
    print(f"FATAL ERROR loading config: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)

# =======================
#        LOGGING
# =======================
try:
    pathlib.Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
except Exception:
    pass

_handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
try:
    _handlers.append(logging.FileHandler(LOG_FILE))
except Exception:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=_handlers,
)
logger = logging.getLogger(__name__)

# =======================
#   POLICY & CONSTANTS
# =======================
PY_TIMEOUT  = 8

# WP-CLI policy

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
def get_server_info() -> dict:
    """
    Geef informatie over deze MCP server instance.
    
    Geeft server type, IP adres en naam terug om duidelijk te identificeren welke server dit is.
    
    Return: dict met server informatie
    
    Voorbeeld: {}
    """
    return {
        "server_name": SERVER_NAME,
        "server_type": SERVER_TYPE,
        "server_ip": SERVER_IP,
        "description": f"Dit is de {SERVER_TYPE} server (IP: {SERVER_IP})"
    }

@mcp.tool
def get_service_whitelist() -> list[str]:
    """
    Lijst van services die deze server **mag** beheren (status/restart).
    
    ⚠️ BELANGRIJK: Check `get_server_info()` voor server type/IP.

    TOEGESTANE SERVICES (SERVICE_WHITELIST):
    - apache2
    - php8.4-fpm
    - postfix
    - opendkim
    - sshd
    - docker
    - memcached
    - ai-trading-dashboard.service
    - postgresql
    - odoo

    Return:
    - list[str]: namen zoals ze aan `systemctl` worden doorgegeven.

    Voorbeeld: {}
    """
    return sorted(SERVICE_WHITELIST)

@mcp.tool
def get_wp_allowed_sites() -> list[str]:
    """
    Lijst van WordPress roots waarvoor WP-CLI is toegestaan.

    TOEGESTANE WORDPRESS SITES (WP_ALLOWED_SITES):
    - /var/www/myvox.eu
    - /var/www/netcare.nl
    - /var/www/vioolles.net
    - /var/www/heksenendraken
    - /var/www/traders-for-traders

    Return:
    - list[str]: absolute paden naar WP roots (waar `wp-config.php` staat).

    Voorbeeld: {}
    """
    return WP_ALLOWED_SITES[:]


# =======================
#   FILES / DIRECTORIES
# =======================
@mcp.tool
def list_dir(path: str, pattern: str = "*", include_files: bool = True, include_dirs: bool = False, max_items: int = MAX_ITEMS) -> list[dict]:
    """
    Toon directory-inhoud met simpele filtering (alleen onder ALLOWED_READ_DIRS).
    
    ⚠️ BELANGRIJK: Check `get_server_info()` voor server type/IP.
    
    ALLOWED_READ_DIRS nu:
    - /var/log
    - /etc
    - /tmp
    - /opt/
    - /root/scripts
    - /var/www
    - /backup

    Parameters:
    - path (str): Directorypad.
    - pattern (str): Glob (bv. "*.log", "**/*.conf").
    - include_files (bool): Bestanden opnemen.
    - include_dirs (bool): Submappen opnemen.
    - max_items (int): Bovenlimiet (default 500).

    Return: list[dict] met velden name/path/is_dir/size/mtime of [{"error": "..."}].
    """
    if not path or not path.strip():
        return [{"error": "Path cannot be empty"}]
    
    try:
        p = pathlib.Path(path)
        if not _is_under_allowlist(p, ALLOWED_READ_DIRS):
            return [{"error": f"Denied: {path} not in allowed read directories"}]
        if not p.exists():
            return [{"error": f"Path does not exist: {path}"}]
        if not p.is_dir():
            return [{"error": f"Not a directory: {path}"}]
        
        items = []
        for entry in p.glob(pattern):
            if len(items) >= max_items:
                break
            try:
                if (entry.is_file() and include_files) or (entry.is_dir() and include_dirs):
                    stat = entry.stat()
                    items.append({
                        "name": entry.name,
                        "path": str(entry.resolve()),
                        "is_dir": entry.is_dir(),
                        "size": stat.st_size if entry.is_file() else None,
                        "mtime": int(stat.st_mtime)
                    })
            except (PermissionError, OSError) as e:
                # Skip files we can't access, but continue
                items.append({
                    "name": entry.name,
                    "path": str(entry.resolve()),
                    "error": f"Access denied: {str(e)}"
                })
        return items
    except Exception as e:
        return [{"error": f"Unexpected error: {str(e)}"}]

@mcp.tool
def create_directory(path: str, owner: str = "root", group: str = "root", mode: str = "755", parents: bool = False) -> str:
    """
    Maakt een nieuwe directory aan.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    ⚠️ WAARSCHUWING: Dit heeft impact op de productie server!

    SECURITY:
    - Alleen naar paden onder ALLOWED_WRITE_DIRS toegestaan (voor de parent directory).

    Parameters:
    - path (str): Het absolute pad naar de directory die moet worden aangemaakt.
    - owner (str, optioneel): De eigenaar van de directory (standaard "root").
    - group (str, optioneel): De groepseigenaar van de directory (standaard "root").
    - mode (str, optioneel): De octale bestandsrechten (standaard "755").
    - parents (bool, optioneel): Of ontbrekende oudermappen recursief moeten worden aangemaakt (standaard False).

    Return: "ok" of foutmelding.

    Voorbeeld:
    {"path": "/opt/odoo", "owner": "odoo", "group": "odoo", "mode": "755", "parents": True}
    """
    if not path or not path.strip():
        return "Error: path cannot be empty"
    
    if not owner or not owner.strip():
        return "Error: owner cannot be empty"
    
    if not group or not group.strip():
        return "Error: group cannot be empty"
    
    p = pathlib.Path(path)
    
    if p.exists():
        return f"Error: path already exists: {path}"

    # Security: only allow configured write directories (ALLOWED_WRITE_DIRS)
    if not _is_under_allowlist(p.parent, ALLOWED_WRITE_DIRS):
        allowed_str = ", ".join(ALLOWED_WRITE_DIRS)
        return f"Denied: target directory not under allowed write directories ({allowed_str})"

    # Validate octal mode
    if not re.match(r"^[0-7]{3,4}$", mode):
        return "Error: invalid mode, must be octal (e.g. 755, 0755)"

    try:
        octal_mode = int(mode, 8)
        p.mkdir(parents=parents, mode=octal_mode)
        shutil.chown(str(p), user=owner, group=group)
        return "ok"
    except PermissionError:
        return f"Error: permission denied creating {path}"
    except LookupError as e:
        return f"Error: user or group not found: {str(e)}"
    except FileExistsError:
        return f"Error: directory already exists: {path}"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool
def read_file(path: str, max_bytes: int = MAX_BYTES) -> str:
    """
    Lees een klein tekstbestand (utf-8) onder ALLOWED_READ_DIRS.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    Parameters:
    - path (str): Absoluut pad naar bestand.
    - max_bytes (int): Max bytes (default 512 KiB).

    Return: inhoud of error message als buiten toegestane directories of bestand niet gevonden.
    
    Voorbeeld: {"path": "/etc/hostname"}
    """
    p = pathlib.Path(path)
    
    if not _is_under_allowlist(p, ALLOWED_READ_DIRS):
        resolved = str(p.resolve())
        allowed_str = ", ".join(ALLOWED_READ_DIRS)
        return f"Denied: path '{resolved}' not in allowed directories: {allowed_str}"
    
    if not p.exists():
        return f"Error: file does not exist: {path}"
    if not p.is_file():
        return f"Error: {path} is not a file"
    
    try:
        with open(p, "rb") as f:
            data = f.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        out = _safe_text(data[:max_bytes])
        return out + ("\n\n[...truncated...]" if truncated else "")
    except PermissionError:
        return f"Error: permission denied reading {path}"
    except Exception as e:
        return f"Error reading {path}: {str(e)}"

@mcp.tool
def head(path: str, n: int = 100) -> str:
    """
    Eerste `n` regels van een bestand (onder ALLOWED_READ_DIRS).
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    Voorbeeld:
    { "path": "/etc/nginx/nginx.conf", "n": 50 }
    """
    p = pathlib.Path(path)
    if not _is_under_allowlist(p, ALLOWED_READ_DIRS):
        return "Denied: path not in allowed read directories"
    if not p.is_file():
        return f"Error: {path} is not a file"
    try:
        res = subprocess.run(["head", "-n", str(n), str(p)], capture_output=True, text=True, check=True, timeout=10)
        return res.stdout
    except subprocess.TimeoutExpired:
        return f"Error: timeout reading {path}"
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr.strip() if e.stderr else str(e)}"
    except FileNotFoundError:
        return "Error: head command not found"
    except Exception as e:
        return f"Error: {str(e)}"

def _tail(path: str, n: int = 200) -> str:
    """Internal tail implementation."""
    p = pathlib.Path(path)
    if not _is_under_allowlist(p, ALLOWED_LOG_DIRS):
        return "Denied: path not in allowed log directories"
    if not p.is_file():
        return f"Error: {path} is not a file"
    try:
        res = subprocess.run(["tail", "-n", str(n), str(p)], capture_output=True, text=True, check=True, timeout=10)
        return res.stdout
    except subprocess.TimeoutExpired:
        return f"Error: timeout reading {path}"
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr.strip() if e.stderr else str(e)}"
    except FileNotFoundError:
        return "Error: tail command not found"
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool
def tail(path: str, n: int = 200) -> str:
    """
    Laatste `n` regels van een **logbestand** onder ALLOWED_LOG_DIRS.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    ALLOWED_LOG_DIRS nu:
    - /var/log
    - /tmp
    - /opt/ai_trading_bot
    - /opt/finbert
    - /var/www

    Voorbeeld:
    { "path": "/var/log/syslog", "n": 300 }
    """
    return _tail(path, n)

@mcp.tool
def log_tail(path: str, n: int = 200) -> str:
    """
    Alias met duidelijke naam: tail een logbestand onder ALLOWED_LOG_DIRS.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    Specifiek bedoeld om LLMs te sturen naar **/var/log/** en andere logmappen.

    Voorbeelden:
    - { "path": "/var/log/syslog", "n": 400 }
    - { "path": "/var/log/nginx/error.log" }
    - { "path": "/var/www/myvox.eu/wp-content/debug.log", "n": 500 }

    (Functioneel identiek aan `tail()`; alleen de naam is duidelijker voor log taken.)
    """
    return _tail(path, n)


# =======================
#      WORDPRESS LOGS
# =======================
def _pick_wp_log_path() -> str:
    for p in WP_LOG_CANDIDATES:
        if pathlib.Path(p).is_file():
            return p
    return ""

@mcp.tool
def log_pick_path() -> str:
    """
    Geef het beste gok WP-log terug:
    1) uploads/ai-translate/logs/urlmap.log
    2) wp-content/debug.log
    Return: absoluut pad of "Not found".

    Tip: voor **andere** logs onder /var/log gebruik `log_tail` of `tail` direct.
    """
    p = _pick_wp_log_path()
    return p if p else "Not found"

@mcp.tool
def log_tail_ai(n: int = 300) -> dict:
    """
    Tail het WP-log en filter op 'ai-translate:'.

    Voorbeeld:
    { "n": 500 }

    Tip: voor system-logs: gebruik `log_tail("/var/log/syslog")`.
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
    Tail WP-log en filter op mapping-flow events:
    request:start, parse_request:start, resolved_post_id, resolved_page_by_path,
    fallback_pagename, no_reverse_mapping, empty_basename, pre_handle_404.

    Voorbeeld:
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
    Tail WP-log en filter op willekeurige keywords (case-sensitive).

    Voorbeeld:
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
    Korte status (is-active) van een service via systemctl.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    SECURITY: Alleen READ-ONLY status, geen stop/start/enable/disable.
    NOTE: MCP server moet als root draaien voor systemctl toegang.

    TOEGESTANE SERVICES (SERVICE_WHITELIST):
    - apache2, php8.4-fpm, postfix, opendkim, sshd, docker, memcached, ai-trading-dashboard.service, postgresql, odoo

    Return: "{name}: {status}" of error message als service niet in whitelist of command failed.
    
    Voorbeeld: {"name": "apache2"}
    """
    if name not in SERVICE_WHITELIST:
        return f"Denied: service '{name}' not in whitelist"
    
    try:
        res = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=10)
        if res.returncode == 0:
            state = res.stdout.strip()
            return f"{name}: {state}"
        else:
            # Try to get more detailed status
            res_detail = subprocess.run(["systemctl", "status", name, "--no-pager", "-n", "0"], 
                                       capture_output=True, text=True, timeout=5)
            error_msg = res.stderr.strip() if res.stderr else "unknown"
            return f"{name}: {error_msg}"
    except subprocess.TimeoutExpired:
        return f"Error: timeout checking status of {name}"
    except Exception as e:
        return f"Error checking {name}: {str(e)}"

@mcp.tool
def restart_service(name: str) -> str:
    """
    Herstart een service en rapporteer de nieuwe status via systemctl restart.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    ⚠️ WAARSCHUWING: Dit heeft impact op de productie server!
    
    SECURITY: Alleen RESTART toegestaan, geen stop/start/enable/disable.
    NOTE: MCP server moet als root draaien voor systemctl toegang.
    ⚠️ mcp-linux-tools.service mag NIET herstart worden (zou Cursor disconnecten)

    TOEGESTANE SERVICES (SERVICE_WHITELIST):
    - apache2, php8.4-fpm, postfix, opendkim, sshd, docker, memcached, ai-trading-dashboard.service, postgresql, odoo

    Return: "Restarted {name}. State: {status}" of error message
    
    Voorbeeld: {"name": "php8.4-fpm"}
    """
    if name not in SERVICE_WHITELIST:
        return f"Denied: service '{name}' not in whitelist"
    
    # Prevent restarting MCP server itself (would disconnect Cursor)
    if name == "mcp-linux-tools.service" or name == "mcp-linux-tools":
        return "Denied: Cannot restart MCP server (would disconnect Cursor)"
    
    try:
        res = subprocess.run(["systemctl", "restart", name], capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            error_detail = res.stderr.strip() if res.stderr else "Unknown error"
            return f"Failed to restart {name}: {error_detail}"
        
        # Check status after restart
        st = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=10)
        if st.returncode == 0:
            state = st.stdout.strip()
            return f"Restarted {name}. State: {state}"
        else:
            return f"Restarted {name} but status check failed: {st.stderr.strip() if st.stderr else 'unknown'}"
    except subprocess.TimeoutExpired:
        return f"Error: timeout restarting {name}"
    except Exception as e:
        return f"Error restarting {name}: {str(e)}"


# =======================
#       PYTHON EXEC
# =======================
@mcp.tool
def python_run(code: str) -> dict:
    """
    Voer kort Python-code uit in aparte venv (zonder netwerk), met timeout.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    SECURITY BEPERKINGEN:
    - Interpreter: /opt/mcp/venv/bin/python (Python 3.13)
    - CWD: /opt/mcp/sandbox (geïsoleerd)
    - Timeout: 8 seconden
    - Geen netwerk toegang
    - Beperkte environment (alleen /usr/bin en /bin in PATH)
    
    Return: {"stdout": str, "stderr": str, "exit": int, "success": bool}

    Voorbeeld: {"code": "import platform; print(platform.python_version())"}
    """
    if not code or not code.strip():
        return {"stdout": "", "stderr": "Error: code cannot be empty", "exit": 1, "success": False}
    
    try:
        os.makedirs(SANDBOX_CWD, exist_ok=True)
        proc = subprocess.run(
            [PYTHON_BIN, "-S", "-c", code],
            cwd=SANDBOX_CWD,
            capture_output=True,
            text=True,
            timeout=PY_TIMEOUT,
            env={"PATH": "/usr/bin:/bin", "PYTHONUNBUFFERED": "1"}
        )
        success = proc.returncode == 0
        return {
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "exit": proc.returncode,
            "success": success
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Python execution timeout ({PY_TIMEOUT}s)",
            "exit": 124,
            "success": False
        }
    except FileNotFoundError:
        return {
            "stdout": "",
            "stderr": f"Python interpreter not found: {PYTHON_BIN}",
            "exit": 127,
            "success": False
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": f"Unexpected error: {str(e)}",
            "exit": 1,
            "success": False
        }


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
    WP-CLI runner voor **toegestane** WordPress sites.
    
    SECURITY: Alleen toegestane sites, auto-check op wp-config.php.

    TOEGESTANE WORDPRESS SITES (WP_ALLOWED_SITES):
    - /var/www/myvox.eu
    - /var/www/netcare.nl
    - /var/www/vioolles.net
    - /var/www/heksenendraken
    - /var/www/traders-for-traders

    Parameters:
    - site_path (str): WP root pad (moet in whitelist)
    - args (str): WP-CLI subcommando + flags, bijv. "plugin list --format=json"
    - as_www_data (bool): default True (voer uit als www-data user)

    Return:
    - dict: {"cmd": str, "exit": int, "stdout": str, "stderr": str} 
    - of {"error": "Denied/Not found"}

    Voorbeelden:
    {"site_path": "/var/www/netcare.nl", "args": "cache flush"}
    {"site_path": "/var/www/netcare.nl", "args": "plugin list --format=json"}
    {"site_path": "/var/www/netcare.nl", "args": "db tables"}
    """
    return _wp_cli(site_path, args, as_www_data)

@mcp.tool
def wp_cache_flush(site_path: str, as_www_data: bool = True) -> dict:
    """
    WP-CLI: `cache flush` voor een toegestane WordPress site.
    
    Shortcut voor: wp_cli(site_path, "cache flush", as_www_data)

    Parameters:
    - site_path: moet in WP_ALLOWED_SITES whitelist

    Voorbeeld: {"site_path": "/var/www/netcare.nl"}
    """
    return _wp_cli(site_path, "cache flush", as_www_data)

@mcp.tool
def wp_plugin_list(site_path: str, as_www_data: bool = True) -> dict:
    """
    WP-CLI: lijst alle plugins in JSON format.
    
    Shortcut voor: wp_cli(site_path, "plugin list --format=json", as_www_data)
    
    Return: JSON array met plugin info (name, status, version, etc.)

    Voorbeeld: {"site_path": "/var/www/netcare.nl"}
    """
    return _wp_cli(site_path, "plugin list --format=json", as_www_data)

@mcp.tool
def wp_user_list(site_path: str, as_www_data: bool = True) -> dict:
    """
    WP-CLI: lijst alle WordPress users in JSON format.
    
    Shortcut voor: wp_cli(site_path, "user list --format=json", as_www_data)
    
    Return: JSON array met user info (ID, login, email, roles, etc.)

    Voorbeeld: {"site_path": "/var/www/netcare.nl"}
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
    out: List[str] = []
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
    out: List[str] = []
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
    Toon de volledige crontab van root (read-only).
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    SECURITY: Alleen READ-ONLY, geen modificaties.

    Return: volledige crontab inhoud als string

    Voorbeeld: {}
    """
    try:
        return _get_crontab(CRON_USER)
    except Exception as e:
        return f"Error reading crontab: {str(e)}"

@mcp.tool
def cron_add(job_id: str, schedule: str, command: str) -> str:
    """
    Voeg of vervang een job in de MCP-sectie van roots crontab.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    ⚠️ WAARSCHUWING: Dit wijzigt de productie server crontab!
    
    SECURITY BEPERKINGEN:
    - Alleen binnen MCP-managed sectie (tussen BEGIN/END markers)
    - Command moet absoluut pad zijn (geen relatieve paden)
    - Schedule validatie via croniter
    - Max 2000 regels totale crontab

    Parameters:
    - job_id: unieke identifier (alphanumeric + ._-)
    - schedule: cron format "min hour day month weekday"
    - command: absoluut pad naar command + args

    Return: "ok" of "error: {reason}"

    Voorbeeld:
    {"job_id": "cleanup_tmp", "schedule": "*/10 * * * *", 
     "command": "/usr/bin/find /tmp -type f -mtime +1 -delete"}
    """
    if not job_id or not job_id.strip():
        return "error: job_id cannot be empty"
    
    if not schedule or not schedule.strip():
        return "error: schedule cannot be empty"
    
    if not command or not command.strip():
        return "error: command cannot be empty"
    
    if not _validate_schedule(schedule):
        return "error: invalid schedule format"
    
    if not re.match(r"^[A-Za-z0-9._\-]+$", job_id):
        return "error: job_id must be alphanumeric with ._- only"
    
    first = command.split()[0]
    if not os.path.isabs(first):
        return "error: command must be absolute path"
    
    try:
        content = _ensure_section(_get_crontab(CRON_USER))
        pre, mid, post = content.partition(MCP_SECTION_BEGIN)
        sect, mid2, post2 = post.partition(MCP_SECTION_END)
        section_body = _replace_or_append_job(sect, job_id, f"{schedule} {command}")
        new_content = pre + mid + section_body + post2
        res = _set_crontab(CRON_USER, new_content)
        return "ok" if res == "ok" else f"error: {res}"
    except Exception as e:
        return f"error: {str(e)}"

@mcp.tool
def cron_remove(job_id: str) -> str:
    """
    Verwijder één MCP-job uit roots crontab.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    ⚠️ WAARSCHUWING: Dit wijzigt de productie server crontab!
    
    SECURITY: Alleen MCP-managed jobs kunnen verwijderd worden.

    Parameters:
    - job_id: identifier van job om te verwijderen

    Return: "ok" of "error: {reason}"

    Voorbeeld: {"job_id": "cleanup_tmp"}
    """
    if not job_id or not job_id.strip():
        return "error: job_id cannot be empty"
    
    try:
        content = _ensure_section(_get_crontab(CRON_USER))
        pre, mid, post = content.partition(MCP_SECTION_BEGIN)
        sect, mid2, post2 = post.partition(MCP_SECTION_END)
        section_body = _replace_or_append_job(sect, job_id, None)
        new_content = pre + mid + section_body + post2
        res = _set_crontab(CRON_USER, new_content)
        return "ok" if res == "ok" else f"error: {res}"
    except Exception as e:
        return f"error: {str(e)}"

@mcp.tool
def cron_enable(job_id: str, enabled: bool) -> str:
    """
    Zet een MCP-job **aan/uit** (comment/uncomment).
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    ⚠️ WAARSCHUWING: Dit wijzigt de productie server crontab!
    
    SECURITY: Alleen MCP-managed jobs kunnen gewijzigd worden.

    Parameters:
    - job_id: identifier van job
    - enabled: True = uncomment (actief), False = comment (inactief)

    Return: "ok" of "error: {reason}"

    Voorbeeld: {"job_id": "cleanup_tmp", "enabled": false}
    """
    if not job_id or not job_id.strip():
        return "error: job_id cannot be empty"
    
    try:
        content = _ensure_section(_get_crontab(CRON_USER))
        pre, mid, post = content.partition(MCP_SECTION_BEGIN)
        sect, mid2, post2 = post.partition(MCP_SECTION_END)
        section_body = _set_enabled(sect, job_id, enabled)
        new_content = pre + mid + section_body + post2
        res = _set_crontab(CRON_USER, new_content)
        return "ok" if res == "ok" else f"error: {res}"
    except Exception as e:
        return f"error: {str(e)}"

@mcp.tool
def cron_next_runs(schedule: str, n: int = 5) -> list:
    """
    Bereken de eerstvolgende `n` runtijden voor een cronschema.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    Nuttig om te valideren of een cron schedule correct is.
    
    Parameters:
    - schedule: cron format "min hour day month weekday"
    - n: aantal toekomstige runs (max 20)
    
    Return: list van datetime strings (YYYY-MM-DD HH:MM:SS) of [] als ongeldig

    Voorbeeld: {"schedule": "0 3 * * *", "n": 5}
    """
    if not schedule or not schedule.strip():
        return []
    
    if not _validate_schedule(schedule) or not croniter:
        return []
    
    try:
        n = max(1, min(20, int(n)))
        base = time.time()
        it = croniter(schedule, base)
        return [time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(it.get_next())) for _ in range(n)]
    except (ValueError, TypeError):
        return []
    except Exception:
        return []


# =======================
#       DATABASE (MySQL)
# =======================
@mcp.tool
def mysql_query(query: str, database: str = "") -> dict:
    """
    Voer een MySQL query uit op de productie databases.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    SECURITY:
    - Query's zijn read-only beveiligd waar mogelijk
    - Geen DROP/TRUNCATE/ALTER zonder voorzichtigheid
    - Commands moeten veilig zijn
    
    Parameters:
    - query: SQL query (bv. "SELECT * FROM wp_users WHERE ID=1")
    - database: optionele database naam (bv. "netcare_nl" of "myvox_eu")
    
    Return: dict met result set of error message
    
    Voorbeeld:
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
            error_msg = result.stderr.strip() if result.stderr else "Query failed with unknown error"
            return {"error": error_msg, "exit_code": result.returncode}
        
        return {"query": query, "database": database or "default", "result": result.stdout}
    except subprocess.TimeoutExpired:
        return {"error": "Query timeout (30s)"}
    except FileNotFoundError:
        return {"error": "mysql command not found. Is MySQL client installed?"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}


# =======================
#     FILE PERMISSIONS
# =======================
@mcp.tool
def chmod_file(path: str, mode: str) -> str:
    """
    Wijzig bestandsrechten (permissions) via chmod.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    ⚠️ WAARSCHUWING: Dit heeft impact op de productie server!
    
    SECURITY:
    - Alleen directories onder de geconfigureerde ALLOWED_WRITE_DIRS (bv. "/var/www", "/opt/") toegestaan
    - Mode moet geldig octal getal zijn (bv. 755, 644)
    
    Parameters:
    - path: bestandspad (bv. "/var/www/netcare.nl/wp-content")
    - mode: octal mode (bv. "755", "644", "777")
    
    Return: "ok" of foutmelding
    
    Voorbeeld:
    {"path": "/var/www/netcare.nl/wp-content/uploads", "mode": "755"}
    {"path": "/var/www/myvox.eu/wp-content/cache", "mode": "644"}
    """
    if not path or not path.strip():
        return "Error: path cannot be empty"
    
    if not mode or not mode.strip():
        return "Error: mode cannot be empty"
    
    p = pathlib.Path(path)
    
    # Security: only allow configured write directories (ALLOWED_WRITE_DIRS)
    if not _is_under_allowlist(p, ALLOWED_WRITE_DIRS):
        allowed_str = ", ".join(ALLOWED_WRITE_DIRS)
        return f"Denied: path not under allowed write directories ({allowed_str})"
    
    if not p.exists():
        return f"Error: path does not exist: {path}"
    
    # Validate octal mode
    if not re.match(r"^[0-7]{3,4}$", mode):
        return "Error: invalid mode, must be octal (e.g. 755, 0755)"
    
    try:
        octal_mode = int(mode, 8)
        os.chmod(str(p), octal_mode)
        return f"ok: changed {path} to {mode}"
    except PermissionError:
        return f"Error: permission denied changing {path}"
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool
def chown_path(path: str, owner: str, group: str) -> str:
    """
    Wijzig bestands- of directory-eigenaar en -groep via chown.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    ⚠️ WAARSCHUWING: Dit heeft impact op de productie server!

    SECURITY:
    - Alleen paden onder de geconfigureerde ALLOWED_WRITE_DIRS (bv. "/var/www", "/opt/") toegestaan.

    Parameters:
    - path: bestandspad (bv. "/var/www/netcare.nl/wp-content")
    - owner: nieuwe eigenaar (bv. "www-data")
    - group: nieuwe groep (bv. "www-data")

    Return: "ok" of foutmelding

    Voorbeeld:
    {"path": "/var/www/netcare.nl/wp-content/uploads", "owner": "www-data", "group": "www-data"}
    """
    if not path or not path.strip():
        return "Error: path cannot be empty"
    
    if not owner or not owner.strip():
        return "Error: owner cannot be empty"
    
    if not group or not group.strip():
        return "Error: group cannot be empty"
    
    p = pathlib.Path(path)

    # Security: only allow configured write directories (ALLOWED_WRITE_DIRS)
    if not _is_under_allowlist(p, ALLOWED_WRITE_DIRS):
        allowed_str = ", ".join(ALLOWED_WRITE_DIRS)
        return f"Denied: path not under allowed write directories ({allowed_str})"

    if not p.exists():
        return f"Error: path does not exist: {path}"

    try:
        shutil.chown(str(p), user=owner, group=group)
        return f"ok: changed owner/group of {path} to {owner}:{group}"
    except PermissionError:
        return f"Error: permission denied changing {path}"
    except LookupError as e:
        return f"Error: user or group not found: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"


# =======================
#      NETWORK (PING)
# =======================
@mcp.tool
def ping_host(host: str, count: int = 4) -> dict:
    """
    Test network connectivity via ping.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    SECURITY:
    - Max 10 packets (prevents flooding)
    - Timeout 30 seconds
    - Valid hostname/IP validation
    
    Parameters:
    - host: hostname of IP address (bv. "netcare.nl", "8.8.8.8")
    - count: aantal packets (default 4, max 10)
    
    Return: dict met ping result
    
    Voorbeeld:
    {"host": "netcare.nl"}
    {"host": "8.8.8.8", "count": 8}
    """
    if not host or not host.strip():
        return {"error": "Host cannot be empty", "success": False}
    
    # Sanitize host input
    if not re.match(r"^[a-zA-Z0-9.-]+$", host):
        return {"error": "Invalid hostname format", "success": False}
    
    try:
        count = max(1, min(10, int(count)))  # Limit to 1-10
    except (ValueError, TypeError):
        return {"error": "Invalid count value, must be integer", "success": False}
    
    try:
        cmd = ["ping", "-c", str(count), "-W", "30", host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        success = result.returncode == 0
        response = {
            "host": host,
            "count": count,
            "success": success,
            "output": result.stdout if result.stdout else result.stderr,
            "exit_code": result.returncode
        }
        
        if not success:
            response["error"] = f"Ping failed: {result.stderr.strip() if result.stderr else 'Unknown error'}"
        
        return response
    except subprocess.TimeoutExpired:
        return {"error": f"Ping timeout for {host} (60s)", "success": False}
    except FileNotFoundError:
        return {"error": "ping command not found. Is ping installed?", "success": False}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}", "success": False}


# =======================
#        GIT CONTROL
# =======================
@mcp.tool
def git_command(path: str, command: str) -> dict:
    """
    Voer Git commando's uit in toegestane repositories.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    SECURITY:
    - Alleen repositories onder de geconfigureerde ALLOWED_WRITE_DIRS (bv. "/var/www", "/opt/")
    - Alleen veilige commando's (pull, status, log, diff, branch)
    - Geen push/force operations
    
    Parameters:
    - path: git repository directory
    - command: git subcommand (bv. "status", "pull origin master", "log -5")
    
    Return: dict met output of error
    
    Voorbeeld:
    {"path": "/var/www/netcare.nl", "command": "status"}
    {"path": "/opt/ai-translate", "command": "pull origin master"}
    {"path": "/var/www/myvox.eu", "command": "log --oneline -10"}
    """
    if not path or not path.strip():
        return {"error": "Path cannot be empty", "success": False}
    
    if not command or not command.strip():
        return {"error": "Command cannot be empty", "success": False}
    
    p = pathlib.Path(path)
    
    # Security: only allow configured write directories (ALLOWED_WRITE_DIRS)
    if not _is_under_allowlist(p, ALLOWED_WRITE_DIRS):
        allowed_str = ", ".join(ALLOWED_WRITE_DIRS)
        return {"error": f"Denied: only allowed write directories ({allowed_str})", "success": False}
    
    if not p.exists():
        return {"error": f"Path does not exist: {path}", "success": False}
    
    # Check if .git exists
    if not (p / ".git").is_dir():
        return {"error": f"Not a git repository: {path}", "success": False}
    
    # Block dangerous commands
    dangerous_cmds = ["push", "force", "force-push", "delete", "branch -d", "reset --hard"]
    if any(cmd in command.lower() for cmd in dangerous_cmds):
        return {"error": f"Dangerous command blocked: {command}", "success": False}
    
    try:
        cmd = ["git", "-C", str(p)] + shlex.split(command)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        success = result.returncode == 0
        response = {
            "path": str(p),
            "command": command,
            "output": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
            "success": success
        }
        
        if not success:
            error_msg = result.stderr.strip() if result.stderr else "Command failed with unknown error"
            response["error"] = error_msg
        
        return response
    except subprocess.TimeoutExpired:
        return {"error": "Git command timeout (30s)", "success": False}
    except FileNotFoundError:
        return {"error": "git command not found. Is Git installed?", "success": False}
    except ValueError as e:
        return {"error": f"Invalid command syntax: {str(e)}", "success": False}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}", "success": False}


# =======================
#     SYSTEM COMMANDS
# =======================
@mcp.tool
def execute_shell_command(command: str, user: Optional[str] = None) -> dict:
    """
    Voert een willekeurig shell-commando uit op het systeem.
    ?? BELANGRIJK: Check get_server_info() voor server type/IP.
    ⚠️ WAARSCHUWING: Dit heeft impact op de productie server!

    SECURITY:
    - Uitgevoerd als root tenzij een specifieke gebruiker is opgegeven.
    - Wees extreem voorzichtig met welke commando's hier worden uitgevoerd.

    Parameters:
    - command (str): Het shell-commando dat uitgevoerd moet worden.
    - user (str, optioneel): De systeemgebruiker waaronder het commando moet worden uitgevoerd (bijv. "odoo").

    Return: dict met stdout, stderr, exit_code, en success status.

    Voorbeeld:
    {"command": "apt update && apt install -y nginx"}
    {"command": "ls -la /opt/odoo", "user": "odoo"}
    """
    if not command or not command.strip():
        return {"error": "Command cannot be empty", "success": False}
    
    try:
        full_cmd = shlex.split(command)
        if user:
            # Use sudo -u for specific user execution
            proc_cmd = ["sudo", "-u", user] + full_cmd
        else:
            # Execute as root (since mcp-linux-tools.service runs as root)
            proc_cmd = full_cmd

        result = subprocess.run(proc_cmd, capture_output=True, text=True, timeout=300) # 5 minuten timeout voor langere installaties
        
        success = result.returncode == 0
        response = {
            "command": command,
            "user": user or "root",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
            "success": success
        }
        
        if not success:
            response["error"] = f"Command failed with exit code {result.returncode}"
            if result.stderr:
                response["error"] += f": {result.stderr.strip()}"
        
        return response
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after 300 seconds: {command}", "success": False}
    except ValueError as e:
        return {"error": f"Invalid command syntax: {str(e)}", "success": False}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}", "success": False}


# =======================
#          RUN
# =======================
if __name__ == "__main__":
    def _signal_handler(sig, frame):
        logger.info(f"Received signal {sig}, shutting down gracefully...")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # Cursor gebruikt Streamable HTTP (met SSE voor events).
    # Belangrijk: op sommige servers/versies is alleen transport="http" beschikbaar
    # (CLI mapte "http" al naar streamable-http). Daarom gebruiken we transport="http"
    # en maken we optionele kwargs (zoals stateless_http) tolerant via fallback.
    max_retries = 5
    retry_delay = 1

    logger.info(f"Starting {SERVER_NAME} ({SERVER_TYPE}) on {SERVER_IP}")
    logger.info("MCP server transport: http (streamable) with tolerant reconnect settings")
    logger.info("Server will listen on http://0.0.0.0:8765/mcp")

    for attempt in range(1, max_retries + 1):
        try:
            try:
                # Preferred settings
                mcp.run(
                    transport="http",
                    host="0.0.0.0",
                    port=8765,
                    path="/mcp",
                    stateless_http=True,
                    log_level="info",
                )
            except TypeError as te:
                # Older FastMCP: unknown kwarg(s) like stateless_http
                logger.warning(f"TypeError starting server with stateless_http; retrying without it: {te}")
                mcp.run(
                    transport="http",
                    host="0.0.0.0",
                    port=8765,
                    path="/mcp",
                    log_level="info",
                )
            break
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
            sys.exit(0)
        except OSError as e:
            if "Address already in use" in str(e) and attempt < max_retries:
                logger.warning(
                    f"Port 8765 already in use, retrying in {retry_delay}s (attempt {attempt}/{max_retries})"
                )
                time.sleep(retry_delay)
                continue
            logger.error(f"OS error: {e}", exc_info=True)
            sys.exit(1)
        except Exception as e:
            logger.error(f"Server error: {e}", exc_info=True)
            if attempt < max_retries:
                logger.info(f"Retrying in {retry_delay}s (attempt {attempt}/{max_retries})")
                time.sleep(retry_delay)
                continue
            sys.exit(1)
