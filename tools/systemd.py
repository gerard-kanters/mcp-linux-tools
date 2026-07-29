import subprocess

from config import ServerConfig
from core.errors import DENIED_SERVICE, INTERNAL_ERROR, TIMEOUT
from core.response import err, err_denied_service, ok


def register_systemd_tools(mcp, cfg: ServerConfig) -> None:
    def _is_blocked_self_service(name: str) -> bool:
        return name in {"mcp-linux-tools.service", "mcp-linux-tools"}

    def _active_state(name: str) -> str:
        st = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=10)
        if st.returncode == 0:
            return st.stdout.strip()
        return st.stderr.strip() if st.stderr else "unknown"

    def _reload_service(name: str) -> dict:
        if name not in cfg.service_whitelist:
            return err_denied_service(name, cfg)
        if _is_blocked_self_service(name):
            return err(DENIED_SERVICE, "Cannot reload MCP server (would disconnect Cursor)", cfg=cfg)
        try:
            res = subprocess.run(["systemctl", "reload", name], capture_output=True, text=True, timeout=30)
            if res.returncode != 0:
                error_detail = res.stderr.strip() if res.stderr else "Unknown error"
                return err(INTERNAL_ERROR, f"Failed to reload {name}: {error_detail}", cfg=cfg)
            return ok(f"Reloaded {name}. State: {_active_state(name)}", cfg)
        except subprocess.TimeoutExpired:
            return err(TIMEOUT, f"Timeout reloading {name}", cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def service_status(name: str) -> dict:
        """
        Lees de actieve systemd-status van één toegestane service.

        `name` moet exact in `service_whitelist` staan. De tool voert alleen
        `systemctl is-active` uit, wijzigt de service niet en heeft een timeout
        van 10 seconden. Zowel een actieve status als een niet-actieve
        systemd-melding wordt als tekst in de standaardresponse teruggegeven.
        """
        if name not in cfg.service_whitelist:
            return err_denied_service(name, cfg)
        try:
            res = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                state = res.stdout.strip()
                return ok(f"{name}: {state}", cfg)
            error_msg = res.stderr.strip() if res.stderr else "unknown"
            return ok(f"{name}: {error_msg}", cfg)
        except subprocess.TimeoutExpired:
            return err(TIMEOUT, f"Timeout checking status of {name}", cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def reload_service(name: str) -> dict:
        """
        Herlaad een service via `systemctl reload` (voorkeursactie).

        Gebruik bij voorkeur reload in plaats van restart om impact te beperken.
        Alleen als reload niet wordt ondersteund of expliciet nodig is, gebruik `restart_service`.
        """
        return _reload_service(name)

    @mcp.tool
    def restart_service(name: str, force_restart: bool = False) -> dict:
        """
        Service mutate-tool met voorkeur voor reload.

        Standaard doet deze tool eerst een reload (lage impact). Alleen met
        `force_restart=True` wordt een echte restart uitgevoerd.
        """
        if not force_restart:
            return _reload_service(name)

        if name not in cfg.service_whitelist:
            return err_denied_service(name, cfg)
        if _is_blocked_self_service(name):
            return err(DENIED_SERVICE, "Cannot restart MCP server (would disconnect Cursor)", cfg=cfg)
        try:
            res = subprocess.run(["systemctl", "restart", name], capture_output=True, text=True, timeout=30)
            if res.returncode != 0:
                error_detail = res.stderr.strip() if res.stderr else "Unknown error"
                return err(INTERNAL_ERROR, f"Failed to restart {name}: {error_detail}", cfg=cfg)
            return ok(f"Restarted {name}. State: {_active_state(name)}", cfg)
        except subprocess.TimeoutExpired:
            return err(TIMEOUT, f"Timeout restarting {name}", cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)
