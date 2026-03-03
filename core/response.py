"""Uniform responsecontract voor MCP tools."""

from config import ServerConfig
from core.errors import DENIED_PATH, DENIED_SERVICE, DENIED_SITE


def _meta(cfg: ServerConfig) -> dict:
    return {
        "server_type": cfg.server_type,
        "server_ip": cfg.server_ip,
        "server_name": cfg.server_name,
    }


def ok(data, cfg: ServerConfig) -> dict:
    """Succes-response: data + meta."""
    return {
        "success": True,
        "data": data,
        "error": None,
        "meta": _meta(cfg),
    }


def err(
    code: str,
    message: str,
    hint: str | None = None,
    cfg: ServerConfig | None = None,
) -> dict:
    """Fout-response: code, message, optioneel hint + meta."""
    meta = _meta(cfg) if cfg else {}
    return {
        "success": False,
        "data": None,
        "error": {"code": code, "message": message, "hint": hint},
        "meta": meta,
    }


def err_denied_path(path: str, allowed: list[str], cfg: ServerConfig) -> dict:
    """Pad buiten allowlist."""
    allowed_str = ", ".join(allowed)
    return err(
        DENIED_PATH,
        f"Path not in allowed directories: {path}",
        hint=f"Use a path under: {allowed_str}",
        cfg=cfg,
    )


def err_denied_service(name: str, cfg: ServerConfig) -> dict:
    """Service niet in whitelist."""
    return err(
        DENIED_SERVICE,
        f"Service '{name}' not in whitelist",
        hint="Check get_service_whitelist() for allowed services",
        cfg=cfg,
    )


def err_denied_site(site_path: str, cfg: ServerConfig) -> dict:
    """WordPress site niet toegestaan."""
    return err(
        DENIED_SITE,
        f"Site path not allowed: {site_path}",
        hint="Check get_wp_allowed_sites() for allowed paths",
        cfg=cfg,
    )
