from config import ServerConfig
from core.response import ok


def register_discovery_tools(mcp, cfg: ServerConfig) -> None:
    @mcp.tool
    def get_server_info() -> dict:
        """
        Geef informatie over deze MCP server instance.

        Geeft server type, IP adres en naam terug om duidelijk te identificeren welke server dit is.
        """
        return ok(
            {
                "server_name": cfg.server_name,
                "server_type": cfg.server_type,
                "server_ip": cfg.server_ip,
                "description": f"Dit is de {cfg.server_type} server (IP: {cfg.server_ip})",
            },
            cfg,
        )

    @mcp.tool
    def get_service_whitelist() -> dict:
        """Lijst van services die deze server mag beheren (status/restart)."""
        return ok(sorted(cfg.service_whitelist), cfg)

    @mcp.tool
    def get_wp_allowed_sites() -> dict:
        """Lijst van WordPress roots waarvoor WP-CLI is toegestaan."""
        return ok(cfg.wp_allowed_sites[:], cfg)
