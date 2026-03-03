from config import ServerConfig
from tools.cron_tools import register_cron_tools
from tools.discovery import register_discovery_tools
from tools.filesystem import register_filesystem_tools
from tools.logs import register_log_tools
from tools.ops import register_ops_tools
from tools.python_exec import register_python_exec_tools
from tools.systemd import register_systemd_tools
from tools.wordpress import register_wordpress_tools


def register_all_tools(mcp, cfg: ServerConfig) -> None:
    register_discovery_tools(mcp, cfg)
    register_filesystem_tools(mcp, cfg)
    register_log_tools(mcp, cfg)
    register_systemd_tools(mcp, cfg)
    register_python_exec_tools(mcp, cfg)
    register_wordpress_tools(mcp, cfg)
    register_cron_tools(mcp, cfg)
    register_ops_tools(mcp, cfg)
