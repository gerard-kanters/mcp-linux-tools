"""
MCP Linux Tools Server (refactored entrypoint)
"""

import logging
import pathlib
import signal
import sys
import time

from fastmcp import FastMCP

from config import load_config
from register_tools import register_all_tools


def _build_logger(log_file: str) -> logging.Logger:
    try:
        pathlib.Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.append(logging.FileHandler(log_file))
    except Exception:
        pass

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )
    return logging.getLogger(__name__)


def main() -> None:
    config_path = pathlib.Path(__file__).parent / "config.json"
    try:
        cfg = load_config(config_path)
    except Exception as e:
        print(f"FATAL ERROR loading config: {e}", file=sys.stderr)
        raise

    logger = _build_logger(cfg.log_file)
    mcp = FastMCP(cfg.server_name)
    register_all_tools(mcp, cfg)

    def _signal_handler(sig, _frame):
        logger.info(f"Received signal {sig}, shutting down gracefully...")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    max_retries = 5
    retry_delay = 1

    logger.info(f"Starting {cfg.server_name} ({cfg.server_type}) on {cfg.server_ip}")
    logger.info("MCP server transport: http (streamable) with tolerant reconnect settings")
    logger.info("Server will listen on http://0.0.0.0:8765/mcp")

    for attempt in range(1, max_retries + 1):
        try:
            try:
                mcp.run(
                    transport="http",
                    host="0.0.0.0",
                    port=8765,
                    path="/mcp",
                    stateless_http=True,
                    log_level="info",
                )
            except TypeError as te:
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
                logger.warning(f"Port 8765 already in use, retrying in {retry_delay}s (attempt {attempt}/{max_retries})")
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


if __name__ == "__main__":
    main()
