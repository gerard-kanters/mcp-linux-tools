import os
import subprocess

from config import ServerConfig
from core.errors import INVALID_INPUT, INTERNAL_ERROR, TIMEOUT
from core.response import err, ok


PY_TIMEOUT = 8


def register_python_exec_tools(mcp, cfg: ServerConfig) -> None:
    @mcp.tool
    def python_run(code: str) -> dict:
        """
        Voer een kort Python-fragment uit in de geconfigureerde sandboxdirectory.

        `code` is verplichte Python-broncode en wordt met de geconfigureerde
        interpreter als `python -S -c` uitgevoerd. De subprocess krijgt alleen
        een minimale `PATH` en `PYTHONUNBUFFERED`, gebruikt `sandbox_cwd` als
        werkdirectory en wordt na 8 seconden beëindigd. De code kan binnen de
        rechten en isolatie van het MCP-serviceproces side effects veroorzaken.
        Stdout, stderr, exitcode en successtatus worden geretourneerd.
        """
        if not code or not code.strip():
            return err(INVALID_INPUT, "Code cannot be empty", cfg=cfg)
        try:
            os.makedirs(cfg.sandbox_cwd, exist_ok=True)
            proc = subprocess.run(
                [cfg.python_bin, "-S", "-c", code],
                cwd=cfg.sandbox_cwd,
                capture_output=True,
                text=True,
                timeout=PY_TIMEOUT,
                env={"PATH": "/usr/bin:/bin", "PYTHONUNBUFFERED": "1"},
            )
            return ok(
                {
                    "stdout": proc.stdout,
                    "stderr": proc.stderr,
                    "exit": proc.returncode,
                    "success": proc.returncode == 0,
                },
                cfg,
            )
        except subprocess.TimeoutExpired:
            return err(TIMEOUT, f"Python execution timeout ({PY_TIMEOUT}s)", cfg=cfg)
        except FileNotFoundError:
            return err(INTERNAL_ERROR, f"Python interpreter not found: {cfg.python_bin}", cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)
