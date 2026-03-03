import pathlib
import re
import shlex
import shutil
import subprocess

from config import ServerConfig
from core.errors import INTERNAL_ERROR, NOT_FOUND, TIMEOUT
from core.response import err, err_denied_path, ok
from core.security import is_under_allowlist


def register_log_tools(mcp, cfg: ServerConfig) -> None:
    def _tail(path: str, n: int = 200) -> dict:
        p = pathlib.Path(path)
        if not is_under_allowlist(p, cfg.allowed_log_dirs):
            return err_denied_path(str(p.resolve()), cfg.allowed_log_dirs, cfg)
        if not p.is_file():
            return err(INTERNAL_ERROR, f"Not a file: {path}", cfg=cfg)
        try:
            res = subprocess.run(["tail", "-n", str(n), str(p)], capture_output=True, text=True, check=True, timeout=10)
            return ok(res.stdout, cfg)
        except subprocess.TimeoutExpired:
            return err(TIMEOUT, f"Timeout reading {path}", cfg=cfg)
        except subprocess.CalledProcessError as e:
            return err(INTERNAL_ERROR, e.stderr.strip() if e.stderr else str(e), cfg=cfg)
        except FileNotFoundError:
            return err(INTERNAL_ERROR, "tail command not found", cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    def _pick_wp_log_path() -> str:
        for p in cfg.wp_log_candidates:
            if pathlib.Path(p).is_file():
                return p
        return ""

    @mcp.tool
    def tail(path: str, n: int = 200) -> dict:
        return _tail(path, n)

    @mcp.tool
    def log_tail(path: str, n: int = 200) -> dict:
        return _tail(path, n)

    @mcp.tool
    def log_pick_path() -> dict:
        p = _pick_wp_log_path()
        if p:
            return ok(p, cfg)
        return err(NOT_FOUND, "No WordPress debug log found", hint="Check wp_log_candidates in config", cfg=cfg)

    @mcp.tool
    def log_tail_ai(n: int = 300) -> dict:
        p = _pick_wp_log_path()
        if not p:
            return err(NOT_FOUND, "No log file found", cfg=cfg)
        if not is_under_allowlist(pathlib.Path(p), cfg.allowed_log_dirs):
            return err_denied_path(p, cfg.allowed_log_dirs, cfg)
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
            return ok({"path": p, "lines": out}, cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def log_tail_flow(n: int = 400) -> dict:
        p = _pick_wp_log_path()
        if not p:
            return err(NOT_FOUND, "No log file found", cfg=cfg)
        if not is_under_allowlist(pathlib.Path(p), cfg.allowed_log_dirs):
            return err_denied_path(p, cfg.allowed_log_dirs, cfg)
        pattern = r"ai-translate:(request:start|parse_request:start|resolved_post_id|resolved_page_by_path|fallback_pagename|no_reverse_mapping|empty_basename|pre_handle_404)"
        try:
            cmd = f"tail -n {int(n)} {shlex.quote(p)} | grep -E {shlex.quote(pattern)} || true"
            proc = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True)
            return ok({"path": p, "lines": proc.stdout}, cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def log_tail_keywords(keywords: list[str], n: int = 400) -> dict:
        p = _pick_wp_log_path()
        if not p:
            return err(NOT_FOUND, "No log file found", cfg=cfg)
        if not is_under_allowlist(pathlib.Path(p), cfg.allowed_log_dirs):
            return err_denied_path(p, cfg.allowed_log_dirs, cfg)
        try:
            if not keywords:
                return ok({"path": p, "lines": ""}, cfg)
            expr = "(" + "|".join([re.escape(k) for k in keywords]) + ")"
            cmd = f"tail -n {int(n)} {shlex.quote(p)} | grep -E {shlex.quote(expr)} || true"
            proc = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True)
            return ok({"path": p, "lines": proc.stdout}, cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)
