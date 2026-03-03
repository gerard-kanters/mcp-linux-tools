import os
import re
import tempfile
import time
from typing import Optional

from config import ServerConfig
from core.errors import COMMAND_BLOCKED, INVALID_INPUT, INTERNAL_ERROR
from core.process import run
from core.response import err, ok

try:
    from croniter import croniter  # type: ignore[import]
except Exception:
    croniter = None


CRON_USER = "root"
MCP_SECTION_BEGIN = "# --- BEGIN MCP MANAGED ---"
MCP_SECTION_END = "# --- END MCP MANAGED ---"
CRON_MAX_LINES = 2000


def register_cron_tools(mcp, cfg: ServerConfig) -> None:
    def _validate_schedule(s: str) -> bool:
        valid = bool(re.match(r"^\S+\s+\S+\s+\S+\s+\S+\s+\S+$", s.strip()))
        if valid and croniter:
            try:
                croniter(s, time.time())
            except Exception:
                return False
        return valid

    def _get_crontab(user: str) -> str:
        p = run(["crontab", "-u", user, "-l"])
        if p.returncode != 0 and "no crontab for" in (p.stderr or "").lower():
            return ""
        return p.stdout or ""

    def _set_crontab(user: str, content: str) -> str:
        if content.count("\n") > CRON_MAX_LINES:
            return "crontab too large"
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write(content)
            tpath = tf.name
        pr = run(["crontab", "-u", user, tpath])
        try:
            os.unlink(tpath)
        except Exception:
            pass
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
        i = 0
        found = False
        while i < len(lines):
            if lines[i].startswith("# MCP: id="):
                m = re.search(r"id=([A-Za-z0-9._\-]+)", lines[i])
                if m and m.group(1) == job_id:
                    found = True
                    i += 1
                if i < len(lines) and (not lines[i].startswith("#") or lines[i].startswith("# ")):
                    i += 1
                    if line:
                        out.append(f"# MCP: id={job_id} enabled=1")
                        out.append(line)
                    continue
            out.append(lines[i])
            i += 1
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
            out.append(lines[i])
            i += 1
        return "\n".join(out) + ("\n" if out and not out[-1].endswith("\n") else "")

    @mcp.tool
    def cron_list() -> dict:
        try:
            content = _get_crontab(CRON_USER)
            return ok(content, cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def cron_add(job_id: str, schedule: str, command: str) -> dict:
        if not job_id or not job_id.strip():
            return err(INVALID_INPUT, "job_id cannot be empty", cfg=cfg)
        if not schedule or not schedule.strip():
            return err(INVALID_INPUT, "schedule cannot be empty", cfg=cfg)
        if not command or not command.strip():
            return err(INVALID_INPUT, "command cannot be empty", cfg=cfg)
        if not _validate_schedule(schedule):
            return err(INVALID_INPUT, "invalid schedule format", hint="Use format: minute hour day month weekday", cfg=cfg)
        if not re.match(r"^[A-Za-z0-9._\-]+$", job_id):
            return err(INVALID_INPUT, "job_id must be alphanumeric with ._- only", cfg=cfg)
        first = command.split()[0]
        if not os.path.isabs(first):
            return err(COMMAND_BLOCKED, "command must be absolute path", hint="Use e.g. /usr/bin/echo", cfg=cfg)

        try:
            content = _ensure_section(_get_crontab(CRON_USER))
            pre, mid, post = content.partition(MCP_SECTION_BEGIN)
            sect, mid2, post2 = post.partition(MCP_SECTION_END)
            section_body = _replace_or_append_job(sect, job_id, f"{schedule} {command}")
            new_content = pre + mid + section_body + mid2 + post2
            res = _set_crontab(CRON_USER, new_content)
            if res == "ok":
                return ok("ok", cfg)
            return err(INTERNAL_ERROR, res, cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def cron_remove(job_id: str) -> dict:
        if not job_id or not job_id.strip():
            return err(INVALID_INPUT, "job_id cannot be empty", cfg=cfg)
        try:
            content = _ensure_section(_get_crontab(CRON_USER))
            pre, mid, post = content.partition(MCP_SECTION_BEGIN)
            sect, mid2, post2 = post.partition(MCP_SECTION_END)
            section_body = _replace_or_append_job(sect, job_id, None)
            new_content = pre + mid + section_body + mid2 + post2
            res = _set_crontab(CRON_USER, new_content)
            if res == "ok":
                return ok("ok", cfg)
            return err(INTERNAL_ERROR, res, cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def cron_enable(job_id: str, enabled: bool) -> dict:
        if not job_id or not job_id.strip():
            return err(INVALID_INPUT, "job_id cannot be empty", cfg=cfg)
        try:
            content = _ensure_section(_get_crontab(CRON_USER))
            pre, mid, post = content.partition(MCP_SECTION_BEGIN)
            sect, mid2, post2 = post.partition(MCP_SECTION_END)
            section_body = _set_enabled(sect, job_id, enabled)
            new_content = pre + mid + section_body + mid2 + post2
            res = _set_crontab(CRON_USER, new_content)
            if res == "ok":
                return ok("ok", cfg)
            return err(INTERNAL_ERROR, res, cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def cron_next_runs(schedule: str, n: int = 5) -> dict:
        if not schedule or not schedule.strip():
            return err(INVALID_INPUT, "schedule cannot be empty", cfg=cfg)
        if not _validate_schedule(schedule):
            return err(INVALID_INPUT, "invalid schedule format", cfg=cfg)
        if not croniter:
            return err(INTERNAL_ERROR, "croniter not installed", cfg=cfg)
        try:
            safe_n = max(1, min(20, int(n)))
            base = time.time()
            it = croniter(schedule, base)
            times = [time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(it.get_next())) for _ in range(safe_n)]
            return ok(times, cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)
