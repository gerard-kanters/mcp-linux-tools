import os
import pathlib
import re
import shlex
import shutil
import subprocess
from typing import Optional

from config import ServerConfig
from core.errors import COMMAND_BLOCKED, INTERNAL_ERROR, INVALID_INPUT, NOT_FOUND, PERMISSION_DENIED, TIMEOUT
from core.response import err, err_denied_path, ok
from core.security import is_under_allowlist


def register_ops_tools(mcp, cfg: ServerConfig) -> None:
    @mcp.tool
    def mysql_query(query: str, database: str = "") -> dict:
        """
        Voer SQL uit met de lokale MySQL-client als databasegebruiker `root`.

        `query` is de volledige SQL-tekst en mag niet leeg zijn. `database`
        kiest optioneel een database; een lege waarde gebruikt de standaard
        MySQL-context. Queries met de tekst `DROP`, `TRUNCATE`, `DELETE` of
        `ALTER` worden geblokkeerd. Andere SQL, inclusief mogelijk muterende
        statements, wordt niet door deze tool geblokkeerd. De timeout is
        30 seconden en stdout van de client wordt teruggegeven.
        """
        if not query or not query.strip():
            return err(INVALID_INPUT, "Query cannot be empty", cfg=cfg)

        query_upper = query.strip().upper()
        dangerous = ["DROP", "TRUNCATE", "DELETE", "ALTER"]
        blocked = [q for q in dangerous if q in query_upper]
        if blocked:
            return err(COMMAND_BLOCKED, f"Dangerous query blocked: contains {blocked}", cfg=cfg)

        try:
            cmd = ["mysql", "-u", "root"]
            if database:
                cmd.append(database)
            cmd.extend(["-e", query])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else "Query failed with unknown error"
                return err(INTERNAL_ERROR, error_msg, cfg=cfg)
            return ok({"query": query, "database": database or "default", "result": result.stdout}, cfg)
        except subprocess.TimeoutExpired:
            return err(TIMEOUT, "Query timeout (30s)", cfg=cfg)
        except FileNotFoundError:
            return err(INTERNAL_ERROR, "mysql command not found. Is MySQL client installed?", cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def chmod_file(path: str, mode: str) -> dict:
        """
        Wijzig de Unix-permissiemodus van een bestaand toegestaan pad.

        `path` moet bestaan en onder `allowed_write_dirs` vallen. `mode` moet
        een octale tekenreeks van drie of vier cijfers zijn, bijvoorbeeld
        `755` of `0755`. Deze tool muteert bestandssysteemmetadata via
        `chmod`, maar wijzigt de bestandsinhoud niet.
        """
        if not path or not path.strip():
            return err(INVALID_INPUT, "Path cannot be empty", cfg=cfg)
        if not mode or not mode.strip():
            return err(INVALID_INPUT, "Mode cannot be empty", cfg=cfg)

        p = pathlib.Path(path)
        if not is_under_allowlist(p, cfg.allowed_write_dirs):
            return err_denied_path(str(p.resolve()), cfg.allowed_write_dirs, cfg)
        if not p.exists():
            return err(NOT_FOUND, f"Path does not exist: {path}", cfg=cfg)
        if not re.match(r"^[0-7]{3,4}$", mode):
            return err(INVALID_INPUT, "Invalid mode, must be octal (e.g. 755, 0755)", cfg=cfg)

        try:
            os.chmod(str(p), int(mode, 8))
            return ok(f"ok: changed {path} to {mode}", cfg)
        except PermissionError:
            return err(PERMISSION_DENIED, f"Permission denied changing {path}", cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def chown_path(path: str, owner: str, group: str) -> dict:
        """
        Wijzig eigenaar en groep van een bestaand toegestaan pad.

        `path` moet bestaan en onder `allowed_write_dirs` vallen. `owner` en
        `group` moeten bestaande lokale namen zijn. Deze tool muteert
        bestandssysteemmetadata via `chown`; onbekende gebruikers of groepen
        en ontbrekende permissies leveren een fout op.
        """
        if not path or not path.strip():
            return err(INVALID_INPUT, "Path cannot be empty", cfg=cfg)
        if not owner or not owner.strip():
            return err(INVALID_INPUT, "Owner cannot be empty", cfg=cfg)
        if not group or not group.strip():
            return err(INVALID_INPUT, "Group cannot be empty", cfg=cfg)

        p = pathlib.Path(path)
        if not is_under_allowlist(p, cfg.allowed_write_dirs):
            return err_denied_path(str(p.resolve()), cfg.allowed_write_dirs, cfg)
        if not p.exists():
            return err(NOT_FOUND, f"Path does not exist: {path}", cfg=cfg)

        try:
            shutil.chown(str(p), user=owner, group=group)
            return ok(f"ok: changed owner/group of {path} to {owner}:{group}", cfg)
        except PermissionError:
            return err(PERMISSION_DENIED, f"Permission denied changing {path}", cfg=cfg)
        except LookupError as e:
            return err(INVALID_INPUT, f"User or group not found: {e}", cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def ping_host(host: str, count: int = 4) -> dict:
        """
        Test netwerkbereikbaarheid van een host met ICMP-ping.

        `host` accepteert alleen letters, cijfers, punten en koppeltekens;
        shell-expressies zijn daardoor niet toegestaan. `count` wordt begrensd
        tot 1–10 pakketten. De tool wijzigt het systeem niet, heeft een totale
        timeout van 60 seconden en retourneert uitvoer, exitcode en successtatus.
        """
        if not host or not host.strip():
            return err(INVALID_INPUT, "Host cannot be empty", cfg=cfg)
        if not re.match(r"^[a-zA-Z0-9.-]+$", host):
            return err(INVALID_INPUT, "Invalid hostname format", cfg=cfg)
        try:
            safe_count = max(1, min(10, int(count)))
        except Exception:
            return err(INVALID_INPUT, "Invalid count value, must be integer", cfg=cfg)

        try:
            cmd = ["ping", "-c", str(safe_count), "-W", "30", host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            success = result.returncode == 0
            data = {
                "host": host,
                "count": safe_count,
                "success": success,
                "output": result.stdout if result.stdout else result.stderr,
                "exit_code": result.returncode,
            }
            if not success:
                data["error"] = f"Ping failed: {result.stderr.strip() if result.stderr else 'Unknown error'}"
            return ok(data, cfg)
        except subprocess.TimeoutExpired:
            return err(TIMEOUT, f"Ping timeout for {host} (60s)", cfg=cfg)
        except FileNotFoundError:
            return err(INTERNAL_ERROR, "ping command not found. Is ping installed?", cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def git_command(path: str, command: str) -> dict:
        """
        Voer één Git-subcommando uit in een toegestane lokale repository.

        `path` moet onder `allowed_write_dirs` vallen en een `.git`-directory
        bevatten. `command` bevat alles na `git -C <path>` en wordt met
        shell-achtige argumentquoting opgesplitst, zonder shelluitbreiding.
        Push, force, delete, `branch -d` en `reset --hard` worden geblokkeerd;
        andere muterende Git-commando's kunnen de repository wel wijzigen.
        De timeout is 30 seconden en stdout, stderr en exitcode worden geretourneerd.
        """
        if not path or not path.strip():
            return err(INVALID_INPUT, "Path cannot be empty", cfg=cfg)
        if not command or not command.strip():
            return err(INVALID_INPUT, "Command cannot be empty", cfg=cfg)

        p = pathlib.Path(path)
        if not is_under_allowlist(p, cfg.allowed_write_dirs):
            return err_denied_path(str(p.resolve()), cfg.allowed_write_dirs, cfg)
        if not p.exists():
            return err(NOT_FOUND, f"Path does not exist: {path}", cfg=cfg)
        if not (p / ".git").is_dir():
            return err(NOT_FOUND, f"Not a git repository: {path}", cfg=cfg)

        dangerous_cmds = ["push", "force", "force-push", "delete", "branch -d", "reset --hard"]
        if any(cmd in command.lower() for cmd in dangerous_cmds):
            return err(COMMAND_BLOCKED, f"Dangerous command blocked: {command}", cfg=cfg)

        try:
            cmd = ["git", "-C", str(p)] + shlex.split(command)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            data = {
                "path": str(p),
                "command": command,
                "output": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode,
                "success": result.returncode == 0,
            }
            if result.returncode != 0:
                data["error"] = result.stderr.strip() if result.stderr else "Command failed with unknown error"
            return ok(data, cfg)
        except subprocess.TimeoutExpired:
            return err(TIMEOUT, "Git command timeout (30s)", cfg=cfg)
        except FileNotFoundError:
            return err(INTERNAL_ERROR, "git command not found. Is Git installed?", cfg=cfg)
        except ValueError as e:
            return err(INVALID_INPUT, f"Invalid command syntax: {e}", cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def execute_shell_command(command: str, user: Optional[str] = None) -> dict:
        """
        Voer een lokaal programma uit als root of als de opgegeven gebruiker.

        `command` wordt in argumenten opgesplitst en direct gestart, dus pipes,
        redirects en andere shellsyntaxis worden niet geïnterpreteerd. Met
        `user` wordt het programma via `sudo -u` uitgevoerd; zonder waarde is
        de uitvoerende gebruiker root. Het commando kan het systeem wijzigen.
        Voor curl/wget is de werkdirectory `/tmp`; de timeout is 300 seconden.
        Stdout, stderr, exitcode en de effectieve gebruiker worden geretourneerd.
        """
        if not command or not command.strip():
            return err(INVALID_INPUT, "Command cannot be empty", cfg=cfg)

        try:
            full_cmd = shlex.split(command)
            proc_cmd = ["sudo", "-u", user] + full_cmd if user else full_cmd

            cmd_lower = command.lower()
            cwd = "/tmp" if "curl" in cmd_lower or "wget" in cmd_lower else None

            result = subprocess.run(proc_cmd, capture_output=True, text=True, timeout=300, cwd=cwd)
            success = result.returncode == 0
            data = {
                "command": command,
                "user": user or "root",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode,
                "success": success,
            }
            if not success:
                data["error"] = f"Command failed with exit code {result.returncode}"
                if result.stderr:
                    data["error"] += f": {result.stderr.strip()}"
            return ok(data, cfg)
        except subprocess.TimeoutExpired:
            return err(TIMEOUT, f"Command timed out after 300 seconds: {command}", cfg=cfg)
        except ValueError as e:
            return err(INVALID_INPUT, f"Invalid command syntax: {e}", cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)
