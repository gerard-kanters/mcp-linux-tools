import pathlib
import subprocess

from config import ServerConfig
from core.errors import INTERNAL_ERROR, INVALID_INPUT, NOT_FOUND, TIMEOUT
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
        """
        Lees de laatste `n` regels van één specifiek logbestand.

        `path` moet een bestaand bestand onder een geconfigureerde
        `allowed_log_dirs`-directory zijn. `n` bepaalt hoeveel regels aan
        `tail -n` worden doorgegeven. De tool is alleen-lezen, heeft een
        timeout van 10 seconden en retourneert de tekst via de standaard
        `{success, data, error, meta}`-response.
        """
        return _tail(path, n)

    @mcp.tool
    def log_pick_path() -> dict:
        """
        Kies het eerste bestaande WordPress-debuglog uit de configuratie.

        De kandidaten worden in de volgorde van `wp_log_candidates` getest.
        De tool wijzigt niets en retourneert alleen het gevonden pad. Als
        geen kandidaat een bestaand bestand is, volgt een `NOT_FOUND`-fout.
        """
        p = _pick_wp_log_path()
        if p:
            return ok(p, cfg)
        return err(NOT_FOUND, "No WordPress debug log found", hint="Check wp_log_candidates in config", cfg=cfg)

    @mcp.tool
    def log_search(keywords: list[str], path: str | None = None, n: int = 400) -> dict:
        """
        Zoek letterlijke trefwoorden in de laatste regels van een logbestand.

        `keywords` moet minimaal één niet-lege tekenreeks bevatten; een regel
        wordt opgenomen als één van de trefwoorden erin voorkomt. De vergelijking
        is hoofdlettergevoelig. Met `path` wordt een specifiek bestaand bestand
        onder `allowed_log_dirs` gekozen. Zonder `path` gebruikt de tool het
        eerste bestaande bestand uit `wp_log_candidates`; als dat ontbreekt volgt
        een `NOT_FOUND`-fout. `n` bepaalt hoeveel laatste regels vóór filtering
        worden gelezen. De tool is alleen-lezen en retourneert het gebruikte pad
        en uitsluitend de overeenkomende regels via
        `{success, data, error, meta}`. Gebruik `tail` wanneer geen filtering
        nodig is.
        """
        safe_keywords = [keyword for keyword in keywords if keyword]
        if not safe_keywords:
            return err(INVALID_INPUT, "Keywords must contain at least one non-empty value", cfg=cfg)

        selected_path = _pick_wp_log_path() if path is None else path
        if not selected_path:
            return err(NOT_FOUND, "No WordPress debug log found", cfg=cfg)

        result = _tail(selected_path, n)
        if not result["success"]:
            return result

        matching_lines = "".join(
            line
            for line in result["data"].splitlines(keepends=True)
            if any(keyword in line for keyword in safe_keywords)
        )
        return ok({"path": selected_path, "lines": matching_lines}, cfg)
