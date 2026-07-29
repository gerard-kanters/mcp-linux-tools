import pathlib
import re
import shutil
import subprocess

from config import ServerConfig
from core.errors import INTERNAL_ERROR, INVALID_INPUT, NOT_FOUND, PERMISSION_DENIED, TIMEOUT
from core.response import err, err_denied_path, ok
from core.security import is_under_allowlist


def _safe_text(data: bytes) -> str:
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return str(data)


def register_filesystem_tools(mcp, cfg: ServerConfig) -> None:
    @mcp.tool
    def list_dir(
        path: str,
        pattern: str = "*",
        include_files: bool = True,
        include_dirs: bool = False,
        max_items: int | None = None,
    ) -> dict:
        """
        Bekijk gefilterde directory-inhoud zonder het bestandssysteem te wijzigen.

        `path` moet een bestaande directory onder `allowed_read_dirs` zijn.
        `pattern` gebruikt `pathlib`-globsyntaxis (`*` standaard; gebruik
        bijvoorbeeld `**/*` voor recursieve resultaten). Standaard worden alleen
        bestanden opgenomen; zet `include_dirs=True` voor directories en
        `include_files=False` om bestanden uit te sluiten. `max_items` gebruikt
        standaard de geconfigureerde limiet en wordt begrensd tot 1–`max_items`
        uit de serverconfiguratie. De tool retourneert per item naam, absoluut
        pad, type, wijzigingstijd en voor bestanden de grootte; ontoegankelijke
        items bevatten een eigen foutmelding. Resultaten gebruiken de standaard
        `{success, data, error, meta}`-response. Gebruik `read_file`, `head` of
        `tail` om vervolgens bestandsinhoud te lezen.
        """
        if not path or not path.strip():
            return err(INVALID_INPUT, "Path cannot be empty", cfg=cfg)

        try:
            p = pathlib.Path(path)
            if not is_under_allowlist(p, cfg.allowed_read_dirs):
                return err_denied_path(str(p.resolve()), cfg.allowed_read_dirs, cfg)
            if not p.exists():
                return err(NOT_FOUND, f"Path does not exist: {path}", cfg=cfg)
            if not p.is_dir():
                return err(INVALID_INPUT, f"Not a directory: {path}", cfg=cfg)

            requested_max_items = cfg.max_items if max_items is None else int(max_items)
            safe_max_items = max(1, min(requested_max_items, cfg.max_items))
            items = []
            for entry in p.glob(pattern):
                if len(items) >= safe_max_items:
                    break
                try:
                    if (entry.is_file() and include_files) or (entry.is_dir() and include_dirs):
                        stat = entry.stat()
                        items.append(
                            {
                                "name": entry.name,
                                "path": str(entry.resolve()),
                                "is_dir": entry.is_dir(),
                                "size": stat.st_size if entry.is_file() else None,
                                "mtime": int(stat.st_mtime),
                            }
                        )
                except (PermissionError, OSError) as e:
                    items.append(
                        {
                            "name": entry.name,
                            "path": str(entry.resolve()),
                            "error": f"Access denied: {str(e)}",
                        }
                    )
            return ok(items, cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def create_directory(
        path: str,
        owner: str = "root",
        group: str = "root",
        mode: str = "755",
        parents: bool = False,
    ) -> dict:
        """
        Maak een nieuwe directory en stel eigenaar, groep en Unix-modus in.

        Deze tool wijzigt het bestandssysteem. `path` mag nog niet bestaan en
        de bovenliggende directory moet onder `allowed_write_dirs` vallen.
        `owner` en `group` zijn bestaande lokale namen (standaard `root`);
        `mode` is een octale tekenreeks zoals `755` of `0755`. Met
        `parents=True` worden ontbrekende bovenliggende directories aangemaakt;
        eigenaar, groep en de opgegeven modus worden alleen expliciet op de
        doel-directory toegepast. De uitvoerende service moet daarvoor voldoende
        permissies hebben. Succes retourneert `"ok"` via
        `{success, data, error, meta}`; bestaande paden, onbekende accounts,
        ongeldige modi, geweigerde paden en ontbrekende permissies leveren een
        foutresponse op. Gebruik deze tool niet om een bestaande directory of
        bestandsinhoud te wijzigen.
        """
        if not path or not path.strip():
            return err(INVALID_INPUT, "Path cannot be empty", cfg=cfg)
        if not owner or not owner.strip():
            return err(INVALID_INPUT, "Owner cannot be empty", cfg=cfg)
        if not group or not group.strip():
            return err(INVALID_INPUT, "Group cannot be empty", cfg=cfg)

        p = pathlib.Path(path)
        if p.exists():
            return err(INVALID_INPUT, f"Path already exists: {path}", cfg=cfg)
        if not is_under_allowlist(p.parent, cfg.allowed_write_dirs):
            return err_denied_path(str(p.parent.resolve()), cfg.allowed_write_dirs, cfg)
        if not re.match(r"^[0-7]{3,4}$", mode):
            return err(INVALID_INPUT, "Invalid mode, must be octal (e.g. 755, 0755)", cfg=cfg)

        try:
            octal_mode = int(mode, 8)
            p.mkdir(parents=parents, mode=octal_mode)
            shutil.chown(str(p), user=owner, group=group)
            return ok("ok", cfg)
        except PermissionError:
            return err(PERMISSION_DENIED, f"Permission denied creating {path}", cfg=cfg)
        except LookupError as e:
            return err(INVALID_INPUT, f"User or group not found: {e}", cfg=cfg)
        except FileExistsError:
            return err(INVALID_INPUT, f"Directory already exists: {path}", cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def read_file(path: str, max_bytes: int | None = None) -> dict:
        """
        Lees een tekstbestand onder `allowed_read_dirs` zonder het te wijzigen.

        `path` moet een bestaand regulier bestand zijn. `max_bytes` bepaalt
        hoeveel bytes maximaal worden gelezen; zonder waarde geldt de
        geconfigureerde `max_bytes`, en iedere opgegeven waarde wordt begrensd
        tot 1–die configuratielimiet. Bytes worden als UTF-8 gedecodeerd waarbij
        ongeldige tekens worden vervangen. Als meer gegevens beschikbaar zijn,
        eindigt de tekst met `[...truncated...]`. De
        `{success, data, error, meta}`-response bevat de tekst of een fout voor
        een geweigerd pad, ontbrekend bestand of ontbrekende leespermissie.
        Gebruik `head` of `tail` wanneer alleen regels aan het begin of einde
        nodig zijn.
        """
        p = pathlib.Path(path)
        if not is_under_allowlist(p, cfg.allowed_read_dirs):
            return err_denied_path(str(p.resolve()), cfg.allowed_read_dirs, cfg)
        if not p.exists():
            return err(NOT_FOUND, f"File does not exist: {path}", cfg=cfg)
        if not p.is_file():
            return err(INVALID_INPUT, f"Not a file: {path}", cfg=cfg)

        try:
            requested_max_bytes = cfg.max_bytes if max_bytes is None else int(max_bytes)
            safe_max_bytes = max(1, min(requested_max_bytes, cfg.max_bytes))
            with open(p, "rb") as f:
                data = f.read(safe_max_bytes + 1)
            truncated = len(data) > safe_max_bytes
            out = _safe_text(data[:safe_max_bytes])
            content = out + ("\n\n[...truncated...]" if truncated else "")
            return ok(content, cfg)
        except PermissionError:
            return err(PERMISSION_DENIED, f"Permission denied reading {path}", cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def head(path: str, n: int = 100) -> dict:
        """
        Eerste `n` regels van een bestand (onder ALLOWED_READ_DIRS).
        """
        p = pathlib.Path(path)
        if not is_under_allowlist(p, cfg.allowed_read_dirs):
            return err_denied_path(str(p.resolve()), cfg.allowed_read_dirs, cfg)
        if not p.is_file():
            return err(INVALID_INPUT, f"Not a file: {path}", cfg=cfg)

        try:
            res = subprocess.run(["head", "-n", str(n), str(p)], capture_output=True, text=True, check=True, timeout=10)
            return ok(res.stdout, cfg)
        except subprocess.TimeoutExpired:
            return err(TIMEOUT, f"Timeout reading {path}", cfg=cfg)
        except subprocess.CalledProcessError as e:
            return err(INTERNAL_ERROR, e.stderr.strip() if e.stderr else str(e), cfg=cfg)
        except FileNotFoundError:
            return err(INTERNAL_ERROR, "head command not found", cfg=cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)
