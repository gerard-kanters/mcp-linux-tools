import json
import pathlib
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ServerConfig:
    server_type: str
    server_ip: str
    server_name: str
    server_host: str
    server_port: int
    log_file: str
    allowed_log_dirs: list[str]
    allowed_read_dirs: list[str]
    allowed_write_dirs: list[str]
    service_whitelist: set[str]
    max_bytes: int
    max_items: int
    python_bin: str
    sandbox_cwd: str
    wp_allowed_sites: list[str]
    wp_bin_candidates: list[str]
    wp_log_candidates: list[str]


def _get_config_value(cfg: dict[str, Any], path: list[str]) -> Any:
    node: Any = cfg
    for key in path:
        if not isinstance(node, dict) or key not in node:
            raise RuntimeError(f"Missing config key: {'.'.join(path)}")
        node = node[key]
    return node


def _require_str(cfg: dict[str, Any], path: list[str]) -> str:
    value = _get_config_value(cfg, path)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"Config key {'.'.join(path)} must be a non-empty string")
    return value.strip()


def _require_int(cfg: dict[str, Any], path: list[str]) -> int:
    value = _get_config_value(cfg, path)
    if not isinstance(value, int):
        raise RuntimeError(f"Config key {'.'.join(path)} must be an integer")
    return value


def _require_str_list(cfg: dict[str, Any], path: list[str]) -> list[str]:
    value = _get_config_value(cfg, path)
    if not isinstance(value, list) or not value:
        raise RuntimeError(f"Config key {'.'.join(path)} must be a non-empty list")
    out: list[str] = []
    for idx, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise RuntimeError(f"Config key {'.'.join(path)} contains invalid entry at index {idx}")
        out.append(item.strip())
    return out


def _optional_str(cfg: dict[str, Any], path: list[str], default: str) -> str:
    try:
        value = _get_config_value(cfg, path)
        if isinstance(value, str) and value.strip():
            return value.strip()
    except RuntimeError:
        pass
    return default


def _optional_int(cfg: dict[str, Any], path: list[str], default: int) -> int:
    try:
        value = _get_config_value(cfg, path)
        if isinstance(value, int):
            return value
    except RuntimeError:
        pass
    return default


def load_config(path: pathlib.Path) -> ServerConfig:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError as e:
        raise RuntimeError(f"Missing server config: {path}") from e
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in server config: {path}: {e}") from e

    if not isinstance(raw, dict):
        raise RuntimeError(f"Invalid config structure: expected object at top level in {path}")

    return ServerConfig(
        server_type=_require_str(raw, ["server_type"]),
        server_ip=_require_str(raw, ["server_ip"]),
        server_name=_require_str(raw, ["server_name"]),
        server_host=_optional_str(raw, ["server", "host"], "127.0.0.1"),
        server_port=_optional_int(raw, ["server", "port"], 8765),
        log_file=_require_str(raw, ["logging", "log_file"]),
        allowed_log_dirs=_require_str_list(raw, ["directories", "allowed_log"]),
        allowed_read_dirs=_require_str_list(raw, ["directories", "allowed_read"]),
        allowed_write_dirs=_require_str_list(raw, ["directories", "allowed_write"]),
        service_whitelist=set(_require_str_list(raw, ["services", "whitelist"])),
        max_bytes=_require_int(raw, ["limits", "max_bytes"]),
        max_items=_require_int(raw, ["limits", "max_items"]),
        python_bin=_require_str(raw, ["python", "bin"]),
        sandbox_cwd=_require_str(raw, ["directories", "sandbox_cwd"]),
        wp_allowed_sites=_require_str_list(raw, ["wordpress", "allowed_sites"]),
        wp_bin_candidates=_require_str_list(raw, ["wordpress", "bin_candidates"]),
        wp_log_candidates=_require_str_list(raw, ["wordpress", "log_candidates"]),
    )
