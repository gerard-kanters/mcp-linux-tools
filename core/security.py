import pathlib


def is_under_allowlist(path: pathlib.Path, allow: list[str]) -> bool:
    resolved_path = str(path.resolve())
    for base in allow:
        normalized = base.rstrip("/") or "/"
        if resolved_path == normalized or resolved_path.startswith(normalized + "/"):
            return True
    return False


def is_allowed_wp_site(site_path: str, allowed_sites: list[str]) -> bool:
    resolved_path = str(pathlib.Path(site_path).resolve())
    for site in allowed_sites:
        normalized = site.rstrip("/") or "/"
        if resolved_path == normalized or resolved_path.startswith(normalized + "/"):
            return True
    return False
