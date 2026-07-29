import os
import pathlib
import shlex
import shutil
import subprocess

from config import ServerConfig
from core.errors import DENIED_SITE, INTERNAL_ERROR, NOT_FOUND
from core.response import err, err_denied_site, ok
from core.security import is_allowed_wp_site


def register_wordpress_tools(mcp, cfg: ServerConfig) -> None:
    def _which_wp():
        for p in cfg.wp_bin_candidates:
            if pathlib.Path(p).is_file() and os.access(p, os.X_OK):
                return p
        return shutil.which("wp")

    def _wp_cli(site_path: str, args: str, as_www_data: bool = True) -> dict:
        if not is_allowed_wp_site(site_path, cfg.wp_allowed_sites):
            return err_denied_site(site_path, cfg)

        wp_config = pathlib.Path(site_path) / "wp-config.php"
        if not wp_config.is_file():
            return err(NOT_FOUND, f"wp-config.php not found in {site_path}", cfg=cfg)

        wp = _which_wp()
        if not wp:
            return err(INTERNAL_ERROR, "wp not found (install wp-cli)", cfg=cfg)

        cmd = [wp, f"--path={site_path}"] + shlex.split(args)
        if not as_www_data:
            cmd.append("--allow-root")

        env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "WP_CLI_DISABLE_AUTO_CHECK_UPDATE": "1",
            "HOME": "/var/www" if as_www_data else "/root",
        }

        try:
            if as_www_data:
                full = ["sudo", "-u", "www-data", "-E"] + cmd
            else:
                full = cmd
            proc = subprocess.run(full, capture_output=True, text=True, env=env, timeout=60)
            return ok({"cmd": " ".join(full), "exit": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}, cfg)
        except Exception as e:
            return err(INTERNAL_ERROR, str(e), cfg=cfg)

    @mcp.tool
    def wp_cli(site_path: str, args: str, as_www_data: bool = True) -> dict:
        """
        Voer opgegeven WP-CLI-argumenten uit voor een toegestane WordPress-site.

        `site_path` moet in `wp_allowed_sites` staan en `wp-config.php` bevatten.
        `args` wordt met shell-achtige argumentquoting opgesplitst, zonder
        shelluitbreiding, en kan afhankelijk van het WP-CLI-commando de site
        wijzigen. Standaard draait het commando als `www-data`; met
        `as_www_data=False` draait het als root met `--allow-root`. De timeout
        is 60 seconden; commando, stdout, stderr en exitcode worden geretourneerd.
        """
        return _wp_cli(site_path, args, as_www_data)

    @mcp.tool
    def wp_cache_flush(site_path: str, as_www_data: bool = True) -> dict:
        """
        Wis de WordPress-objectcache van één toegestane site via WP-CLI.

        `site_path` moet in `wp_allowed_sites` staan en een `wp-config.php`
        bevatten. Deze muterende tool voert `wp cache flush` uit, standaard
        als `www-data`; met `as_www_data=False` als root met `--allow-root`.
        De timeout is 60 seconden en stdout, stderr en exitcode worden geretourneerd.
        """
        return _wp_cli(site_path, "cache flush", as_www_data)

    @mcp.tool
    def wp_plugin_list(site_path: str, as_www_data: bool = True) -> dict:
        """
        Lees de geïnstalleerde WordPress-plugins van een toegestane site.

        `site_path` moet in `wp_allowed_sites` staan en `wp-config.php`
        bevatten. De tool voert `wp plugin list --format=json` uit, standaard
        als `www-data`; met `as_www_data=False` als root met `--allow-root`.
        De bedoelde operatie is alleen-lezen en heeft een timeout van 60 seconden.
        """
        return _wp_cli(site_path, "plugin list --format=json", as_www_data)

    @mcp.tool
    def wp_user_list(site_path: str, as_www_data: bool = True) -> dict:
        """
        Lees de WordPress-gebruikers van een toegestane site als JSON.

        `site_path` moet in `wp_allowed_sites` staan en `wp-config.php`
        bevatten. De tool voert `wp user list --format=json` uit, standaard
        als `www-data`; met `as_www_data=False` als root met `--allow-root`.
        De bedoelde operatie is alleen-lezen en heeft een timeout van 60 seconden.
        """
        return _wp_cli(site_path, "user list --format=json", as_www_data)
