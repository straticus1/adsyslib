"""
MySQL/MariaDB scanner — service status, version, config, security settings.
"""
from typing import Any

from .base import ScanResult, ServiceScanner


class MysqlScanner(ServiceScanner):
    service_name = "mysql"

    def scan(self) -> ScanResult:
        service, active = self._detect_service()
        version = self._detect_version()
        config = self._read_config()
        issues = self._check_issues(active, config)

        return ScanResult(
            service="mysql",
            active=active,
            version=version,
            config=config,
            issues=issues,
            metrics={"service_name": service},
        )

    def _detect_service(self) -> tuple[str, bool]:
        for name in ("mysql", "mariadb", "mysqld"):
            if self._is_active(name):
                return name, True
        for name in ("mysql", "mariadb", "mysqld"):
            r = self._run(["which", name])
            if r.ok():
                return name, False
        return "mysql", False

    def _detect_version(self) -> str:
        for cmd in (["mysql", "--version"], ["mysqld", "--version"], ["mariadb", "--version"]):
            r = self._run(cmd)
            if r.ok() and r.stdout:
                return r.stdout.splitlines()[0].strip()
        return ""

    def _read_config(self) -> dict[str, Any]:
        """Parse key security settings from my.cnf."""
        for path in ("/etc/mysql/my.cnf", "/etc/my.cnf", "/etc/mysql/mysql.conf.d/mysqld.cnf"):
            r = self._run(["cat", path])
            if r.ok() and r.stdout:
                return self._parse_cnf(r.stdout)
        return {}

    def _parse_cnf(self, text: str) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            key = k.strip().lower().replace("-", "_")
            result[key] = v.strip()
        return {
            "bind_address": result.get("bind_address", ""),
            "skip_networking": "skip_networking" in result,
            "local_infile": result.get("local_infile", ""),
            "ssl_ca": result.get("ssl_ca", ""),
            "require_secure_transport": result.get("require_secure_transport", ""),
        }

    def _check_issues(self, active: bool, config: dict) -> list[str]:
        issues = []
        if not active:
            issues.append("mysql/mariadb is not running")
        bind = config.get("bind_address", "")
        if bind in ("0.0.0.0", "::") :
            issues.append(f"mysql bound to all interfaces: bind_address={bind}")
        if config.get("local_infile", "").lower() in ("1", "on", "true"):
            issues.append("local_infile is enabled — allows arbitrary file reads")
        if not config.get("ssl_ca") and not config.get("require_secure_transport"):
            issues.append("TLS not configured: ssl_ca and require_secure_transport both absent")
        return issues
