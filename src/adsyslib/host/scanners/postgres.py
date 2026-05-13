"""
PostgreSQL scanner — service status, version, pg_hba auth methods, SSL config.
"""
import re
from typing import Any, Dict, List

from .base import ScanResult, ServiceScanner

_INSECURE_AUTH = {"trust", "password"}  # plaintext or no-auth methods


class PostgresScanner(ServiceScanner):
    service_name = "postgresql"

    def scan(self) -> ScanResult:
        active = self._is_active("postgresql") or self._is_active("postgres")
        version = self._detect_version()
        ssl_config = self._ssl_config()
        hba = self._parse_hba()
        issues = self._check_issues(active, ssl_config, hba)

        return ScanResult(
            service="postgresql",
            active=active,
            version=version,
            config={"ssl": ssl_config},
            issues=issues,
            metrics={"hba_entries": len(hba), "hba": hba},
        )

    def _detect_version(self) -> str:
        for cmd in (["psql", "--version"], ["postgres", "--version"]):
            r = self._run(cmd)
            if r.ok() and r.stdout:
                return r.stdout.splitlines()[0].strip()
        return ""

    def _ssl_config(self) -> Dict[str, Any]:
        """Read ssl setting from postgresql.conf."""
        for path in (
            "/etc/postgresql/postgresql.conf",
            "/var/lib/pgsql/data/postgresql.conf",
            "/var/lib/postgresql/data/postgresql.conf",
        ):
            r = self._run(["cat", path])
            if not (r.ok() and r.stdout):
                continue
            ssl_on = bool(re.search(r"^\s*ssl\s*=\s*on", r.stdout, re.MULTILINE))
            ssl_cert = re.search(r"^\s*ssl_cert_file\s*=\s*'?([^'\s#]+)", r.stdout, re.MULTILINE)
            return {
                "ssl_enabled": ssl_on,
                "ssl_cert_file": ssl_cert.group(1) if ssl_cert else "",
            }
        return {"ssl_enabled": False, "ssl_cert_file": ""}

    def _parse_hba(self) -> List[Dict[str, str]]:
        """Parse pg_hba.conf for auth method per connection type."""
        for path in (
            "/etc/postgresql/pg_hba.conf",
            "/var/lib/pgsql/data/pg_hba.conf",
            "/var/lib/postgresql/data/pg_hba.conf",
        ):
            r = self._run(["cat", path])
            if not (r.ok() and r.stdout):
                continue
            entries = []
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    entries.append({
                        "type": parts[0],
                        "database": parts[1],
                        "user": parts[2],
                        "address": parts[3] if len(parts) > 4 else "",
                        "method": parts[-1],
                    })
            return entries
        return []

    def _check_issues(self, active: bool, ssl: Dict, hba: List[Dict]) -> List[str]:
        issues = []
        if not active:
            issues.append("postgresql is not running")
        if not ssl.get("ssl_enabled"):
            issues.append("SSL is not enabled in postgresql.conf")
        for entry in hba:
            if entry["method"] in _INSECURE_AUTH and entry["type"] == "host":
                issues.append(
                    f"pg_hba.conf: insecure auth method '{entry['method']}' "
                    f"for host connections (db={entry['database']}, user={entry['user']})"
                )
        return issues
