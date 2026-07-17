"""
Dovecot scanner — IMAP/POP3 status, protocols, SSL config, auth mechanisms.
"""
from typing import Any

from .base import ScanResult, ServiceScanner


class DovecotScanner(ServiceScanner):
    service_name = "dovecot"

    def scan(self) -> ScanResult:
        active = self._is_active("dovecot")
        version = self._version(["dovecot", "--version"])
        config = self._doveconf()
        connections = self._active_connections()
        issues = self._check_issues(active, config)

        return ScanResult(
            service="dovecot",
            active=active,
            version=version,
            config=config,
            issues=issues,
            metrics={"active_connections": connections},
        )

    def _doveconf(self) -> dict[str, Any]:
        result = self._run(["doveconf", "-n"])
        if not result.ok():
            return {}

        conf: dict[str, str] = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                conf[k.strip()] = v.strip()

        keys = [
            "protocols", "ssl", "ssl_cert", "ssl_key", "ssl_min_protocol",
            "ssl_cipher_list", "auth_mechanisms", "disable_plaintext_auth",
            "mail_location", "first_valid_uid",
        ]
        return {k: conf[k] for k in keys if k in conf}

    def _active_connections(self) -> int:
        r = self._run(["doveadm", "who"])
        if not r.ok():
            return -1
        lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
        return max(0, len(lines) - 1)  # subtract header

    def _check_issues(self, active: bool, config: dict) -> list[str]:
        issues = []
        if not active:
            issues.append("dovecot is not running")
        ssl = config.get("ssl", "no")
        if ssl == "no":
            issues.append("ssl=no — plaintext connections allowed")
        elif ssl == "yes":
            issues.append("ssl=yes — consider ssl=required to force TLS")
        if config.get("disable_plaintext_auth", "no").lower() != "yes":
            issues.append("disable_plaintext_auth is not set — plaintext auth allowed over non-SSL")
        mechs = config.get("auth_mechanisms", "")
        if "plain" in mechs.lower() and ssl != "required":
            issues.append("PLAIN auth mechanism active without ssl=required")
        min_proto = config.get("ssl_min_protocol", "")
        if min_proto and min_proto.upper() in ("SSLV3", "TLSV1", "TLSV1.1"):
            issues.append(f"ssl_min_protocol={min_proto} — use TLSv1.2 or TLSv1.3")
        return issues
