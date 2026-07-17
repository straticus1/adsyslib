"""
Nginx scanner — service status, config test, sites, TLS protocols.
"""
import re
from typing import Any

from .base import ScanResult, ServiceScanner


class NginxScanner(ServiceScanner):
    service_name = "nginx"

    def scan(self) -> ScanResult:
        active = self._is_active("nginx")
        version = self._version(["nginx", "-v"])
        conf_ok, conf_errors = self._config_test()
        sites = self._enabled_sites()
        tls = self._tls_summary()
        issues = self._check_issues(active, conf_ok, conf_errors, tls)

        return ScanResult(
            service="nginx",
            active=active,
            version=version,
            config={"tls": tls},
            issues=issues,
            metrics={
                "conf_test_ok": conf_ok,
                "enabled_sites": sites,
            },
        )

    def _config_test(self) -> tuple[bool, list[str]]:
        r = self._run(["nginx", "-t"])
        # nginx writes to stderr even on success
        output = (r.stdout + r.stderr).strip()
        ok = "test is successful" in output.lower() or r.exit_code == 0
        errors = [ln.strip() for ln in output.splitlines() if "error" in ln.lower()]
        return ok, errors

    def _enabled_sites(self) -> list[str]:
        for sites_dir in ("/etc/nginx/sites-enabled", "/etc/nginx/conf.d"):
            r = self._run(["ls", sites_dir])
            if r.ok() and r.stdout.strip():
                return [s.strip() for s in r.stdout.splitlines() if s.strip()]
        return []

    def _tls_summary(self) -> dict[str, Any]:
        r = self._run(["nginx", "-T"])
        if not r.ok():
            return {}
        text = r.stdout
        protocols = list(set(re.findall(r"ssl_protocols\s+([^;]+);", text)))
        ciphers = list(set(re.findall(r"ssl_ciphers\s+([^;]+);", text)))
        certs = list(set(re.findall(r"ssl_certificate\s+([^;]+);", text)))
        hsts = bool(re.search(r"Strict-Transport-Security", text))
        return {
            "ssl_protocols": [p.strip() for p in protocols],
            "ssl_ciphers": [c.strip() for c in ciphers],
            "ssl_certificates": [c.strip() for c in certs],
            "hsts_configured": hsts,
        }

    def _check_issues(
        self, active: bool, conf_ok: bool, conf_errors: list[str], tls: dict
    ) -> list[str]:
        issues = []
        if not active:
            issues.append("nginx is not running")
        if not conf_ok:
            issues.append("nginx -t config test failed")
            issues.extend(conf_errors[:5])
        for proto_block in tls.get("ssl_protocols", []):
            tokens = set(re.split(r"[\s;,]+", proto_block))
            for weak in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                if weak in tokens:
                    issues.append(f"weak SSL/TLS protocol in use: {weak}")
        if tls and not tls.get("hsts_configured"):
            issues.append("HSTS (Strict-Transport-Security) not configured")
        return issues
