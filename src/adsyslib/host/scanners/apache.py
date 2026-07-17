"""
Apache scanner — service status, config test, modules, TLS config.
Works with both apache2 (Debian/Ubuntu) and httpd (RHEL/CentOS).
"""
import re
from typing import Any

from .base import ScanResult, ServiceScanner

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
_WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"}


class ApacheScanner(ServiceScanner):
    service_name = "apache"

    def scan(self) -> ScanResult:
        service, active = self._detect_service()
        version = self._version([service, "-v"])
        conf_ok, conf_errors = self._config_test(service)
        modules = self._loaded_modules(service)
        tls = self._tls_summary()
        vhosts = self._vhost_count(service)
        issues = self._check_issues(active, conf_ok, conf_errors, modules, tls)

        ssl_loaded = any("ssl" in m.lower() for m in modules)
        return ScanResult(
            service="apache",
            active=active,
            version=version,
            config={"tls": tls, "ssl_module_loaded": ssl_loaded},
            issues=issues,
            metrics={
                "conf_test_ok": conf_ok,
                "loaded_modules": modules,
                "vhost_count": vhosts,
            },
        )

    def _detect_service(self) -> tuple[str, bool]:
        """Returns (binary_name, is_active). Tries apache2 then httpd."""
        for name in ("apache2", "httpd"):
            if self._is_active(name):
                return name, True
        # Not active — still pick the available binary for version/config info
        for name in ("apache2", "httpd"):
            r = self._run(["which", name])
            if r.ok():
                return name, False
        return "apache2", False

    def _config_test(self, service: str) -> tuple[bool, list[str]]:
        r = self._run([service, "-t"])
        output = (r.stdout + r.stderr).strip()
        ok = "syntax ok" in output.lower() or r.exit_code == 0
        errors = [ln.strip() for ln in output.splitlines() if "error" in ln.lower()]
        return ok, errors

    def _loaded_modules(self, service: str) -> list[str]:
        r = self._run([service, "-M"])
        if not r.ok():
            return []
        return [
            ln.strip().split()[0]
            for ln in r.stdout.splitlines()
            if ln.strip() and not ln.strip().startswith("Loaded")
        ]

    def _vhost_count(self, service: str) -> int:
        r = self._run([service, "-S"])
        if not r.ok():
            return -1
        return sum(1 for ln in r.stdout.splitlines() if "namevhost" in ln.lower())

    def _tls_summary(self) -> dict[str, Any]:
        """Parse SSLProtocol / SSLCipherSuite from live config dump."""
        # apache2ctl or apachectl -D DUMP_CONFIG (not universally available)
        r = self._run(["apachectl", "-D", "DUMP_CONFIG"])
        if not r.ok():
            r = self._run(["apache2ctl", "-D", "DUMP_CONFIG"])
        if not r.ok():
            return {}
        text = r.stdout
        protocols = re.findall(r"^\s*SSLProtocol\s+(.+)$", text, re.MULTILINE)
        ciphers = re.findall(r"^\s*SSLCipherSuite\s+(.+)$", text, re.MULTILINE)
        hsts = bool(re.search(r"Strict-Transport-Security", text))
        return {
            "ssl_protocols": [p.strip() for p in protocols],
            "ssl_ciphers": [c.strip() for c in ciphers],
            "hsts_configured": hsts,
        }

    def _check_issues(
        self, active: bool, conf_ok: bool, conf_errors: list[str],
        modules: list[str], tls: dict,
    ) -> list[str]:
        issues = []
        if not active:
            issues.append("apache is not running")
        if not conf_ok:
            issues.append("apache config test failed")
            issues.extend(conf_errors[:5])
        for proto_line in tls.get("ssl_protocols", []):
            for token in re.split(r"[\s,]+", proto_line):
                token = token.lstrip("+-")
                if token in _WEAK_PROTOCOLS:
                    issues.append(f"weak SSL/TLS protocol configured: {token}")
        for cipher_line in tls.get("ssl_ciphers", []):
            for token in re.split(r"[:,\s]+", cipher_line):
                token = token.lstrip("+")
                if token.startswith("!"):
                    continue  # negated (excluded) — not a vulnerability
                if token.upper() in _WEAK_CIPHERS:
                    issues.append(f"weak cipher suite component: {token}")
        if tls and not tls.get("hsts_configured"):
            issues.append("HSTS (Strict-Transport-Security) not configured")
        return issues
