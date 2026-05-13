"""
DNS scanner — BIND/named status, config check, zone count, rndc status.
"""
import re
from typing import Any, Dict, List, Optional

from .base import ScanResult, ServiceScanner


_NAMED_CONF_PATHS = [
    "/etc/named.conf",
    "/etc/bind/named.conf",
    "/etc/named/named.conf",
]


class DnsScanner(ServiceScanner):
    service_name = "named"

    def scan(self) -> ScanResult:
        # named runs as either "named" or "bind9" depending on distro
        active = self._is_active("named") or self._is_active("bind9")
        version = self._version(["named", "-v"])

        conf_path = self._find_conf()
        config = self._parse_conf(conf_path) if conf_path else {}
        conf_ok, conf_errors = self._check_conf()
        zones = self._zone_count()
        rndc = self._rndc_status()
        issues = self._check_issues(active, conf_ok, conf_errors, config, rndc)

        return ScanResult(
            service="dns",
            active=active,
            version=version,
            config={**config, "conf_path": conf_path},
            issues=issues,
            metrics={
                "zone_count": zones,
                "conf_check_ok": conf_ok,
                "rndc_status": rndc,
            },
        )

    def _find_conf(self) -> Optional[str]:
        for path in _NAMED_CONF_PATHS:
            r = self._run(["test", "-f", path])
            if r.exit_code == 0:
                return path
            # Fallback: try reading (works with FakeShell / when test(1) unavailable)
            if self._shell.read_text(path) is not None:
                return path
        return None

    def _parse_conf(self, path: str) -> Dict[str, Any]:
        text = self._shell.read_text(path)
        if not text:
            return {}
        listen = re.findall(r"listen-on\s*\{([^}]+)\}", text)
        forwarders = re.findall(r"forwarders\s*\{([^}]+)\}", text)
        recursion = "yes" if re.search(r"recursion\s+yes", text) else "no"
        return {
            "listen_on": [s.strip().strip(";") for s in listen],
            "forwarders": [f.strip().strip(";") for f in " ".join(forwarders).split()],
            "recursion": recursion,
            "dnssec_validation": "yes" if re.search(r"dnssec-validation\s+yes", text) else "no",
        }

    def _check_conf(self):
        r = self._run(["named-checkconf"])
        ok = r.exit_code == 0
        errors = [ln.strip() for ln in (r.stdout + r.stderr).splitlines() if ln.strip()] if not ok else []
        return ok, errors

    def _zone_count(self) -> int:
        r = self._run(["rndc", "status"])
        if r.ok():
            m = re.search(r"number of zones:\s*(\d+)", r.stdout, re.IGNORECASE)
            if m:
                return int(m.group(1))
        # Fallback: count zone files
        for zone_dir in ("/var/named", "/etc/bind/zones", "/var/cache/bind"):
            r2 = self._run(["find", zone_dir, "-name", "*.zone", "-type", "f"])
            if r2.ok() and r2.stdout.strip():
                return len(r2.stdout.strip().splitlines())
        return -1

    def _rndc_status(self) -> Dict[str, Any]:
        r = self._run(["rndc", "status"])
        if not r.ok():
            return {"available": False}
        data: Dict[str, Any] = {"available": True}
        for line in r.stdout.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                data[k.strip().lower().replace(" ", "_")] = v.strip()
        return data

    def _check_issues(
        self, active: bool, conf_ok: bool, conf_errors: List[str],
        config: Dict, rndc: Dict,
    ) -> List[str]:
        issues = []
        if not active:
            issues.append("named/bind9 is not running")
        if not conf_ok:
            issues.append("named-checkconf found errors")
            issues.extend(conf_errors[:5])
        if config.get("recursion") == "yes" and not config.get("forwarders"):
            issues.append("recursion enabled with no forwarders — open resolver risk")
        if config.get("dnssec_validation") != "yes":
            issues.append("dnssec-validation is not enabled")
        return issues
