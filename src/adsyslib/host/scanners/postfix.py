"""
Postfix scanner — mail server status, queue depth, TLS config, recent errors.
"""
import re
from typing import Any, Dict, List

from .base import ScanResult, ServiceScanner

# TLS levels that are acceptable for inbound and outbound
_STRONG_TLS = {"encrypt", "may", "dane", "dane-only", "secure"}

# postconf keys we care about
_CONFIG_KEYS = [
    "myhostname", "mydomain", "myorigin",
    "smtpd_tls_security_level", "smtp_tls_security_level",
    "smtpd_tls_cert_file", "smtpd_tls_key_file",
    "smtpd_tls_protocols", "smtp_tls_protocols",
    "inet_interfaces", "inet_protocols",
    "smtpd_relay_restrictions", "smtpd_recipient_restrictions",
    "mailq_path", "queue_directory",
]


class PostfixScanner(ServiceScanner):
    service_name = "postfix"

    def scan(self) -> ScanResult:
        active = self._is_active("postfix")
        version = self._version(["postfix", "-d", "-"])
        if not version:
            version = self._version(["postconf", "-d", "mail_version"])

        config = self._postconf()
        queue = self._queue_depth()
        issues = self._check_issues(active, config, queue)
        errors = self._recent_errors()

        return ScanResult(
            service="postfix",
            active=active,
            version=version,
            config=config,
            issues=issues,
            metrics={"queue_depth": queue, "recent_errors": errors},
        )

    def _postconf(self) -> Dict[str, Any]:
        result = self._run(["postconf", "-n"])
        if not result.ok():
            return {}
        conf: Dict[str, str] = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                conf[k.strip()] = v.strip()
        # Return only keys we track
        return {k: conf[k] for k in _CONFIG_KEYS if k in conf}

    def _queue_depth(self) -> int:
        result = self._run(["mailq"])
        if not result.ok():
            return -1
        last = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
        m = re.search(r"(\d+)\s+request", last, re.IGNORECASE)
        return int(m.group(1)) if m else 0

    def _recent_errors(self, lines: int = 50) -> List[str]:
        for log in ("/var/log/mail.log", "/var/log/maillog"):
            result = self._run(["tail", f"-{lines}", log])
            if result.ok() and result.stdout:
                return [
                    ln.strip() for ln in result.stdout.splitlines()
                    if any(kw in ln.lower() for kw in ("error", "fatal", "panic", "reject"))
                ][-20:]
        return []

    def _check_issues(self, active: bool, config: Dict, queue: int) -> List[str]:
        issues = []
        if not active:
            issues.append("postfix is not running")
        inbound_tls = config.get("smtpd_tls_security_level", "none")
        if inbound_tls not in _STRONG_TLS:
            issues.append(f"smtpd_tls_security_level={inbound_tls!r} — consider 'may' or 'encrypt'")
        outbound_tls = config.get("smtp_tls_security_level", "none")
        if outbound_tls not in _STRONG_TLS:
            issues.append(f"smtp_tls_security_level={outbound_tls!r} — consider 'may' or 'dane'")
        if queue > 100:
            issues.append(f"mail queue depth is high: {queue} messages")
        return issues
