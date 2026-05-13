"""
SpamAssassin scanner — spamd status, version, rule freshness, bayes status.
"""
import re
from typing import Any, Dict, List

from .base import ScanResult, ServiceScanner


class SpamassassinScanner(ServiceScanner):
    service_name = "spamassassin"

    def scan(self) -> ScanResult:
        active = self._is_active("spamassassin") or self._is_active("spamd")
        version = self._version(["spamassassin", "--version"])
        rule_age_days = self._rule_age()
        bayes = self._bayes_status()
        issues = self._check_issues(active, rule_age_days, bayes)

        return ScanResult(
            service="spamassassin",
            active=active,
            version=version,
            config={"bayes": bayes},
            issues=issues,
            metrics={"rule_age_days": rule_age_days},
        )

    def _rule_age(self) -> int:
        """Return days since sa-update last ran, or -1 if unknown."""
        for path in ("/var/lib/spamassassin", "/usr/share/spamassassin"):
            r = self._run(["find", path, "-name", "*.cf", "-newer", "/etc/cron.daily/spamassassin"])
            if r.ok():
                # If recent .cf files exist, rules are fresh
                return 0 if r.stdout.strip() else 8
        # Fallback: check sa-update timestamp file
        for ts_path in ("/var/lib/spamassassin/sa-update-running", "/var/cache/spamassassin/sa-update-running"):
            r = self._run(["stat", "-c", "%Y", ts_path])
            if r.ok() and r.stdout.strip():
                try:
                    import time
                    mtime = int(r.stdout.strip())
                    return max(0, int((time.time() - mtime) / 86400))
                except ValueError:
                    pass
        return -1

    def _bayes_status(self) -> Dict[str, Any]:
        r = self._run(["sa-learn", "--dump", "magic"])
        if not r.ok():
            return {"available": False}
        result: Dict[str, Any] = {"available": True}
        for line in r.stdout.splitlines():
            m = re.match(r"^0\.\d+\s+\d+\s+(\w+)\s+(.+)$", line.strip())
            if m:
                result[m.group(1).lower()] = m.group(2).strip()
        return result

    def _check_issues(self, active: bool, rule_age: int, bayes: Dict) -> List[str]:
        issues = []
        if not active:
            issues.append("spamd is not running")
        if rule_age > 7:
            issues.append(f"SpamAssassin rules may be stale (last update: ~{rule_age} days ago)")
        elif rule_age == -1:
            issues.append("Could not determine SpamAssassin rule update age")
        if not bayes.get("available"):
            issues.append("Bayes database not accessible via sa-learn")
        return issues
