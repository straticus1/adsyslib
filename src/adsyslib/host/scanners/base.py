"""
ServiceScanner base class.

Each scanner wraps a RemoteShell and implements scan() → ScanResult.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ScanResult:
    service: str
    active: bool
    version: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    issues: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)

    def ok(self) -> bool:
        return self.active and not self.issues

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service": self.service,
            "active": self.active,
            "version": self.version,
            "config": self.config,
            "issues": self.issues,
            "metrics": self.metrics,
        }


class ServiceScanner:
    """
    Base for all service scanners.
    Subclasses implement scan() and set service_name.
    """
    service_name: str = ""

    def __init__(self, shell):
        self._shell = shell

    def _run(self, cmd, check: bool = False):
        return self._shell.run(cmd, check=check)

    def _is_active(self, service: str) -> bool:
        return self._run(["systemctl", "is-active", service]).stdout.strip() == "active"

    def _version(self, cmd) -> str:
        r = self._run(cmd)
        return r.stdout.splitlines()[0].strip() if r.ok() and r.stdout else ""

    def scan(self) -> ScanResult:
        raise NotImplementedError
