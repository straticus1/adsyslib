"""
HostSession — SSH connection with pre-built service scanners.

Usage:
    # Context manager (auto-connect/disconnect)
    with ssh_to_host("mail.corp.com", user="root") as host:
        print(host.postfix.scan())
        print(host.dns.scan())
        report = host.scan_all()

    # Manual connect/disconnect
    host = ssh_to_host("10.0.0.5", user="admin", key_file="~/.ssh/id_ed25519")
    host.connect()
    result = host.postfix.scan()
    host.disconnect()

    # Run an arbitrary command
    with ssh_to_host("box.corp.com", user="ops") as host:
        r = host.run(["systemctl", "list-units", "--failed"])
        print(r.stdout)
"""
import json
import logging
from typing import Any, Dict, List, Optional

from adsyslib.remote import RemoteShell
from .scanners import DnsScanner, DovecotScanner, NginxScanner, PostfixScanner, ScanResult

logger = logging.getLogger(__name__)

# Registry: name → scanner class. Add new scanners here.
_SCANNER_REGISTRY = {
    "postfix": PostfixScanner,
    "dns":     DnsScanner,
    "dovecot": DovecotScanner,
    "nginx":   NginxScanner,
}


class HostSession:
    """
    SSH session with lazy-initialized service scanners.

    Attributes are resolved on first access so you only pay for
    the connection, not for instantiating every scanner up front.
    """

    def __init__(
        self,
        host: str,
        user: str,
        port: int = 22,
        key_file: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.host = host
        self.user = user
        self._shell = RemoteShell(
            host=host, user=user, port=port,
            key_file=key_file, password=password, timeout=timeout,
        )
        self._scanners: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> "HostSession":
        self._shell.connect()
        logger.info(f"Connected to {self.user}@{self.host}")
        return self

    def disconnect(self) -> None:
        self._shell.disconnect()

    def __enter__(self) -> "HostSession":
        return self.connect()

    def __exit__(self, *_) -> None:
        self.disconnect()

    # ------------------------------------------------------------------
    # Raw command execution
    # ------------------------------------------------------------------

    def run(self, cmd, check: bool = False):
        """Run an arbitrary command on the remote host."""
        return self._shell.run(cmd, check=check)

    def read_text(self, path: str) -> Optional[str]:
        """Read a remote file as text."""
        return self._shell.read_text(path)

    # ------------------------------------------------------------------
    # Scanner access (lazy, cached)
    # ------------------------------------------------------------------

    def _scanner(self, name: str):
        if name not in self._scanners:
            cls = _SCANNER_REGISTRY.get(name)
            if cls is None:
                raise AttributeError(f"No scanner registered for '{name}'")
            self._scanners[name] = cls(self._shell)
        return self._scanners[name]

    @property
    def postfix(self) -> PostfixScanner:
        return self._scanner("postfix")

    @property
    def dns(self) -> DnsScanner:
        return self._scanner("dns")

    @property
    def dovecot(self) -> DovecotScanner:
        return self._scanner("dovecot")

    @property
    def nginx(self) -> NginxScanner:
        return self._scanner("nginx")

    # ------------------------------------------------------------------
    # Scan all registered services
    # ------------------------------------------------------------------

    def scan_all(self, services: Optional[List[str]] = None) -> "HostReport":
        """
        Run all (or a named subset of) scanners and return a HostReport.

        Args:
            services: list of scanner names to run, e.g. ["postfix", "dns"].
                      Defaults to all registered scanners.
        """
        targets = services or list(_SCANNER_REGISTRY)
        results: Dict[str, ScanResult] = {}
        for name in targets:
            try:
                results[name] = self._scanner(name).scan()
            except Exception as e:
                logger.warning(f"Scanner '{name}' failed on {self.host}: {e}")
                results[name] = ScanResult(
                    service=name, active=False,
                    issues=[f"Scanner error: {e}"],
                )
        return HostReport(host=self.host, results=results)

    def __repr__(self) -> str:
        return f"HostSession({self.user}@{self.host})"


class HostReport:
    """Aggregated scan results for a single host."""

    def __init__(self, host: str, results: Dict[str, ScanResult]):
        self.host = host
        self.results = results

    def ok(self) -> bool:
        return all(r.ok() for r in self.results.values())

    def issues(self) -> Dict[str, List[str]]:
        return {
            svc: r.issues
            for svc, r in self.results.items()
            if r.issues
        }

    def summary(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "ok": self.ok(),
            "services": {
                svc: {
                    "active": r.active,
                    "version": r.version,
                    "issues": r.issues,
                }
                for svc, r in self.results.items()
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            {
                "host": self.host,
                "services": {svc: r.to_dict() for svc, r in self.results.items()},
            },
            indent=indent,
            default=str,
        )

    def print_summary(self) -> None:
        status = "OK" if self.ok() else "ISSUES FOUND"
        print(f"\n=== {self.host} [{status}] ===")
        for svc, result in self.results.items():
            state = "active" if result.active else "INACTIVE"
            ver = f" ({result.version})" if result.version else ""
            print(f"  {svc:<12} {state}{ver}")
            for issue in result.issues:
                print(f"    ! {issue}")

    def __repr__(self) -> str:
        n_issues = sum(len(r.issues) for r in self.results.values())
        return f"HostReport({self.host}, {len(self.results)} services, {n_issues} issues)"
