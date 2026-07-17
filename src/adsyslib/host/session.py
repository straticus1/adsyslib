"""
HostSession — shell-agnostic service scanner session.

The same session works over SSH, docker exec, or kubectl exec —
swap in the appropriate shell and all scanners just work.

Usage:
    # SSH to a bare metal / VM host
    with ssh_to_host("mail.corp.com", user="root") as host:
        report = host.scan_all()
        report.print_summary()

    # Scan a running Docker container
    with docker_container("nginx-proxy-1") as host:
        print(host.nginx.scan())

    # Scan a Kubernetes pod
    with kube_pod("nginx-6d4cf56db6-xkbzr", namespace="prod") as host:
        print(host.nginx.scan())

    # Run an arbitrary command on any target
    with ssh_to_host("box.corp.com", user="ops") as host:
        r = host.run(["systemctl", "list-units", "--failed"])
        print(r.stdout)
"""
import json
import logging
from typing import Any, Dict, List, Optional

from adsyslib.remote import RemoteShell

from .scanners import (
    ApacheScanner,
    DnsScanner,
    DovecotScanner,
    MysqlScanner,
    NginxScanner,
    PostfixScanner,
    PostgresScanner,
    RedisScanner,
    ScanResult,
    SpamassassinScanner,
)

logger = logging.getLogger(__name__)

# Registry: name → scanner class. Add new scanners here.
_SCANNER_REGISTRY = {
    "apache":        ApacheScanner,
    "dns":           DnsScanner,
    "dovecot":       DovecotScanner,
    "mysql":         MysqlScanner,
    "nginx":         NginxScanner,
    "postgresql":    PostgresScanner,
    "postfix":       PostfixScanner,
    "redis":         RedisScanner,
    "spamassassin":  SpamassassinScanner,
}


class HostSession:
    """
    Shell-agnostic session with lazy-initialized service scanners.

    Accepts any shell object that implements run/read_text/connect/disconnect.
    Use the factory functions (ssh_to_host, docker_container, kube_pod)
    rather than instantiating directly.
    """

    def __init__(
        self,
        host: str,
        user: str = "root",
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

    @classmethod
    def _from_shell(cls, shell: Any, label: Optional[str] = None) -> "HostSession":
        """Build a HostSession around any compatible shell object."""
        obj = cls.__new__(cls)
        obj.host = label if label is not None else str(getattr(shell, "host", shell))
        obj.user = getattr(shell, "user", "")
        obj._shell = shell
        obj._scanners = {}
        return obj

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> "HostSession":
        self._shell.connect()
        logger.info(f"Connected to {self.host}")
        return self

    def disconnect(self) -> None:
        self._shell.disconnect()

    def __enter__(self) -> "HostSession":
        return self.connect()

    def __exit__(self, *_) -> None:
        self.disconnect()

    # ------------------------------------------------------------------
    # Raw execution
    # ------------------------------------------------------------------

    def run(self, cmd, check: bool = False):
        return self._shell.run(cmd, check=check)

    def read_text(self, path: str) -> Optional[str]:
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
    def apache(self) -> ApacheScanner:
        return self._scanner("apache")

    @property
    def dns(self) -> DnsScanner:
        return self._scanner("dns")

    @property
    def dovecot(self) -> DovecotScanner:
        return self._scanner("dovecot")

    @property
    def mysql(self) -> MysqlScanner:
        return self._scanner("mysql")

    @property
    def nginx(self) -> NginxScanner:
        return self._scanner("nginx")

    @property
    def postgresql(self) -> PostgresScanner:
        return self._scanner("postgresql")

    @property
    def postfix(self) -> PostfixScanner:
        return self._scanner("postfix")

    @property
    def redis(self) -> RedisScanner:
        return self._scanner("redis")

    @property
    def spamassassin(self) -> SpamassassinScanner:
        return self._scanner("spamassassin")

    # ------------------------------------------------------------------
    # Scan all
    # ------------------------------------------------------------------

    def scan_all(self, services: Optional[List[str]] = None) -> "HostReport":
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
        return f"HostSession({self.host})"


class HostReport:
    """Aggregated scan results for a single host/container/pod."""

    def __init__(self, host: str, results: Dict[str, ScanResult]):
        self.host = host
        self.results = results

    def ok(self) -> bool:
        return all(r.ok() for r in self.results.values())

    def issues(self) -> Dict[str, List[str]]:
        return {svc: r.issues for svc, r in self.results.items() if r.issues}

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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "services": {svc: r.to_dict() for svc, r in self.results.items()},
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

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
