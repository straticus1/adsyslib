"""
Fleet scanner — parallel scanning across mixed target types.

Accepts any mix of HostSession objects (SSH, Docker, Kubernetes pod)
and scans them concurrently. Returns a FleetReport with per-host
results and aggregate issue summary.

Usage:
    from adsyslib.host import ssh_to_host, docker_container, kube_pod, scan_fleet

    targets = [
        ssh_to_host("web-01.corp.com", user="root"),
        ssh_to_host("web-02.corp.com", user="root"),
        docker_container("nginx-proxy"),
        kube_pod("api-server-abc123", namespace="prod"),
    ]

    report = scan_fleet(targets, services=["nginx", "postfix"], workers=8)
    report.print_summary()
    report.save("fleet_report.json")
"""
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _scan_one(session, services: Optional[list[str]]):
    """Connect, scan, disconnect — designed to run in a thread."""
    try:
        session.connect()
        try:
            return session.host, session.scan_all(services=services), None
        finally:
            try:
                session.disconnect()
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Failed to scan {getattr(session, 'host', str(session))}: {e}")
        return getattr(session, "host", str(session)), None, str(e)


class FleetReport:
    """Aggregated results across all scanned targets."""

    def __init__(
        self,
        host_reports: dict[str, Any],  # host → HostReport
        errors: Optional[dict[str, str]] = None,  # host → error message
    ):
        self.host_reports = host_reports
        self.errors = errors or {}

    def ok(self) -> bool:
        return not self.errors and all(r.ok() for r in self.host_reports.values())

    def hosts_with_issues(self) -> list[str]:
        return [h for h, r in self.host_reports.items() if not r.ok()]

    def all_issues(self) -> dict[str, Any]:
        """Returns {host: {service: [issues]}} for every host that has issues."""
        result = {}
        for host, report in self.host_reports.items():
            issues = report.issues()
            if issues:
                result[host] = issues
        if self.errors:
            result["_connection_errors"] = self.errors
        return result

    def summary(self) -> dict[str, Any]:
        return {
            "total_hosts": len(self.host_reports) + len(self.errors),
            "scanned": len(self.host_reports),
            "failed_to_connect": len(self.errors),
            "hosts_ok": sum(1 for r in self.host_reports.values() if r.ok()),
            "hosts_with_issues": self.hosts_with_issues(),
            "connection_errors": self.errors,
            "hosts": {h: r.summary() for h, r in self.host_reports.items()},
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.summary(), indent=indent, default=str)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    def print_summary(self) -> None:
        total = len(self.host_reports) + len(self.errors)
        ok_count = sum(1 for r in self.host_reports.values() if r.ok())
        print(f"\n{'='*60}")
        print(f"Fleet Report: {ok_count}/{total} hosts OK")
        print(f"{'='*60}")

        for host, report in sorted(self.host_reports.items()):
            report.print_summary()

        if self.errors:
            print(f"\n  Connection failures ({len(self.errors)}):")
            for host, err in self.errors.items():
                print(f"    ! {host}: {err}")

    def __repr__(self) -> str:
        return (
            f"FleetReport({len(self.host_reports)} hosts, "
            f"{len(self.hosts_with_issues())} with issues, "
            f"{len(self.errors)} errors)"
        )


def scan_fleet(
    sessions: list[Any],
    services: Optional[list[str]] = None,
    workers: int = 10,
) -> FleetReport:
    """
    Scan a fleet of hosts/containers/pods in parallel.

    Args:
        sessions: List of HostSession objects (from ssh_to_host,
                  docker_container, or kube_pod). Sessions are
                  connected and disconnected automatically.
        services: Subset of scanners to run. None = all registered scanners.
        workers:  Max concurrent connections.

    Returns:
        FleetReport with per-host results and aggregate summary.
    """
    host_reports: dict[str, Any] = {}
    errors: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_scan_one, session, services): session
            for session in sessions
        }
        for future in as_completed(futures):
            host, report, error = future.result()
            if error:
                errors[host] = error
            else:
                host_reports[host] = report

    return FleetReport(host_reports=host_reports, errors=errors)
