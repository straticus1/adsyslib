"""
adsyslib.host — SSH-based host scanning with pre-built service scanners.

Quick start:
    from adsyslib.host import ssh_to_host

    with ssh_to_host("mail.corp.com", user="root", key_file="~/.ssh/id_ed25519") as host:
        # Scan a specific service
        result = host.postfix.scan()
        print(result.issues)

        # Run all scanners at once
        report = host.scan_all()
        report.print_summary()
        print(report.to_json())

        # Scan a subset
        report = host.scan_all(services=["postfix", "dns"])

        # Run arbitrary commands
        r = host.run(["df", "-h"])
        print(r.stdout)
"""
from .session import HostReport, HostSession
from .scanners import ScanResult, ServiceScanner, PostfixScanner, DnsScanner, DovecotScanner, NginxScanner
from typing import Optional


def ssh_to_host(
    host: str,
    user: str = "root",
    port: int = 22,
    key_file: Optional[str] = None,
    password: Optional[str] = None,
    timeout: float = 30.0,
) -> HostSession:
    """
    Create a HostSession for the given host.

    Does NOT connect automatically — use as a context manager or call .connect() manually.

    Args:
        host:     Hostname or IP address.
        user:     SSH username (default: root).
        port:     SSH port (default: 22).
        key_file: Path to SSH private key. Falls back to ssh-agent / default keys.
        password: SSH password. Prefer key auth.
        timeout:  Connection + command timeout in seconds.

    Returns:
        HostSession (use as context manager for auto-connect/disconnect)
    """
    return HostSession(
        host=host, user=user, port=port,
        key_file=key_file, password=password, timeout=timeout,
    )


__all__ = [
    "ssh_to_host",
    "HostSession",
    "HostReport",
    "ScanResult",
    "ServiceScanner",
    "PostfixScanner",
    "DnsScanner",
    "DovecotScanner",
    "NginxScanner",
]
