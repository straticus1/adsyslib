"""
adsyslib.host — SSH/Docker/Kubernetes host scanning with pre-built service scanners.

The same scanners work across all target types — swap the shell, everything else
stays the same.

Quick start:
    from adsyslib.host import ssh_to_host, docker_container, kube_pod, scan_fleet
    from adsyslib.host import KubernetesClusterScanner

    # Bare metal / VM
    with ssh_to_host("mail.corp.com", user="root", key_file="~/.ssh/id_ed25519") as host:
        report = host.scan_all()
        report.print_summary()

    # Docker container
    with docker_container("nginx-proxy-1") as host:
        print(host.nginx.scan())

    # Kubernetes pod (in-pod service scan)
    with kube_pod("api-abc123", namespace="prod") as host:
        print(host.postfix.scan())

    # Kubernetes cluster health (API-level)
    scanner = KubernetesClusterScanner(context="prod-cluster")
    report = scanner.scan()
    report.print_summary()

    # Fleet scan — mixed targets, parallel
    targets = [
        ssh_to_host("web-01", user="root"),
        ssh_to_host("web-02", user="root"),
        docker_container("nginx-proxy"),
        kube_pod("api-abc123", namespace="prod"),
    ]
    fleet = scan_fleet(targets, services=["nginx", "postfix"], workers=8)
    fleet.print_summary()
    fleet.save("fleet_report.json")
"""
from typing import Optional

from .session import HostReport, HostSession
from .fleet import FleetReport, scan_fleet
from .docker_shell import DockerShell
from .kube_shell import KubeShell
from .scanners import (
    ScanResult, ServiceScanner,
    PostfixScanner, DnsScanner, DovecotScanner, NginxScanner,
)
from .scanners.k8s import KubernetesClusterScanner, ClusterReport


def ssh_to_host(
    host: str,
    user: str = "root",
    port: int = 22,
    key_file: Optional[str] = None,
    password: Optional[str] = None,
    timeout: float = 30.0,
) -> HostSession:
    """
    Create a HostSession over SSH.

    Use as a context manager for auto-connect/disconnect:
        with ssh_to_host("10.0.0.5", user="admin") as host:
            report = host.scan_all()
    """
    return HostSession(
        host=host, user=user, port=port,
        key_file=key_file, password=password, timeout=timeout,
    )


def docker_container(
    container: str,
    docker_cmd: str = "docker",
    user: Optional[str] = None,
) -> HostSession:
    """
    Create a HostSession that execs into a running Docker container.

    The container must already be running. No SSH needed.

    Args:
        container: Container name or ID.
        docker_cmd: Path to docker binary (default: "docker").
        user: User to exec as inside the container.
    """
    shell = DockerShell(container=container, docker_cmd=docker_cmd, user=user)
    return HostSession._from_shell(shell, label=f"docker:{container}")


def kube_pod(
    pod: str,
    namespace: str = "default",
    container: Optional[str] = None,
    context: Optional[str] = None,
    kubectl_cmd: str = "kubectl",
) -> HostSession:
    """
    Create a HostSession that execs into a running Kubernetes pod.

    Args:
        pod:        Pod name.
        namespace:  Kubernetes namespace (default: "default").
        container:  Container name within the pod (required for multi-container pods).
        context:    kubectl context to use (default: current context).
        kubectl_cmd: Path to kubectl binary.
    """
    shell = KubeShell(
        pod=pod, namespace=namespace, container=container,
        context=context, kubectl_cmd=kubectl_cmd,
    )
    return HostSession._from_shell(shell, label=f"k8s:{namespace}/{pod}")


__all__ = [
    # Factory functions
    "ssh_to_host",
    "docker_container",
    "kube_pod",
    "scan_fleet",
    # Session / report types
    "HostSession",
    "HostReport",
    "FleetReport",
    # K8s cluster (API-level)
    "KubernetesClusterScanner",
    "ClusterReport",
    # Scanner types (for custom scanners)
    "ScanResult",
    "ServiceScanner",
    "PostfixScanner",
    "DnsScanner",
    "DovecotScanner",
    "NginxScanner",
    # Shell types (for advanced use)
    "DockerShell",
    "KubeShell",
]
