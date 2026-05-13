import json
import typer
from typing import List, Optional

app = typer.Typer(help="Scan hosts, containers, and Kubernetes pods/clusters.")

VALID_SERVICES = ["postfix", "dns", "dovecot", "nginx"]


@app.command("scan")
def scan(
    # Target selection — mutually exclusive
    host: Optional[str] = typer.Argument(None, help="SSH hostname or IP"),
    container: Optional[str] = typer.Option(None, "--container", "-c", help="Docker container name/ID"),
    pod: Optional[str] = typer.Option(None, "--pod", "-p", help="Kubernetes pod name"),
    namespace: str = typer.Option("default", "--namespace", "-n", help="Kubernetes namespace"),
    kube_container: Optional[str] = typer.Option(None, "--kube-container", help="Container in pod (multi-container pods)"),
    kube_context: Optional[str] = typer.Option(None, "--kube-context", help="kubectl context"),
    # SSH options
    user: str = typer.Option("root", "--user", "-u", help="SSH username"),
    port: int = typer.Option(22, "--port", help="SSH port"),
    key_file: Optional[str] = typer.Option(None, "--key-file", "-i", help="SSH private key"),
    password: Optional[str] = typer.Option(None, "--password", help="SSH password"),
    # Scanner options
    services: List[str] = typer.Option(
        [], "--service", "-s",
        help="Service(s) to scan. Omit for all.",
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report to file"),
    fmt: str = typer.Option("text", "--format", "-f", help="Output format: text or json"),
):
    """
    Scan service health on a host, Docker container, or Kubernetes pod.

    Examples:

      # SSH to bare metal / VM
      adsys host scan web-01.corp.com --user root --key-file ~/.ssh/id_ed25519

      # Docker container
      adsys host scan --container nginx-proxy-1

      # Kubernetes pod
      adsys host scan --pod api-abc123 --namespace prod

      # Specific services only
      adsys host scan mail.corp.com -s postfix -s dns --format json
    """
    from adsyslib.host import ssh_to_host, docker_container, kube_pod

    # Exactly one target type
    targets_specified = sum([bool(host), bool(container), bool(pod)])
    if targets_specified != 1:
        typer.echo("Specify exactly one of: hostname, --container, or --pod", err=True)
        raise typer.Exit(code=1)

    unknown = set(services) - set(VALID_SERVICES)
    if unknown:
        typer.echo(f"Unknown service(s): {unknown}. Valid: {VALID_SERVICES}", err=True)
        raise typer.Exit(code=1)

    if container:
        typer.echo(f"Connecting to container: {container}")
        session = docker_container(container)
    elif pod:
        typer.echo(f"Connecting to pod: {namespace}/{pod}")
        session = kube_pod(pod, namespace=namespace, container=kube_container, context=kube_context)
    else:
        typer.echo(f"Connecting to {user}@{host}:{port} ...")
        session = ssh_to_host(host, user=user, port=port, key_file=key_file, password=password)

    try:
        with session as h:
            report = h.scan_all(services=services or None)
    except Exception as e:
        typer.echo(f"Failed: {e}", err=True)
        raise typer.Exit(code=1)

    if fmt == "json":
        typer.echo(report.to_json())
    else:
        report.print_summary()

    if output:
        with open(output, "w") as f:
            f.write(report.to_json())
        typer.echo(f"\nReport saved: {output}")

    if not report.ok():
        raise typer.Exit(code=2)


@app.command("cluster")
def cluster(
    context: Optional[str] = typer.Option(None, "--context", help="kubectl context"),
    namespaces: List[str] = typer.Option([], "--namespace", "-n", help="Namespace(s) to scan. Omit for all."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report to file"),
    fmt: str = typer.Option("text", "--format", "-f", help="Output format: text or json"),
):
    """
    Scan a Kubernetes cluster at the API level.

    Checks node health, failing pods, deployment status, PVC binding,
    and warning events. Does not exec into pods.

    Examples:

      adsys host cluster
      adsys host cluster --context prod-cluster
      adsys host cluster --namespace prod --namespace staging --format json
    """
    from adsyslib.host import KubernetesClusterScanner

    ctx_label = context or "current context"
    typer.echo(f"Scanning cluster [{ctx_label}] ...")

    try:
        scanner = KubernetesClusterScanner(
            context=context,
            namespaces=namespaces or None,
        )
        report = scanner.scan()
    except Exception as e:
        typer.echo(f"Cluster scan failed: {e}", err=True)
        raise typer.Exit(code=1)

    if fmt == "json":
        typer.echo(report.to_json())
    else:
        report.print_summary()

    if output:
        with open(output, "w") as f:
            f.write(report.to_json())
        typer.echo(f"\nReport saved: {output}")

    if not report.ok():
        raise typer.Exit(code=2)


@app.command("fleet")
def fleet(
    hosts: List[str] = typer.Argument(..., help="Hostnames or IPs to scan over SSH"),
    user: str = typer.Option("root", "--user", "-u"),
    key_file: Optional[str] = typer.Option(None, "--key-file", "-i"),
    services: List[str] = typer.Option([], "--service", "-s", help="Services to scan. Omit for all."),
    workers: int = typer.Option(10, "--workers", "-w", help="Parallel connections"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
    fmt: str = typer.Option("text", "--format", "-f", help="text or json"),
):
    """
    Scan a fleet of hosts in parallel over SSH.

    Examples:

      adsys host fleet web-01 web-02 web-03 --user admin --key-file ~/.ssh/id_ed25519

      adsys host fleet web-01 web-02 -s nginx -s postfix --workers 20 --format json
    """
    from adsyslib.host import ssh_to_host, scan_fleet

    sessions = [ssh_to_host(h, user=user, key_file=key_file) for h in hosts]
    typer.echo(f"Scanning {len(sessions)} host(s) with {workers} workers ...")

    report = scan_fleet(sessions, services=services or None, workers=workers)

    if fmt == "json":
        typer.echo(report.to_json())
    else:
        report.print_summary()

    if output:
        report.save(output)
        typer.echo(f"\nReport saved: {output}")

    if not report.ok():
        raise typer.Exit(code=2)
