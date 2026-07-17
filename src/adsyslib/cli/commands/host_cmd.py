from typing import List, Optional

import typer

app = typer.Typer(help="Scan hosts, containers, and Kubernetes pods/clusters.")

VALID_SERVICES = ["apache", "dns", "dovecot", "mysql", "nginx", "postgresql", "postfix", "redis", "spamassassin"]


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
    from adsyslib.host import docker_container, kube_pod, ssh_to_host

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
        if not host:
            typer.echo("Provide a HOST argument (or --container / --pod).", err=True)
            raise typer.Exit(code=1)
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
    hosts: List[str] = typer.Argument(None, help="SSH hostnames or IPs"),
    user: str = typer.Option("root", "--user", "-u", help="SSH username"),
    key_file: Optional[str] = typer.Option(None, "--key-file", "-i", help="SSH private key"),
    containers: List[str] = typer.Option([], "--container", "-c", help="Docker container name/ID (repeatable)"),
    pods: List[str] = typer.Option([], "--pod", "-p", help="Kubernetes pod name (repeatable)"),
    pod_namespace: str = typer.Option("default", "--pod-namespace", help="Namespace for --pod targets"),
    kube_context: Optional[str] = typer.Option(None, "--kube-context", help="kubectl context for pod targets"),
    services: List[str] = typer.Option([], "--service", "-s", help="Services to scan. Omit for all."),
    workers: int = typer.Option(10, "--workers", "-w", help="Parallel connections"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
    fmt: str = typer.Option("text", "--format", "-f", help="text or json"),
):
    """
    Scan a mixed fleet of SSH hosts, Docker containers, and Kubernetes pods in parallel.

    Examples:

      # SSH only
      adsys host fleet web-01 web-02 web-03 --user admin --key-file ~/.ssh/id_ed25519

      # Mixed fleet
      adsys host fleet web-01 --container nginx-proxy --pod api-abc123 --pod-namespace prod

      # Specific services
      adsys host fleet web-01 web-02 -s nginx -s postfix --workers 20 --format json
    """
    from adsyslib.host import docker_container, kube_pod, scan_fleet, ssh_to_host

    sessions = []
    for h in (hosts or []):
        sessions.append(ssh_to_host(h, user=user, key_file=key_file))
    for c in containers:
        sessions.append(docker_container(c))
    for p in pods:
        sessions.append(kube_pod(p, namespace=pod_namespace, context=kube_context))

    if not sessions:
        typer.echo("Specify at least one target: hostname, --container, or --pod", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Scanning {len(sessions)} target(s) with {workers} workers ...")

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
