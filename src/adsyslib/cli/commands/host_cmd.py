import json
import typer
from typing import List, Optional

app = typer.Typer(help="SSH to a host and scan running services.")

VALID_SERVICES = ["postfix", "dns", "dovecot", "nginx"]


@app.command("scan")
def scan(
    host: str = typer.Argument(..., help="Hostname or IP to scan"),
    user: str = typer.Option("root", "--user", "-u", help="SSH username"),
    port: int = typer.Option(22, "--port", "-p", help="SSH port"),
    key_file: Optional[str] = typer.Option(None, "--key-file", "-i", help="SSH private key path"),
    password: Optional[str] = typer.Option(None, "--password", help="SSH password"),
    services: List[str] = typer.Option(
        [], "--service", "-s",
        help="Service(s) to scan: postfix, dns, dovecot, nginx. Omit for all.",
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report to file"),
    fmt: str = typer.Option("text", "--format", "-f", help="Output format: text or json"),
):
    """
    SSH to a host and scan service health, config, and known issues.

    Examples:

      adsys host scan mail.corp.com

      adsys host scan 10.0.0.5 --user admin --key-file ~/.ssh/id_ed25519 --service postfix --service dns

      adsys host scan mail.corp.com --format json --output report.json
    """
    from adsyslib.host import ssh_to_host

    unknown = set(services) - set(VALID_SERVICES)
    if unknown:
        typer.echo(f"Unknown service(s): {unknown}. Valid: {VALID_SERVICES}", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Connecting to {user}@{host}:{port} ...")
    try:
        with ssh_to_host(host, user=user, port=port, key_file=key_file, password=password) as h:
            report = h.scan_all(services=services or None)
    except Exception as e:
        typer.echo(f"Connection failed: {e}", err=True)
        raise typer.Exit(code=1)

    if fmt == "json":
        out = report.to_json()
        typer.echo(out)
    else:
        report.print_summary()

    if output:
        with open(output, "w") as f:
            f.write(report.to_json())
        typer.echo(f"\nReport saved: {output}")

    if not report.ok():
        raise typer.Exit(code=2)
