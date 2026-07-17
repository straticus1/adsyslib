import logging
from typing import Optional

import typer

from adsyslib.cli.commands import (
    authentik_cmd,
    cloud_cmd,
    compliance_cmd,
    container_cmd,
    host_cmd,
    iac_cmd,
    pkg_cmd,
    run_cmd,
)
from adsyslib.logger import configure_logging

app = typer.Typer(
    name="adsys",
    help="adsyslib - Advanced Systems Library CLI. '10x' your sysadmin workflows.",
    add_completion=False,
    no_args_is_help=True
)

# Register sub-apps
app.add_typer(run_cmd.app, name="run", help="Execute shell commands safely")
app.add_typer(pkg_cmd.app, name="pkg", help="Manage system packages (apt/dnf)")
app.add_typer(container_cmd.app, name="container", help="Manage Docker containers")
app.add_typer(cloud_cmd.app, name="cloud", help="Manage Cloud Resources (AWS/OCI)")
app.add_typer(iac_cmd.app, name="iac", help="Infrastructure as Code (Terraform/Ansible)")
app.add_typer(authentik_cmd.app, name="authentik", help="Manage Authentik Identity Provider")
app.add_typer(compliance_cmd.app, name="compliance", help="Generate compliance audit packages")
app.add_typer(host_cmd.app, name="host", help="SSH to hosts and scan services")

@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging"),
    log_file: Optional[str] = typer.Option(None, "--log-file", help="Path to audit log file")
) -> None:
    """
    Global configuration for adsys CLI.
    """
    level = logging.DEBUG if verbose else logging.INFO
    configure_logging(level=level, log_file=log_file)

if __name__ == "__main__":
    app()
