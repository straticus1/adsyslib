import typer
import logging
from rich.logging import RichHandler
from typing import Optional
from adsyslib.logger import configure_logging
from adsyslib.cli.commands import run_cmd, pkg_cmd, container_cmd, cloud_cmd, iac_cmd, authentik_cmd

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

@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging"),
    log_file: Optional[str] = typer.Option(None, "--log-file", help="Path to audit log file")
):
    """
    Global configuration for adsys CLI.
    """
    level = logging.DEBUG if verbose else logging.INFO
    configure_logging(level=level, log_file=log_file)

if __name__ == "__main__":
    app()
