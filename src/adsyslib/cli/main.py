import json
import logging
from importlib.metadata import version
from typing import Any, Optional

import typer
from typer.core import TyperGroup

from adsyslib.cli.commands import (
    authentik_cmd,
    cloud_cmd,
    compliance_cmd,
    container_cmd,
    host_cmd,
    iac_cmd,
    k8s_cmd,
    pkg_cmd,
    run_cmd,
)
from adsyslib.core import AdsysError, ShellError
from adsyslib.diagnostics import capabilities
from adsyslib.logger import configure_logging


class CommandGroup(TyperGroup):
    """Render operational failures without tracebacks or Rich interpretation."""

    def invoke(self, ctx: Any) -> Any:
        try:
            return super().invoke(ctx)
        except (AdsysError, ImportError, OSError, ValueError) as exc:
            typer.echo(f"Error: {exc}", err=True)
            code = exc.result.exit_code if isinstance(exc, ShellError) else 1
            raise typer.Exit(code if code > 0 else 1) from None


app = typer.Typer(
    cls=CommandGroup,
    name="adsys",
    help="System administration, infrastructure management, and compliance evidence.",
    add_completion=False,
    no_args_is_help=True,
)


@app.command("doctor")
def doctor() -> None:
    """Show installed integrations and command availability as JSON."""
    typer.echo(json.dumps(capabilities(), indent=2))


@app.command("version")
def show_version() -> None:
    """Print the installed version."""
    typer.echo(version("adsyslib"))


# Register sub-apps
app.add_typer(run_cmd.app, name="run", help="Execute shell commands safely")
app.add_typer(pkg_cmd.app, name="pkg", help="Manage system packages (apt/dnf)")
app.add_typer(container_cmd.app, name="container", help="Manage Docker containers")
app.add_typer(cloud_cmd.app, name="cloud", help="Manage Cloud Resources (AWS/OCI)")
app.add_typer(iac_cmd.app, name="iac", help="Infrastructure as Code (Terraform/Ansible)")
app.add_typer(authentik_cmd.app, name="authentik", help="Manage Authentik Identity Provider")
app.add_typer(compliance_cmd.app, name="compliance", help="Generate compliance audit packages")
app.add_typer(k8s_cmd.app, name="k8s", help="Manage Kubernetes resources")
app.add_typer(host_cmd.app, name="host", help="SSH to hosts and scan services")


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging"),
    log_file: Optional[str] = typer.Option(None, "--log-file", help="Path to audit log file"),
) -> None:
    """
    Global configuration for adsys CLI.
    """
    level = logging.DEBUG if verbose else logging.INFO
    configure_logging(level=level, log_file=log_file)


if __name__ == "__main__":
    app()
