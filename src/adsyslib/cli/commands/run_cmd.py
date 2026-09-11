"""Command execution with machine-readable results and faithful exit codes."""

import json
from dataclasses import asdict
from typing import Optional

import typer

from adsyslib.core import ShellError, ShellTimeoutError
from adsyslib.core import run as core_run

app = typer.Typer()


@app.command("exec")
def execute(
    command: str = typer.Argument(
        ..., help="Command string, parsed as literal arguments by default"
    ),
    cwd: Optional[str] = typer.Option(None, help="Working directory"),
    check: bool = typer.Option(True, help="Raise on command failure"),
    capture: bool = typer.Option(False, help="Capture output (retained for compatibility)"),
    timeout: Optional[float] = typer.Option(None, min=0.001, help="Deadline in seconds"),
    shell: bool = typer.Option(False, help="Explicitly enable shell syntax"),
    json_output: bool = typer.Option(False, "--json", help="Emit a JSON CommandResult"),
    sensitive: bool = typer.Option(False, help="Redact command metadata and suppress debug output"),
) -> None:
    """Execute a command, print its output and preserve its exit status."""
    try:
        result = core_run(
            command,
            cwd=cwd,
            check=check,
            timeout=timeout,
            shell=shell,
            sensitive=sensitive,
            log_output=False,
            strip_output=False,
        )
    except ShellError as exc:
        result = exc.result
    except ShellTimeoutError:
        typer.echo("Command timed out", err=True)
        raise typer.Exit(124) from None
    except (ValueError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from None
    if json_output:
        typer.echo(json.dumps(asdict(result)))
    else:
        typer.echo(result.stdout, nl=False)
        typer.echo(result.stderr, nl=False, err=True)
    raise typer.Exit(result.exit_code if result.exit_code >= 0 else 128 - result.exit_code)
