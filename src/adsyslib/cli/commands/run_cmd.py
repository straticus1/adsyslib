import typer
from rich.console import Console
from adsyslib.core import run as core_run, ShellError

app = typer.Typer()
console = Console()

@app.command("exec")
def execute(
    command: str = typer.Argument(..., help="Command execution string"),
    cwd: str = typer.Option(None, help="Working directory"),
    check: bool = typer.Option(True, help="Fail on non-zero exit code"),
    capture: bool = typer.Option(False, help="Capture output instead of streaming to logs")
):
    """
    Run a shell command safely.
    """
    try:
        console.print(f"[bold blue]Running:[/bold blue] {command}")
        result = core_run(command, cwd=cwd, check=check, log_output=not capture)
        
        if capture:
            console.print("[bold green]STDOUT:[/bold green]")
            console.print(result.stdout)
            if result.stderr:
                console.print("[bold red]STDERR:[/bold red]")
                console.print(result.stderr)
        
        if result.ok():
            console.print(f"[bold green]Success[/bold green] ({result.duration:.2f}s)")
        else:
            console.print(f"[bold red]Failed[/bold red] (Exit: {result.exit_code})")
            raise typer.Exit(code=result.exit_code)

    except ShellError as e:
        console.print(f"[bold red]Error running command:[/bold red] {e}")
        raise typer.Exit(code=1)
