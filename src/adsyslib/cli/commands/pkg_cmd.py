import typer
import logging
from typing import List, Optional
from rich.console import Console
from adsyslib.packages import get_package_manager, Apt, Dnf
from adsyslib.core import run

app = typer.Typer()
console = Console()
logger = logging.getLogger(__name__)

def detect_manager():
    """Auto-detect package manager with user-friendly error."""
    try:
        return get_package_manager()
    except RuntimeError:
        console.print("[yellow]Could not detect package manager.[/yellow]")
        return None

@app.command("install")
def install_packages(
    packages: List[str] = typer.Argument(..., help="List of packages to install"),
    update: bool = typer.Option(False, "--update", "-u", help="Update lists before install"),
    manager: str = typer.Option("auto", help="Force manager: 'apt' or 'dnf'")
):
    """
    Install packages idempotently.
    """
    pm = None
    if manager == "apt":
        pm = Apt()
    elif manager == "dnf":
        pm = Dnf()
    else:
        pm = detect_manager()

    if not pm:
        console.print("[bold red]No supported package manager found.[/bold red]")
        raise typer.Exit(1)

    console.print(f"[bold blue] Installing packages:[/bold blue] {', '.join(packages)}")
    try:
        pm.install(packages, update=update)
        console.print("[bold green]Success[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Installation failed:[/bold red] {e}")
        raise typer.Exit(1)

@app.command("remove")
def remove_packages(packages: List[str]):
    """Uninstall packages."""
    pm = detect_manager()
    if not pm:
        raise typer.Exit(1)
    
    try:
        pm.uninstall(packages)
        console.print("[bold green]Removed successfully[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Removal failed:[/bold red] {e}")
        raise typer.Exit(1)
