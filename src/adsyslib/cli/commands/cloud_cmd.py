import typer
import os
from rich.console import Console
from rich.table import Table
from typing import Optional
from adsyslib.cloud import get_cloud_provider

app = typer.Typer()
console = Console()

def get_provider(provider_type: str, profile: Optional[str] = None, region: Optional[str] = None):
    try:
        return get_cloud_provider(provider_type, profile=profile, region=region)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

@app.command("list-instances")
def list_instances(
    provider: str = typer.Option(..., help="Cloud provider: aws or oracle"),
    region: Optional[str] = typer.Option(None, help="Region to list instances in"),
    profile: Optional[str] = typer.Option(None, help="Cloud profile name")
):
    """List compute instances."""
    cp = get_provider(provider, profile)
    try:
        instances = cp.list_instances(region=region)
        table = Table(title=f"Instances ({provider.upper()})")
        table.add_column("ID", style="cyan")
        table.add_column("State", style="green")
        table.add_column("Type/Shape")
        table.add_column("Public IP")
        
        for inst in instances:
            table.add_row(
                inst.get("id"),
                inst.get("state"),
                inst.get("type") or inst.get("shape"),
                inst.get("public_ip") or "N/A"
            )
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error listing instances:[/bold red] {e}")
        raise typer.Exit(1)

@app.command("upload")
def upload_file(
    provider: str = typer.Option(..., help="Cloud provider: aws or oracle"),
    bucket: str = typer.Argument(..., help="Target bucket name"),
    file: str = typer.Argument(..., help="Local file path"),
    profile: Optional[str] = typer.Option(None, help="Cloud profile name")
):
    """Upload file to object storage."""
    cp = get_provider(provider, profile)
    try:
        cp.upload_file(bucket, file)
        console.print(f"[bold green]Uploaded {file} to {bucket}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Upload failed:[/bold red] {e}")
        raise typer.Exit(1)
