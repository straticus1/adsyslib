import typer
from rich.console import Console
from rich.table import Table
from typing import List, Optional
from adsyslib.container.manager import DockerManager

app = typer.Typer()
console = Console()

def get_manager():
    dm = DockerManager()
    if not dm.client:
        console.print("[bold red]Docker daemon not reachable.[/bold red]")
        raise typer.Exit(1)
    return dm

@app.command("run")
def run_container(
    image: str,
    name: Optional[str] = typer.Option(None, help="Container name"),
    ports: Optional[List[str]] = typer.Option(None, help="Port mappings host:container"),
    env: Optional[List[str]] = typer.Option(None, help="Env vars KEY=VALUE"),
    detach: bool = typer.Option(True, help="Run in background"),
    wait_log: Optional[str] = typer.Option(None, help="Wait for specific log pattern")
):
    """Run a docker container."""
    dm = get_manager()
    
    # Parse ports
    port_map = {}
    if ports:
        for p in ports:
            if ":" in p:
                host, container = p.split(":")
                port_map[container] = host # docker-py format is container_port -> host_port
    
    # Parse env
    env_map = {}
    if env:
        for e in env:
            if "=" in e:
                k, v = e.split("=", 1)
                env_map[k] = v

    try:
        container = dm.run_container(
            image=image,
            name=name,
            detach=detach,
            ports=port_map,
            env=env_map,
            wait_for_log=wait_log
        )
        console.print(f"[bold green]Started container:[/bold green] {container.short_id} ({container.name})")
    except Exception as e:
        console.print(f"[bold red]Failed to start container:[/bold red] {e}")
        raise typer.Exit(1)

@app.command("stop")
def stop_container(name: str):
    """Stop a container."""
    dm = get_manager()
    dm.stop_container(name)
    console.print(f"[bold green]Stopped {name}[/bold green]")

@app.command("ps")
def list_containers():
    """List running containers."""
    dm = get_manager()
    containers = dm.client.containers.list()
    
    table = Table(title="Running Containers")
    table.add_column("ID", style="cyan")
    table.add_column("Image", style="magenta")
    table.add_column("Name", style="green")
    table.add_column("Status")
    
    for c in containers:
        table.add_row(c.short_id, str(c.image), c.name, c.status)
        
    console.print(table)

@app.command("gen-dockerfile")
def generate_dockerfile(
    image: str = typer.Option("python:3.9-slim", help="Base image"),
    distro: str = typer.Option("debian", help="Distro family: debian, rhel, alpine"),
    packages: List[str] = typer.Option([], help="Packages to install"),
    out: str = typer.Option("Dockerfile", help="Output path")
):
    """Generate a production-ready Dockerfile with installed packages."""
    from adsyslib.container.builder import PackageAwareBuilder
    
    console.print(f"[bold blue]Generating Dockerfile for {distro} based on {image}...[/bold blue]")
    builder = PackageAwareBuilder(image, distro_family=distro)
    
    if packages:
        builder.install(packages)
        
    # Example generic setup
    builder.workdir("/app")
    builder.env("PYTHONUNBUFFERED", "1")
    
    builder.write(out)
    console.print(f"[bold green]Wrote {out}[/bold green]")
