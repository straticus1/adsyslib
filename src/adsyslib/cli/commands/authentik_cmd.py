import typer
import os
from rich.console import Console
from rich.table import Table
from typing import Optional, List
from adsyslib.authentik import AuthentikClient

app = typer.Typer()
console = Console()

def get_client() -> AuthentikClient:
    """Get Authentik client from environment or error."""
    base_url = os.environ.get("AUTHENTIK_URL")
    token = os.environ.get("AUTHENTIK_TOKEN")
    
    if not base_url or not token:
        console.print("[bold red]Error:[/bold red] Set AUTHENTIK_URL and AUTHENTIK_TOKEN environment variables.")
        raise typer.Exit(1)
    
    return AuthentikClient(base_url, token)

# ==================== USERS ====================

@app.command("list-users")
def list_users(search: Optional[str] = typer.Option(None, help="Search filter")):
    """List Authentik users."""
    client = get_client()
    users = client.list_users(search=search)
    
    table = Table(title="Authentik Users")
    table.add_column("ID", style="cyan")
    table.add_column("Username", style="green")
    table.add_column("Name")
    table.add_column("Email")
    table.add_column("Active")
    
    for u in users:
        table.add_row(
            str(u.get("pk")),
            u.get("username"),
            u.get("name"),
            u.get("email", ""),
            "✓" if u.get("is_active") else "✗"
        )
    console.print(table)

@app.command("create-user")
def create_user(
    username: str = typer.Argument(..., help="Username"),
    name: str = typer.Argument(..., help="Display name"),
    email: Optional[str] = typer.Option(None, help="Email address"),
    password: Optional[str] = typer.Option(None, help="Initial password")
):
    """Create a new Authentik user."""
    client = get_client()
    try:
        user = client.create_user(username=username, name=name, email=email)
        console.print(f"[bold green]Created user:[/bold green] {user.get('username')} (ID: {user.get('pk')})")
        
        if password:
            client.set_user_password(user.get("pk"), password)
            console.print("[green]Password set.[/green]")
    except Exception as e:
        console.print(f"[bold red]Failed:[/bold red] {e}")
        raise typer.Exit(1)

@app.command("delete-user")
def delete_user(user_id: int = typer.Argument(..., help="User ID")):
    """Delete an Authentik user."""
    client = get_client()
    try:
        client.delete_user(user_id)
        console.print(f"[bold green]Deleted user {user_id}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed:[/bold red] {e}")
        raise typer.Exit(1)

# ==================== GROUPS ====================

@app.command("list-groups")
def list_groups(search: Optional[str] = typer.Option(None, help="Search filter")):
    """List Authentik groups."""
    client = get_client()
    groups = client.list_groups(search=search)
    
    table = Table(title="Authentik Groups")
    table.add_column("UUID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Superuser")
    table.add_column("Members")
    
    for g in groups:
        table.add_row(
            str(g.get("pk")),
            g.get("name"),
            "✓" if g.get("is_superuser") else "✗",
            str(g.get("num_pk", len(g.get("users", []))))
        )
    console.print(table)

@app.command("create-group")
def create_group(
    name: str = typer.Argument(..., help="Group name"),
    superuser: bool = typer.Option(False, help="Grant superuser permissions")
):
    """Create a new Authentik group."""
    client = get_client()
    try:
        group = client.create_group(name=name, is_superuser=superuser)
        console.print(f"[bold green]Created group:[/bold green] {group.get('name')} (UUID: {group.get('pk')})")
    except Exception as e:
        console.print(f"[bold red]Failed:[/bold red] {e}")
        raise typer.Exit(1)

# ==================== APPLICATIONS ====================

@app.command("list-apps")
def list_apps():
    """List Authentik applications."""
    client = get_client()
    apps = client.list_applications()
    
    table = Table(title="Authentik Applications")
    table.add_column("Slug", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Provider")
    table.add_column("Launch URL")
    
    for a in apps:
        table.add_row(
            a.get("slug"),
            a.get("name"),
            str(a.get("provider")) if a.get("provider") else "None",
            a.get("meta_launch_url", "")
        )
    console.print(table)

@app.command("create-app")
def create_app(
    name: str = typer.Argument(..., help="Application name"),
    slug: str = typer.Argument(..., help="URL-safe slug"),
    launch_url: Optional[str] = typer.Option(None, help="Launch URL")
):
    """Create a new Authentik application."""
    client = get_client()
    try:
        app_obj = client.create_application(name=name, slug=slug, meta_launch_url=launch_url)
        console.print(f"[bold green]Created application:[/bold green] {app_obj.get('name')} ({app_obj.get('slug')})")
    except Exception as e:
        console.print(f"[bold red]Failed:[/bold red] {e}")
        raise typer.Exit(1)

# ==================== HEALTH ====================

@app.command("health")
def health():
    """Check Authentik health status."""
    client = get_client()
    if client.health_check():
        console.print("[bold green]Authentik is healthy ✓[/bold green]")
    else:
        console.print("[bold red]Authentik is not responding ✗[/bold red]")
        raise typer.Exit(1)
