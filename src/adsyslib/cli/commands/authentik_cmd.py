import typer
import os
import json
from rich.console import Console
from rich.table import Table
from typing import Optional, List
from adsyslib.authentik import (
    AuthentikClient,
    AuthentikOAuthManager,
    OAuthProviderConfig,
    load_providers_from_json,
    generate_env_file
)

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

# ==================== OAUTH PROVIDERS ====================

@app.command("oauth-create")
def oauth_create(
    app_name: str = typer.Argument(..., help="Application name"),
    client_id: str = typer.Argument(..., help="OAuth client ID"),
    redirect_uris: List[str] = typer.Option(..., "--redirect-uri", "-r", help="Redirect URI (can specify multiple)"),
    launch_url: str = typer.Option(..., "--launch-url", help="Application launch URL"),
    app_slug: str = typer.Option(None, "--slug", help="Application slug (defaults to lowercase app_name)"),
    client_type: str = typer.Option("confidential", "--type", help="Client type: confidential or public"),
    container: str = typer.Option("authentik-server-prod", "--container", help="Docker container name"),
    output_env: Optional[str] = typer.Option(None, "--output-env", help="Output .env file with credentials")
):
    """Create an OAuth2 provider via Django ORM."""
    if not app_slug:
        app_slug = app_name.lower().replace(' ', '-')

    config = OAuthProviderConfig(
        app_name=app_name,
        app_slug=app_slug,
        client_id=client_id,
        redirect_uris=redirect_uris,
        launch_url=launch_url,
        client_type=client_type
    )

    manager = AuthentikOAuthManager(container_name=container)
    
    try:
        result = manager.create_provider(config)
        
        console.print(f"[bold green]✓ Created OAuth provider:[/bold green] {result['app_name']}")
        console.print(f"  Client ID: [cyan]{result['client_id']}[/cyan]")
        console.print(f"  Client Secret: [yellow]{result['client_secret']}[/yellow]")
        console.print(f"  Client Type: {result['client_type']}")
        console.print(f"  Redirect URIs: {', '.join(result['redirect_uris'])}")
        
        if output_env:
            generate_env_file([result], output_env)
            console.print(f"[green]✓ Credentials saved to {output_env}[/green]")
            
    except Exception as e:
        console.print(f"[bold red]Failed:[/bold red] {e}")
        raise typer.Exit(1)


@app.command("oauth-bulk-create")
def oauth_bulk_create(
    config_file: str = typer.Argument(..., help="JSON config file with provider definitions"),
    container: str = typer.Option("authentik-server-prod", "--container", help="Docker container name"),
    output_env: Optional[str] = typer.Option(".env", "--output-env", help="Output .env file"),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Output JSON file with all secrets")
):
    """Create multiple OAuth providers from JSON config."""
    try:
        configs = load_providers_from_json(config_file)
        console.print(f"Loaded {len(configs)} provider configurations from {config_file}")
        
        manager = AuthentikOAuthManager(container_name=container)
        results = manager.create_providers_bulk(configs)
        
        # Show summary
        success_count = len([r for r in results if 'error' not in r])
        failed_count = len(results) - success_count
        
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"  ✓ Created: {success_count}")
        if failed_count > 0:
            console.print(f"  ✗ Failed: {failed_count}")
        
        # Show table
        table = Table(title="OAuth Providers Created")
        table.add_column("App Name", style="green")
        table.add_column("Client ID", style="cyan")
        table.add_column("Type")
        table.add_column("Status")
        
        for result in results:
            if 'error' in result:
                table.add_row(
                    result.get('app_name', 'Unknown'),
                    result.get('client_id', 'Unknown'),
                    "-",
                    f"[red]✗ {result['error']}[/red]"
                )
            else:
                table.add_row(
                    result['app_name'],
                    result['client_id'],
                    result['client_type'],
                    "[green]✓[/green]"
                )
        
        console.print(table)
        
        # Save outputs
        if output_env:
            generate_env_file(results, output_env)
            console.print(f"\n[green]✓ Credentials saved to {output_env}[/green]")
        
        if output_json:
            with open(output_json, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]✓ Full results saved to {output_json}[/green]")
            
    except Exception as e:
        console.print(f"[bold red]Failed:[/bold red] {e}")
        raise typer.Exit(1)


@app.command("oauth-list")
def oauth_list(
    container: str = typer.Option("authentik-server-prod", "--container", help="Docker container name")
):
    """List all OAuth2 providers."""
    manager = AuthentikOAuthManager(container_name=container)
    
    try:
        providers = manager.list_providers()
        
        table = Table(title="OAuth2 Providers")
        table.add_column("Name", style="green")
        table.add_column("Client ID", style="cyan")
        table.add_column("Type")
        table.add_column("Redirect URIs")
        
        for p in providers:
            table.add_row(
                p['name'],
                p['client_id'],
                p['client_type'],
                '\n'.join(p.get('redirect_uris', []))
            )
        
        console.print(table)
        console.print(f"\nTotal: {len(providers)} providers")
        
    except Exception as e:
        console.print(f"[bold red]Failed:[/bold red] {e}")
        raise typer.Exit(1)


@app.command("oauth-get")
def oauth_get(
    client_id: str = typer.Argument(..., help="OAuth client ID"),
    container: str = typer.Option("authentik-server-prod", "--container", help="Docker container name"),
    show_secret: bool = typer.Option(False, "--show-secret", help="Show client secret")
):
    """Get details of an OAuth provider."""
    manager = AuthentikOAuthManager(container_name=container)
    
    try:
        provider = manager.get_provider(client_id)
        
        console.print(f"[bold]OAuth Provider: {provider['name']}[/bold]")
        console.print(f"  Client ID: [cyan]{provider['client_id']}[/cyan]")
        if show_secret:
            console.print(f"  Client Secret: [yellow]{provider['client_secret']}[/yellow]")
        else:
            console.print(f"  Client Secret: [dim]<hidden, use --show-secret>[/dim]")
        console.print(f"  Client Type: {provider['client_type']}")
        console.print(f"  Redirect URIs:")
        for uri in provider.get('redirect_uris', []):
            console.print(f"    - {uri}")
            
    except Exception as e:
        console.print(f"[bold red]Failed:[/bold red] {e}")
        raise typer.Exit(1)


@app.command("oauth-delete")
def oauth_delete(
    client_id: str = typer.Argument(..., help="OAuth client ID to delete"),
    container: str = typer.Option("authentik-server-prod", "--container", help="Docker container name"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation")
):
    """Delete an OAuth2 provider."""
    if not confirm:
        response = typer.confirm(f"Are you sure you want to delete OAuth provider '{client_id}'?")
        if not response:
            console.print("Cancelled.")
            raise typer.Abort()
    
    manager = AuthentikOAuthManager(container_name=container)
    
    try:
        manager.delete_provider(client_id)
        console.print(f"[bold green]✓ Deleted OAuth provider: {client_id}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed:[/bold red] {e}")
        raise typer.Exit(1)
