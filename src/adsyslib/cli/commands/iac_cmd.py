import typer
import json
from rich.console import Console
from rich.syntax import Syntax
from typing import List, Optional
from adsyslib.iac.terraform import TerraformRunner
from adsyslib.iac.ansible import AnsibleRunner

app = typer.Typer()
console = Console()

@app.command("tf-plan")
def tf_plan(
    dir: str = typer.Option(".", help="Terraform working directory"),
    out: Optional[str] = typer.Option(None, help="Output plan file")
):
    """Run terraform plan."""
    tf = TerraformRunner(dir)
    try:
        console.print("[bold blue]Running Terraform Plan...[/bold blue]")
        output = tf.plan(out=out)
        console.print(output)
    except Exception as e:
        console.print(f"[bold red]Plan failed:[/bold red] {e}")
        raise typer.Exit(1)

@app.command("tf-apply")
def tf_apply(
    dir: str = typer.Option(".", help="Terraform working directory"),
    plan: Optional[str] = typer.Option(None, help="Plan file to apply")
):
    """Run terraform apply."""
    tf = TerraformRunner(dir)
    try:
        console.print("[bold blue]Running Terraform Apply...[/bold blue]")
        tf.apply(plan_file=plan)
        console.print("[bold green]Apply successful[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Apply failed:[/bold red] {e}")
        raise typer.Exit(1)

@app.command("ansible-run")
def ansible_run(
    playbook: str = typer.Argument(..., help="Path to playbook"),
    inventory: Optional[str] = typer.Option(None, help="Inventory file"),
    check: bool = typer.Option(False, help="Check mode (dry run)")
):
    """Run ansible playbook."""
    runner = AnsibleRunner(inventory=inventory)
    try:
        console.print(f"[bold blue]Running Playbook: {playbook}[/bold blue]")
        runner.run_playbook(playbook, check=check)
        console.print("[bold green]Playbook completed[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Playbook failed:[/bold red] {e}")
        raise typer.Exit(1)
