"""Kubernetes operations through a consistent context-aware CLI."""

import json
from typing import Optional

import typer

from adsyslib.k8s.kubectl import KubectlRunner

app = typer.Typer(no_args_is_help=True)


@app.callback()
def configure(
    ctx: typer.Context,
    context: Optional[str] = typer.Option(None, help="Kubernetes context"),
    namespace: Optional[str] = typer.Option(None, "--namespace", "-n"),
    kubeconfig: Optional[str] = typer.Option(None),
) -> None:
    ctx.obj = KubectlRunner(context=context, namespace=namespace, kubeconfig=kubeconfig)


@app.command("get")
def get_resources(
    ctx: typer.Context,
    resource: str,
    name: Optional[str] = None,
    output: str = typer.Option("json", "--output", "-o"),
    all_namespaces: bool = typer.Option(False, "--all-namespaces", "-A"),
) -> None:
    """List or inspect resources."""
    result = ctx.obj.get(resource, name, output=output, all_namespaces=all_namespaces)
    typer.echo(json.dumps(result, indent=2) if output == "json" else result)


@app.command("apply")
def apply(ctx: typer.Context, file: str = typer.Option(..., "--file", "-f")) -> None:
    """Apply a manifest file."""
    typer.echo(ctx.obj.apply(file))


@app.command("delete")
def delete(
    ctx: typer.Context, resource: str, name: str, yes: bool = typer.Option(False, "--yes", "-y")
) -> None:
    """Delete a named resource with confirmation."""
    if not yes:
        typer.confirm(f"Delete {resource}/{name}?", abort=True)
    typer.echo(ctx.obj.delete(resource, name))


@app.command("logs")
def logs(
    ctx: typer.Context,
    pod: str,
    container: Optional[str] = typer.Option(None),
    tail: int = typer.Option(100, min=0),
    previous: bool = False,
) -> None:
    """Read recent pod logs."""
    typer.echo(ctx.obj.logs(pod, container=container, tail=tail, previous=previous))


@app.command("scale")
def scale(
    ctx: typer.Context, resource: str, name: str, replicas: int = typer.Option(..., min=0)
) -> None:
    """Set the desired replica count."""
    typer.echo(ctx.obj.scale(resource, name, replicas))


@app.command("rollout-status")
def rollout(ctx: typer.Context, resource: str, name: str) -> None:
    """Wait for rollout completion."""
    typer.echo(ctx.obj.rollout_status(resource, name))
