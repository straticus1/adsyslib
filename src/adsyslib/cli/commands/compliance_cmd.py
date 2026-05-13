import typer
from pathlib import Path
from typing import List, Optional

app = typer.Typer(help="Generate and compare compliance audit packages (FedRAMP, HIPAA, SOX, GLBA).")

VALID_FRAMEWORKS = {"fedramp", "hipaa", "sox", "glba"}


@app.command("generate")
def generate(
    frameworks: List[str] = typer.Option(
        ["fedramp"], "--framework", "-f",
        help="Compliance framework(s): fedramp, hipaa, sox, glba",
    ),
    output: Path = typer.Option(
        "audit_package.json", "--output", "-o",
        help="Output file path",
    ),
    fmt: str = typer.Option(
        "json", "--format",
        help="Output format: json, yaml, csv",
    ),
    # Remote target options
    host: Optional[str] = typer.Option(None, "--host", "-H", help="Remote host to audit over SSH"),
    user: Optional[str] = typer.Option(None, "--user", "-u", help="SSH username"),
    key_file: Optional[str] = typer.Option(None, "--key-file", "-i", help="SSH private key path"),
    password: Optional[str] = typer.Option(None, "--password", help="SSH password (prefer key auth)"),
    ssh_port: int = typer.Option(22, "--port", help="SSH port"),
    # AWS / IaC options
    aws_iam: bool = typer.Option(False, "--aws-iam", help="Include AWS IAM entitlements"),
    aws_region: Optional[str] = typer.Option(None, "--aws-region"),
    aws_profile: Optional[str] = typer.Option(None, "--aws-profile"),
    ansible_log: str = typer.Option("/var/log/ansible.log", "--ansible-log"),
    # Drift options
    baseline: Optional[Path] = typer.Option(
        None, "--baseline", "-b",
        help="Path to a previous audit package JSON to diff against",
    ),
    drift_output: Optional[Path] = typer.Option(
        None, "--drift-output",
        help="Where to save the drift report (default: drift_<output>)",
    ),
):
    """Collect system evidence and generate a structured audit package.

    Run locally or against a remote host:

      adsys compliance generate -f fedramp

      adsys compliance generate -f fedramp --host 10.0.0.5 --user sysadmin --key-file ~/.ssh/id_ed25519
    """
    from adsyslib.compliance import build_package, compare_packages, load_package

    unknown = {f.lower() for f in frameworks} - VALID_FRAMEWORKS
    if unknown:
        typer.echo(f"Unknown framework(s): {unknown}. Valid: {VALID_FRAMEWORKS}", err=True)
        raise typer.Exit(code=1)

    target = None
    if host:
        from adsyslib.remote import RemoteShell
        if not user:
            typer.echo("--user is required when --host is specified", err=True)
            raise typer.Exit(code=1)
        typer.echo(f"Connecting to {user}@{host}:{ssh_port} ...")
        target = RemoteShell(host, user, port=ssh_port, key_file=key_file, password=password)
        target.connect()

    target_label = f"{user}@{host}" if host else "localhost"
    typer.echo(f"Collecting evidence from {target_label} for: {', '.join(frameworks)}")

    try:
        pkg = build_package(
            frameworks=[f.lower() for f in frameworks],
            target=target,
            include_aws_iam=aws_iam,
            aws_region=aws_region,
            aws_profile=aws_profile,
            ansible_log=ansible_log,
        )
    finally:
        if target:
            target.disconnect()

    pkg.save(str(output), fmt=fmt)

    summary = pkg.summary()
    counts = summary["control_counts"]
    typer.echo(
        f"Controls: {summary['total']} total  "
        f"{counts.get('pass', 0)} pass  "
        f"{counts.get('fail', 0)} fail  "
        f"{counts.get('not_applicable', 0)} n/a"
    )
    typer.echo(f"Package saved: {output}")

    if baseline:
        if not baseline.exists():
            typer.echo(f"Baseline not found: {baseline}", err=True)
            raise typer.Exit(code=1)

        typer.echo(f"\nComparing against baseline: {baseline}")
        base_pkg = load_package(str(baseline))
        report = compare_packages(base_pkg, pkg)

        drift_path = drift_output or output.parent / f"drift_{output.name}"
        report.save(str(drift_path))

        s = report.summary()
        typer.echo(
            f"Drift: {s['regressions']} regression(s)  "
            f"{s['resolutions']} resolved  "
            f"{s['unchanged']} unchanged"
        )
        if report.regressions:
            typer.echo("REGRESSIONS (pass → fail):")
            for r in report.regressions:
                typer.echo(f"  [{r.control_id}] {r.control_title}")
                typer.echo(f"    was: {r.baseline_evidence}")
                typer.echo(f"    now: {r.current_evidence}")
        typer.echo(f"Drift report saved: {drift_path}")


@app.command("compare")
def compare(
    baseline: Path = typer.Argument(..., help="Path to baseline audit package JSON"),
    current: Path = typer.Argument(..., help="Path to current audit package JSON"),
    output: Path = typer.Option("drift_report.json", "--output", "-o"),
):
    """Diff two saved audit packages and report what changed."""
    from adsyslib.compliance import compare_packages, load_package

    if not baseline.exists():
        typer.echo(f"Baseline not found: {baseline}", err=True)
        raise typer.Exit(code=1)
    if not current.exists():
        typer.echo(f"Current package not found: {current}", err=True)
        raise typer.Exit(code=1)

    base_pkg = load_package(str(baseline))
    cur_pkg = load_package(str(current))
    report = compare_packages(base_pkg, cur_pkg)
    report.save(str(output))

    s = report.summary()
    typer.echo(
        f"Drift: {s['regressions']} regression(s)  "
        f"{s['resolutions']} resolved  "
        f"{s['unchanged']} unchanged"
    )
    if report.regressions:
        typer.echo("REGRESSIONS (pass → fail):")
        for r in report.regressions:
            typer.echo(f"  [{r.control_id}] {r.control_title}")
    if report.resolutions:
        typer.echo("RESOLVED (fail → pass):")
        for r in report.resolutions:
            typer.echo(f"  [{r.control_id}] {r.control_title}")

    typer.echo(f"Report saved: {output}")
