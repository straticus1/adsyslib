# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Product context

adsyslib is a "10x better" systems library for Python for robust system administration, cloud
management, and automation (package management, container orchestration, cloud ops, IaC wrappers,
identity provider management, and compliance auditing). It ships both as an importable library
(`adsyslib`) and as a CLI (`adsys`, built on Typer).

It pairs with a sibling tool repo, **adssh** (`/Users/ryan/development/adssh`) — adssh is a
separate project and is out of scope here; this file documents adsyslib only.

## Commands

Install (editable, for development — heavy deps are extras: `remote` paramiko, `cloud`
boto3+oci, `container` docker, `interact` pexpect, `all` for everything):
```bash
pip install -e ".[dev,all]"
```

Run tests (configured in `[tool.pytest.ini_options]`):
```bash
pytest
```

Run a single test file / test:
```bash
pytest tests/test_core.py
pytest tests/test_core.py::test_run_with_check_failure
```

Lint/type gates (configured in pyproject.toml; CI runs all three — see
`.github/workflows/ci.yml`). Both must pass before committing:
```bash
ruff check src/ tests/
mypy src/adsyslib
```
mypy has a grandfathered `ignore_errors` ratchet list in pyproject.toml — remove modules
from it as they're cleaned up, never add to it.

Build/test inside a container (mirrors CI-like isolation, from `Dockerfile.test`):
```bash
docker build -f Dockerfile.test -t adsyslib-test .
```
This installs the package plus `pytest black isort mypy` into an Ubuntu 22.04 image with Docker CLI
available (used for tests that touch `DockerManager`/`DockerShell`). `Dockerfile.alpine` and
`Dockerfile.rhel` are minimal runtime images (no test tooling) that just install the package and
set `adsys` as the entrypoint — useful for checking cross-distro `pkg`/package-manager behavior.

CLI entry point (installed via `pyproject.toml` `[project.scripts]`):
```bash
adsys --help
```

## Architecture

**Everything is built on one abstraction: a pluggable "shell."** `adsyslib.core.run()` /
`adsyslib.core.Shell` execute commands locally via `subprocess`. `adsyslib.remote.RemoteShell`
(paramiko/SSH), `adsyslib.host.docker_shell.DockerShell` (`docker exec`), and
`adsyslib.host.kube_shell.KubeShell` (`kubectl exec`) all implement the *same* interface
(`run()`, `read_text()`, `list_dir()`, `path_exists()`, `is_dir()`, `path_stat()`,
`connect()`/`disconnect()`). The interface is formalized as the runtime-checkable
`adsyslib.protocols.ShellProtocol`, enforced by `tests/test_shell_contract.py` and mypy.
Higher-level code is written once against this interface and works unmodified against a
bare-metal host, a container, or a Kubernetes pod — compliance collectors take any
`ShellProtocol` directly (`adsyslib.compliance.context`'s `LocalContext`/`RemoteContext`
are deprecated shims). All errors derive from `adsyslib.core.AdsysError`.

Module map (`src/adsyslib/`):
- **core.py**: `run()`/`Shell` — the foundational local command execution primitive everything
  else is built on. `CommandResult`/`ShellError` are used throughout the library.
- **remote.py**: `RemoteShell` — SSH execution + SFTP file I/O (paramiko), mirrors `core`'s
  interface for remote targets.
- **host/**: Service-scanning layer. `HostSession` (`host/session.py`) wraps any compatible shell
  (SSH/Docker/Kube) with lazily-instantiated `ServiceScanner` subclasses
  (`host/scanners/*.py`: apache, nginx, postfix, dovecot, dns, mysql, postgresql, redis,
  spamassassin, plus an API-level `KubernetesClusterScanner`). Factory functions `ssh_to_host()`,
  `docker_container()`, `kube_pod()` build a `HostSession` around the right shell.
  `host/fleet.py` (`scan_fleet`) runs many `HostSession`s concurrently (`ThreadPoolExecutor`) and
  aggregates into a `FleetReport`.
- **compliance/**: Audit-package builder. `compliance/collectors/*.py` gather raw evidence
  (auth, admin, config_mgmt, entitlements, logging, network, patching, storage) through a
  `CollectionContext` (local or remote). `compliance/builder.py` maps collected data + `HostReport`
  scan issues to NIST 800-53 controls (`compliance/controls.py`) and assembles an `AuditPackage`
  (`compliance/package.py`, serializable to JSON/YAML/CSV). `compliance/drift.py` diffs two
  `AuditPackage`s over time.
- **packages/**: `PackageManager` ABC with `Apt`/`Dnf` implementations; `get_package_manager()`
  auto-detects the host's package manager.
- **container/**: `DockerManager` (docker-py wrapper: run/stop containers, wait-for-log-line
  readiness) and `DockerfileBuilder`/`PackageAwareBuilder` for generating Dockerfiles.
- **cloud/**: `CloudProvider` ABC with `AWSProvider` (boto3) / `OracleProvider` (oci) for compute +
  object storage; `get_cloud_provider()` factory.
- **iac/**: Thin CLI wrappers over `core.run()` — `TerraformRunner` (init/plan/apply/output) and
  `AnsibleRunner`.
- **k8s/**: `KubectlRunner` — general-purpose kubectl wrapper (apply/get/scale/logs/exec/rollout/
  context management). Library-only: not currently wired into the `adsys` CLI (unlike
  `host`'s Kubernetes pod scanning, which is CLI-exposed via `adsys host scan --pod`).
- **authentik/**: `AuthentikClient` (REST API wrapper for users/groups/applications/providers).
  `authentik/oauth.py` (`AuthentikOAuthManager`) instead manages OAuth2 providers by executing
  Python inside the Authentik container via `docker exec` and driving Authentik's Django ORM
  directly — see `OAUTH_INTEGRATION.md` — because the Authentik REST API and its Terraform
  provider both have permission/reliability issues for this operation.
- **keycloak/**: `KeycloakClient` (data extraction via Keycloak Admin REST API) and
  `KeycloakToAuthentikMigrator` for migrating users/groups from Keycloak to Authentik. Library-only,
  not wired into the CLI.
- **interact.py**: `InteractiveSession` — pexpect-based automation of interactive CLI tools
  (expect/send pattern pairs).
- **io_utils.py**: `IOCatcher`/`capture_io()` — fd-level stdout/stderr capture (catches output from
  subprocesses/C extensions, not just Python-level prints).
- **logger.py**: `configure_logging()` — Rich-based console logging plus optional file handler for
  audit trails.
- **cli/**: Typer app (`cli/main.py`) wiring one subcommand app per domain
  (`cli/commands/*.py`): `run`, `pkg`, `container`, `cloud`, `iac`, `authentik`, `compliance`,
  `host`. Each subcommand is a thin front-end over the corresponding library module.

The library `__init__.py` re-exports only the most commonly used surface (core, logging, io_utils,
interact, compliance, host) — the rest (`cloud`, `packages`, `container`, `iac`, `authentik`,
`k8s`, `keycloak`) must be imported from their submodules directly.
