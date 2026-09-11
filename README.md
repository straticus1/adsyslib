# adsyslib

Python library and `adsys` CLI for system administration, infrastructure operations,
identity management, and compliance evidence collection.

## Install

```sh
python -m pip install .
python -m pip install '.[remote]'       # SSH via Paramiko
python -m pip install '.[container]'    # Docker SDK
python -m pip install '.[cloud]'        # AWS and Oracle Cloud SDKs
python -m pip install '.[interact]'     # pexpect
adsys doctor                          # JSON capability report; no service connections
adsys --help
```

Python 3.9+ is supported. Optional SDKs are not needed for the core CLI. Docker exec,
Kubernetes, Terraform, and Ansible wrappers require their respective executables.
Linux package managers and service scanners require a compatible target system;
installing this library does not install system tools or grant permissions.

## Execute commands

```python
from adsyslib import Shell, ShellError, ShellTimeoutError, run

result = run(["printf", "%s", "literal arguments; no shell expansion"], check=True, timeout=10)
print(result.stdout)

with Shell(cwd="/tmp", env={"APP_ENV": "development"}) as shell:
    result = shell.run(["pwd"], check=True)
    content = shell.read_text("settings.conf")  # None when missing/unreadable
```

Local strings are split into arguments. Shell operators require `shell=True`.
Pass argument lists whenever values come from users. `strip_output=False` preserves
exact text; `input=` supplies stdin. Results contain stdout, stderr, exit code,
command, and duration. `check=True` raises `ShellError`; deadlines raise
`ShellTimeoutError` (also a `subprocess.TimeoutExpired`). POSIX timeouts terminate
the local process group. `sensitive=True` hides command metadata and debug output;
returned stdout/stderr still contain the original data and must be handled carefully.

```sh
adsys run exec 'printf hello'
adsys run exec 'sh -c "exit 7"' --json  # JSON result, exit code 7
adsys run exec 'sleep 60' --timeout 2    # exit code 124
```

## Work across local, SSH, Docker, and Kubernetes targets

All shell adapters implement `ShellProtocol`: execution, file inspection, and lifecycle.
SSH and container **strings** retain their historical target-shell semantics; use lists
for literal arguments, or pass `shell=False` explicitly.

```python
from adsyslib.remote import RemoteShell
from adsyslib.host import docker_container, kube_pod, ssh_to_host, scan_fleet
from adsyslib.packages import get_package_manager

# Verify the host key independently and provision known_hosts before connecting.
with RemoteShell("web.example", "admin", known_hosts="/path/to/known_hosts") as shell:
    print(shell.run(["uname", "-a"], timeout=10).stdout)
    packages = get_package_manager(shell, use_sudo=True)
    packages.install(["nginx"], update=True)

fleet = scan_fleet([
    ssh_to_host("web.example", user="admin"),
    docker_container("mail"),
    kube_pod("api-pod", namespace="apps", context="staging"),
], services=["nginx"], workers=3)
fleet.save("fleet.json")
```

SSH rejects unknown or changed host keys and loads the normal user known-hosts file.
Docker honors an explicitly selected user; otherwise it uses the container's configured
user. Kubernetes connection checks and execution use the same selected context.
Each fleet target must have a unique label. Unsupported SSH execution options fail
explicitly instead of being silently ignored.

## Kubernetes CLI

```sh
adsys k8s --context staging -n apps get pods
adsys k8s --context staging -n apps logs api-pod --tail 100
adsys k8s --context staging -n apps apply -f deployment.yaml
adsys k8s --context staging -n apps scale deployment api --replicas 3
adsys k8s --context staging -n apps rollout-status deployment api
adsys k8s --context staging -n apps delete deployment api --yes
```

The library `KubectlRunner` also exposes describe, exec, context, and deployment helpers.
Commands have a configurable 60-second deadline. Background port forwarding is rejected
explicitly; manage a foreground port-forward process externally.

## Compliance evidence

```sh
adsys compliance generate -f fedramp -f hipaa -o audit.json
adsys compliance generate -f fedramp --baseline audit.json -o audit-new.json
```

```python
from adsyslib.compliance import build_package

package = build_package(frameworks=["fedramp"])
print(package.summary())
print(package.validate())
package.save("audit.json")  # JSON, YAML and CSV supported
```

Collectors cover authentication, administration, entitlements, logging, networking,
storage, patching, and configuration management. Framework mappings include FedRAMP,
HIPAA, SOX, and GLBA. Results are evidence and heuristic checks, **not certification**.
Review errors, missing evidence, and applicability before using a report for an audit.
Audit, drift, and fleet files are atomically replaced with owner-only permissions on
POSIX. CSV exports neutralize formula prefixes. Reports may still contain sensitive data.

## Identity and infrastructure

- `AuthentikClient` lists all pages of users, groups, applications, providers, flows,
  and tokens. `KeycloakClient.iter_users()` supports exports beyond server page limits.
  Both clients support context-manager cleanup, TLS verification, bounded HTTP requests,
  and refuse redirects. Configure the canonical HTTPS URL and least-privilege credentials.
- `AuthentikOAuthManager` supports the existing Django ORM workflow. Generated code
  escapes data fields and suppresses credential-bearing execution logs. This workflow
  depends on Authentik's internal model schema; validate it against your server version.
- `DockerManager` refuses to replace an existing container unless `replace=True`.
  It supports readiness checks and explicit `user`, `read_only`, `cap_drop`, and
  `security_opt` settings. It uses Docker's environment configuration by default.
- `AWSProvider.list_instances()` consumes every EC2 response page. AWS/OCI storage and
  compute methods remain available through `adsyslib.cloud`.
- Terraform apply requires a saved plan or explicit `auto_approve=True`.
  CLI equivalent: `adsys iac tf-apply --plan plan.tfplan` or `--auto-approve`.
  Terraform and Ansible wrappers accept execution deadlines and suppress sensitive logs.

See [CHANGELOG.md](CHANGELOG.md) for compatibility changes and
[docs/SECURITY.md](docs/SECURITY.md) for trust boundaries and validation limits.

## Development

```sh
python -m pip install -e '.[dev,remote]'
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/adsyslib
pytest --cov=adsyslib --cov-fail-under=65
python -m build
```

Tests use local subprocesses and mocked services. They do not mutate real hosts,
containers, clusters, identity providers, or cloud accounts. CI tests multiple Python
versions, validates distribution metadata, and audits installed runtime dependencies.
