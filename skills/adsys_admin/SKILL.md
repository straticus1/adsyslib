---
name: adsys_admin
description: Advanced System Administration using adsyslib (Python & CLI).
---

# adsys_admin Skill

This skill provides capabilities for robust, "10x" system administration using the `adsyslib` Python library and its `adsys` CLI. Use this skill when you need to manage packages, containers, cloud resources, or infrastructure-as-code in a reliable, production-ready manner.

## Capabilities

1.  **Safe Shell Execution**: Run commands with audit logging and output capturing.
2.  **Package Management**: Install/Remove software (apt, dnf) idempotently.
3.  **Container Management**: Orchestrate Docker containers and generate optimized Dockerfiles.
4.  **Cloud Operations**: Manage AWS and Oracle Cloud instances and storage.
5.  **IaC Automation**: Wrap Terraform and Ansible executions.

## Usage Guide

### 1. Using the CLI (`adsys`)

The CLI is the easiest way to perform ad-hoc tasks.

**Running Commands:**
```bash
adsys run exec "ls -la /var/log" --check
```

**Installing Packages (Auto-detects OS):**
```bash
adsys pkg install nginx git --update
```

**Running Containers:**
```bash
# Start redis and wait for it to be ready
adsys container run redis:alpine --name my-redis --wait-log "Ready to accept connections"
```

**Generating Dockerfiles:**
```bash
adsys container gen-dockerfile \
  --image python:3.11-slim \
  --distro debian \
  --packages build-essential git \
  --out Dockerfile.generated
```

**Cloud Operations:**
```bash
# List instances
adsys cloud list-instances --provider aws --region us-east-1

# Upload file
adsys cloud upload --provider oracle --bucket my-bucket --file ./backup.tar.gz
```

**Kubernetes Operations:**
```bash
# Apply configuration
adsys k8s apply --file deployment.yaml --namespace production

# Scale deployment
adsys k8s scale deployment my-app --replicas 5

# View logs
adsys k8s logs my-pod-123 --follow --tail 100

# Execute command in pod
adsys k8s exec my-pod-123 -- /bin/sh -c "ls -la"
```

**Keycloak to Authentik Migration:**
```bash
# Export Keycloak data
adsys keycloak export \
  --url https://keycloak.example.com \
  --realm myrealm \
  --username admin \
  --password secret \
  --output keycloak_export.json

# Migrate to Authentik (dry run first!)
adsys keycloak migrate \
  --keycloak-url https://keycloak.example.com \
  --keycloak-realm myrealm \
  --keycloak-user admin \
  --keycloak-pass secret \
  --authentik-url https://auth.example.com \
  --authentik-token "token-here" \
  --dry-run

# Run actual migration
adsys keycloak migrate ... --default-password "TempPass123!" --no-dry-run
```

### 2. Using the Python Library (`adsyslib`)

For complex logic or scripting, import the library directly.

**Example: Provisioning Workflow**
```python
from adsyslib.core import run, Shell
from adsyslib.packages.apt import Apt
from adsyslib.container.manager import DockerManager

# 1. System Setup
shell = Shell(cwd="/app")
apt = Apt()
apt.install(["curl", "jq"], update=True)

# 2. Container
docker = DockerManager()
container = docker.run_container(
    "nginx:latest", 
    name="web-proxy", 
    ports={"8080": "80"},
    wait_for_log="Configuration complete"
)

# 3. Validation
res = shell.run("curl -I http://localhost:8080")
if res.ok():
    print("Deployment successful!")
```

## Best Practices

- **Idempotency**: `adsys pkg install` is idempotent. Use it freely in scripts.
- **Observability**: All `adsys` commands log structured data. Use `--verbose` for debugging.
- **Safety**: Prefer `adsys run exec` over raw `subprocess` calls to ensure output is captured and errors are handled gracefully.
- **Factory Functions**: Use `get_package_manager()`, `get_cloud_provider()` for auto-detection.

### Authentik (`adsyslib.authentik`)
- `AuthentikClient(base_url, api_token)` - Full-featured identity management
  - **Users**: `.list_users()`, `.create_user()`, `.delete_user()`, `.set_user_password()`
  - **Groups**: `.list_groups()`, `.create_group()`, `.add_user_to_group()`, `.remove_user_from_group()`
  - **Applications**: `.list_applications()`, `.create_application()`, `.delete_application()`
  - **Providers**: `.list_providers()`, `.create_oauth2_provider()`, `.create_proxy_provider()`
  - **Flows**: `.list_flows()`, `.get_flow()`
  - **System**: `.health_check()`, `.get_system_info()`

### Kubernetes (`adsyslib.k8s`)
- `KubectlRunner(context, namespace, kubeconfig)` - High-level kubectl wrapper
  - **Resources**: `.apply()`, `.delete()`, `.get()`, `.describe()`
  - **Pods**: `.list_pods()`, `.logs()`, `.exec()`, `.port_forward()`
  - **Deployments**: `.scale()`, `.rollout_status()`, `.rollout_restart()`
  - **Namespaces**: `.create_namespace()`, `.delete_namespace()`, `.list_namespaces()`
  - **Context**: `.get_current_context()`, `.use_context()`, `.list_contexts()`
  - **Monitoring**: `.top_nodes()`, `.top_pods()`, `.cluster_info()`

### Keycloak (`adsyslib.keycloak`)
- `KeycloakClient(base_url, realm, username, password)` - Keycloak data extraction
  - **Users**: `.list_users()`, `.get_user()`, `.get_user_groups()`, `.get_user_roles()`
  - **Groups**: `.list_groups()`, `.get_group()`, `.get_group_members()`
  - **Clients**: `.list_clients()`, `.get_client()`, `.get_client_by_client_id()`
  - **Roles**: `.list_realm_roles()`, `.list_client_roles()`
  - **Export**: `.export_realm_full()`, `.export_users_minimal()`

- `KeycloakToAuthentikMigrator(keycloak_client, authentik_client, default_password, dry_run)`
  - **Migration**: `.migrate_groups()`, `.migrate_users()`, `.migrate_all()`
  - **Reporting**: `.generate_migration_report()`
  - **Helper**: `quick_migrate()` - One-function migration

**CLI Usage:**
```bash
# Set environment
export AUTHENTIK_URL="https://auth.example.com"
export AUTHENTIK_TOKEN="your-api-token"

# User management
adsys authentik list-users
adsys authentik create-user jdoe "John Doe" --email john@example.com --password secret123
adsys authentik delete-user 42

# Group management
adsys authentik list-groups
adsys authentik create-group developers

# Application management
adsys authentik list-apps
adsys authentik create-app "My App" my-app --launch-url https://app.example.com

# Health check
adsys authentik health
```

## API Reference

### Core (`adsyslib.core`)
- `run(cmd, cwd, env, check, timeout, shell)` → `CommandResult`
- `Shell(cwd, env)` - Stateful shell wrapper with `.run()`, `.cd()`, `.setenv()`
- `ShellError` - Raised on command failure when `check=True`

### Packages (`adsyslib.packages`)
- `get_package_manager()` → Auto-detects apt/dnf/yum
- `Apt`, `Dnf` - Direct package manager classes
- Methods: `.install()`, `.uninstall()`, `.is_installed()`, `.update()`

### Container (`adsyslib.container`)
- `DockerManager` - High-level Docker wrapper
  - `.run_container(image, name, wait_for_log, ...)`
  - `.stop_container(name_or_id)`
- `PackageAwareBuilder` - Smart Dockerfile generation
  - `.install(packages)` - Auto-generates apt/dnf/apk commands

### Cloud (`adsyslib.cloud`)
- `get_cloud_provider(type, profile, region)` → AWS or OCI provider
- Methods: `.list_instances()`, `.start_instance()`, `.stop_instance()`, `.upload_file()`, `.download_file()`

### IaC (`adsyslib.iac`)
- `TerraformRunner(working_dir)` - `.init()`, `.plan()`, `.apply()`, `.output()`
- `AnsibleRunner(inventory)` - `.run_playbook(path, extra_vars, tags, check)`

### Interactive (`adsyslib.interact`)
- `InteractiveSession(command, args, timeout)`
  - `.start()`, `.expect_and_send(pattern, response)`, `.auto_interact([(pattern, response), ...])`

## Error Handling

All library operations raise specific exceptions:
- `ShellError` - Command execution failed
- `TimeoutError` - Operation timed out
- `RuntimeError` - Configuration or initialization error

## Agent Integration Tips

When using this skill as an AI agent:
1. **Always check exit codes**: Use `result.ok()` before proceeding.
2. **Handle Docker dependencies**: Check if Docker daemon is running before container ops.
3. **Cloud credentials**: Ensure AWS/OCI credentials are configured before cloud operations.
4. **Prefer factories**: Use `get_package_manager()` instead of hardcoding `Apt()` or `Dnf()`.
