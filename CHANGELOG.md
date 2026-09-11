# Changelog

## Unreleased — functional and security overhaul

### Execution and trust

- SSH loads trusted host keys and rejects unknown hosts; added a custom known-hosts path.
- Literal SSH argument quoting, concurrent stdout/stderr draining, stdin support,
  deadlines, cleanup after failed connection, and idempotent connections.
- Local process-group cleanup on POSIX deadlines, text preservation, sensitive command
  handling, and a timeout exception in the library error hierarchy.
- Container adapters honor user/context, stdin, timeout and execution options.
- OAuth source generation escapes names/IDs as data; credential environment exports are
  quoted, validated, private and atomic.
- Identity requests have deadlines and refuse redirects; errors omit credential-bearing
  response bodies. Clients expose explicit connection cleanup.

### Functionality

- Kubernetes CLI: get, apply, delete, logs, scale and rollout-status.
- CLI doctor/version commands; command output is visible and failure exit codes survive.
- Package-manager detection/operations accept any ShellProtocol; yum fallback uses yum.
- Authentik list methods traverse pages; Keycloak user exports are no longer capped at
  10,000 requested users; EC2 instance listing traverses all pages.
- Private atomic audit/drift/fleet exports, spreadsheet-safe CSV, actual UUID/timestamp
  validation and duplicate-control/duplicate-fleet-target detection.
- Docker honors its environment, fails at connection time, supports explicit security
  settings, protects existing named containers and bounds readiness polling.
- Dockerfile structured fields reject instruction injection and use quoted data forms.
- Regression coverage, packaging checks, dependency audit CI and rewritten documentation.

### Compatibility changes

- Provision verified SSH host keys before connecting. Automatic trust was removed.
- Docker replacement requires `replace=True`; failure to connect raises immediately.
- Terraform apply requires a saved plan or explicit `auto_approve=True`.
- `run(text=False)` is rejected because CommandResult is a text interface.
- Unsupported SSH kwargs now raise; container execution options are no longer ignored.
- Audit/fleet/drift exports replace the destination atomically with mode 0600 on POSIX.
- CLI command output no longer includes decorative status messages; use `--json` for
  structured output. Kubernetes background port-forward no longer pretends to work.
