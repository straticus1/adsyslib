# Security boundaries and verification

adsyslib performs privileged operations using the credentials and permissions of its
caller. It is not a sandbox for untrusted commands, manifests, playbooks, Terraform
configurations, Dockerfiles, or identity administration scripts.

## Implemented controls

- Argument lists remain literal across local/SSH/container execution. Local shell syntax
  is opt-in. Remote string shell syntax remains available for existing scanners.
- SSH uses known-host verification, following the
  [Paramiko client trust model](https://docs.paramiko.org/en/stable/api/client.html).
  Provision keys over a trusted channel; merely collecting a key does not verify it.
- Identity clients verify TLS by default and reject redirects. Plain HTTP and
  `verify_ssl=False` remain explicit caller-configurable transport choices; production
  callers should use HTTPS with verification enabled. Requests are not implicitly retried,
  especially writes that could duplicate resources.
- Authentik pagination uses page numbers on a fixed endpoint, following its
  [pagination schema](https://github.com/goauthentik/authentik/blob/main/authentik/api/pagination.py).
  Keycloak user export uses `first` and `max` from the
  [Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html).
- Sensitive command mode suppresses command/output logs and redacts exception messages.
  It does not erase returned output, hide arguments from the OS process table, or sanitize
  arbitrary application logs. Supply secrets through stdin or provider-supported secret
  channels where possible. Terraform/Ansible argument values may still be visible locally.
- Audit artifacts and generated OAuth environment files use atomic replacement and
  owner-only permissions on POSIX. Credential environment export refuses destination
  symlinks. These are sensitive artifacts, not encrypted storage.
- Docker container replacement and unsaved Terraform apply require explicit options.
  Security-related Docker runtime settings are available but are not automatically imposed.

## Verification limits

The regression suite exercises local process execution and mocked remote backends.
No live SSH server, Docker daemon, Kubernetes cluster, Authentik/Keycloak server, AWS
account, or OCI tenancy is provisioned by the tests. Run controlled integration checks
against your deployment versions before production use, particularly the Authentik ORM
integration. The whole library has not received an independent penetration test.

Readiness polling uses bounded Docker API requests; an individual request can extend
past the readiness window by up to the client request timeout. Local POSIX command
cleanup kills the process group; processes that intentionally detach require external
supervision. SSH channel closure does not guarantee termination of every remote child.

The legacy planning documents describe additional product directions, including fleet
compliance and a Starlark plugin system. Those are not implemented or advertised as
available by this overhaul. Compliance mappings remain heuristics and do not establish
regulatory compliance.
