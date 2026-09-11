# Overhaul validation — 2026-09-11

The overhaul preserves the existing module layout and adds execution/security fixes,
CLI functionality, integration improvements, regression coverage and release checks.
See [the changelog](../CHANGELOG.md) for behavior and compatibility changes.

## Results

- Original baseline: 259 passing tests; lint and mypy passed.
- Final clean Python 3.14 environment: 317 passing tests (58 added); 65.98% line coverage.
- Python 3.10 suite passed before the final CLI compatibility/APT adjustments; those
  adjustments also pass the final Python 3.14 suite and mypy's Python 3.9 target.
- Final Ruff lint and formatting checks passed, with both existing and freshly installed tooling.
- Final mypy passed across 76 source modules. Development dependencies constrain mypy
  below 2 because version 2 removed the configured Python 3.9 target.
- Source distribution and wheel built; Twine metadata checks passed.
- pip-audit reported no known vulnerabilities in the resolved development/core/SSH
  environment. The editable adsyslib package itself was skipped by the advisory lookup;
  its source is covered by the tests and code changes, not by that vulnerability database.
- CI now runs Python 3.9–3.14, lint/format/types, a coverage floor, distribution checks,
  and a separate dependency audit. Remote CI execution has not been observed in this session.

## Regression coverage added

Literal command arguments, SSH trust setup and connection cleanup, simultaneous remote
stdout/stderr draining, local/remote deadlines, process-group cleanup, sensitive logging,
container user/context/stdin propagation, OAuth source escaping, HTTP redirects/deadlines,
identity pagination, private atomic writes, CSV formula protection, audit validation,
package argument injection and target-side APT environment, duplicate fleet targets,
CLI output/exit codes, Kubernetes routing, Docker replacement/readiness, EC2 pagination,
Dockerfile injection and explicit Terraform apply intent.

## Remaining validation boundaries

No live cloud, cluster, container, identity server or SSH integration was exercised.
Coverage remains uneven outside the execution/compliance foundation; overall coverage
is about 66%, not exhaustive. Optional cloud SDK dependency sets were not included in
the local vulnerability audit. The security document records operational limitations.
The additional product directions in the historical planning documents remain separate
work and are not represented as completed features.
