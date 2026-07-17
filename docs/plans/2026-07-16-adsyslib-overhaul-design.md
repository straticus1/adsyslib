# adsyslib Overhaul — Design

**Date:** 2026-07-16
**Status:** Validated in brainstorming session (approach and scope confirmed; two open
questions below were decided by default and are cheap to reverse).

## Goals and constraints

- **Driver:** full phased overhaul — architecture/quality, then features, then productization.
- **Audience:** internal use now, public PyPI release later. Design the public API surface
  with the release in mind, but don't block internal velocity on it.
- **Scope:** keep all 12 modules (core, remote, host, compliance, packages, container,
  cloud, iac, k8s, authentik, keycloak, interact) and unify them — no cuts, no repo split.
- **Approach:** A+B hybrid — foundation-first (gates, then the shell contract), with the
  compliance spine as the exemplar module unification before the rest.

## Motivating findings (from code inspection, 2026-07-16)

1. `core.Shell` lacks the file-inspection half of the interface (`read_text`, `list_dir`,
   `path_exists`, `is_dir`, `path_stat`) that `RemoteShell`, `DockerShell`, `KubeShell`,
   and the compliance `CollectionContext`s implement. The "one interface everywhere" story
   is aspirational for local execution today.
2. `pyproject.toml` makes boto3, oci, docker, pexpect, and sh **mandatory** dependencies —
   a blocker for a lean public release.
3. `compliance.context.CollectionContext` is a parallel abstraction duplicating the shell
   interface; it exists only to bridge local `run()` vs. `RemoteShell`.
4. No lint/type/CI gates exist. Test baseline: 223 passing (~1s). Ruff default-rule
   baseline: 51 findings (46 auto-fixable). Local Python is 3.9.6; `requires-python >=3.9`.

## Phase 0 — Gates (land first; everything else lands under them)

- `[tool.ruff]` in pyproject.toml: lint (`E`, `F`, `I`, `UP`, `B` when clean) + `ruff format`
  as the formatter, replacing black/isort in the dev extra. Fix the 51-finding baseline.
- `[tool.mypy]`: start lenient (`ignore_missing_imports`, no strict flags) so the gate
  passes from day one; ratchet per-module strictness during Phase 2.
- `[tool.pytest.ini_options]`: testpaths, quiet defaults. Add `pytest-cov` to the dev
  extra; record the coverage baseline and enforce it as a floor (`--cov-fail-under`) so
  coverage can only rise.
- GitHub Actions: ruff check, ruff format --check, mypy, pytest across Python 3.9–3.13.

## Phase 1 — The contract

- **`adsyslib/protocols.py`** — a `runtime_checkable` `typing.Protocol` named
  `ShellProtocol`: `run()`, `read_text()`, `list_dir()`, `path_exists()`, `is_dir()`,
  `path_stat()`, `connect()`, `disconnect()`, `__enter__`/`__exit__`. Sync-only for now
  (no async story in v1 — YAGNI).
- **Bring `core.Shell` up to the full contract** with local `os`/`pathlib` implementations;
  `connect()`/`disconnect()` are no-ops locally.
- **One exception hierarchy** rooted in core: `AdsysError` → `ShellError`,
  `ShellConnectionError`, `CollectionError`, … All modules raise from this family.
- **Collapse the context layer:** collectors accept any `ShellProtocol` directly.
  `LocalContext`/`RemoteContext` remain as thin **deprecated aliases** (open question #1)
  for one release cycle, then go.
- **Contract test suite:** one parametrized test module run against `Shell`, `RemoteShell`,
  `DockerShell`, `KubeShell` (remote/container variants against fakes locally, real
  backends in the Docker test image) enforcing conformance forever.
- **Dependency restructure:** core install shrinks to `typer`, `rich`, `pyyaml`,
  `requests`; extras: `[remote]` paramiko, `[cloud]` boto3+oci, `[container]` docker,
  `[interact]` pexpect, `[all]`. Lazy imports with an error naming the extra to install.
  (Open question #2 — changes behavior of bare `pip install adsyslib` for existing
  installs.)

## Phase 2 — Exemplar spine, then per-module unification

Unify the compliance spine first (core → remote → host → compliance → CLI): collectors on
`ShellProtocol`, typed host-scan → audit-package path, full coverage. Distill a **module
unification checklist**: complete typing, `AdsysError`-family errors only, lazy optional
imports, docstrings, contract/unit tests, CLI parity where applicable. Then run packages,
container, cloud, iac, k8s, authentik, keycloak, interact through the checklist one by
one, each as a reviewable unit.

## Phase 3 — Feature deepening

More compliance frameworks/collectors, more service scanners, k8s CLI exposure
(`adsys k8s …`), fleet-scale compliance (fleet scan → per-host audit packages).
Scoped in detail when Phase 2 completes.

## Phase 4 — Productization

API-surface review (`__all__`, deprecation policy), docs site, semver + changelog,
PyPI publishing via CI trusted publisher.

## Phase 5 — Starlark plugin layer (decided 2026-07-16)

Embed Starlark via `python-starlark-go` so SOC/NOC/CloudOps authors can write
higher-level plugins without touching the Python core. Chosen over JavaScript because
Starlark's syntax is Python, and the language is deterministic and hermetically sandboxed
(no I/O, no imports, no unbounded loops) — an inexperienced author cannot hang a scan or
exfiltrate from inside a plugin.

**Plugin model: pure evaluators.** `python-starlark-go` marshals data (dict/list/str/int)
in and out but cannot expose Python callables to Starlark. So adsyslib collects evidence
(shells/collectors/scanners), passes the evidence dict to the plugin, and the plugin
returns findings/verdicts — e.g. custom compliance controls, scan-issue rules, fleet
triage policies. Deterministic, auditable, side-effect-free. If action-taking plugins are
ever needed, add a Python-side verb allowlist driven by plugin return values; never
expose the core. Lands after Phase 2 (needs the stable evidence schemas), can run in
parallel with Phase 3.

## Open questions (defaults chosen, cheap to reverse)

1. **Deprecated context aliases vs. hard delete** — default: keep `LocalContext`/
   `RemoteContext` as deprecated aliases for one cycle. (User was AFK at this checkpoint.)
2. **Dependency extras split** — default: do it in Phase 1, not Phase 0, since it changes
   install behavior; confirm grouping before landing.
3. **`ShellProtocol` method set** — as listed above; revisit if async or streaming output
   is needed before v1.
