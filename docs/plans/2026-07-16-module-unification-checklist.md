# Module Unification Checklist (Phase 2)

Every module goes through this checklist, one module per reviewable commit.
The compliance spine (core → remote → host → compliance → CLI) went first as the
exemplar; remaining modules follow the same steps.

## The checklist

1. **mypy ratchet** — module is out of the `ignore_errors` list in pyproject.toml and
   passes `mypy src/adsyslib` clean. Fix errors properly (guards, annotations); never
   suppress with blanket ignores.
2. **Untyped defs** — all public functions/methods have parameter and return
   annotations (`mypy --disallow-untyped-defs` clean for the module).
3. **Errors from the family** — everything raised derives from `adsyslib.core.AdsysError`
   (`ShellError`, `ShellConnectionError`, `CollectionError`, or a new subclass). No bare
   `RuntimeError`/`Exception`. Keep dual inheritance (e.g. `ShellConnectionError` is also
   a `RuntimeError`) only where backward compat demands it.
4. **Shell access via ShellProtocol** — anything that executes commands accepts a
   `ShellProtocol`, not a concrete shell class or a wrapper. No new context/adapter
   layers.
5. **Optional deps are lazy** — heavy imports (`boto3`, `oci`, `docker`, `pexpect`,
   `paramiko`) use the `try/except ImportError → None` pattern with a constructor guard
   whose message names the extra (`pip install 'adsyslib[cloud]'`).
6. **Tests** — behavior covered by hermetic tests (fakes over real backends). Shell
   implementations must join the contract suite (`tests/test_shell_contract.py`).
7. **Docstrings** — module docstring states purpose and maps to the architecture; public
   API has usage-level docstrings.
8. **CLI parity** — if the module has a CLI surface, flags/errors behave like the other
   subcommands (usage errors exit via `typer.Exit` with a message, not tracebacks).

## Status

| Module | Ratchet clean | Untyped defs | Notes |
|---|---|---|---|
| core, protocols | ✅ | 6 remaining | spine exemplar |
| remote | ✅ | (in the 6) | connection guards added |
| host/** | ✅ | ~20 across host+compliance | contract suite in place |
| compliance/** | ✅ | (see above) | collectors on ShellProtocol |
| cli/commands (host, pkg) | ✅ | not measured | host_cmd usage guard added |
| packages | ✅ | not measured | not yet through checklist |
| container | ✅ | not measured | lazy docker done (step 5) |
| cloud | ✅ | not measured | lazy boto3/oci done (step 5) |
| iac | ✅ | not measured | not yet through checklist |
| logger, io_utils, interact | ✅ | not measured | lazy pexpect done |
| k8s.kubectl | ✅ | not measured | run_command/run_command_json split |
| authentik (client, oauth, cmd) | ✅ | not measured | steps 2–8 pending |
| keycloak (client, migrate) | ✅ | not measured | steps 2–8 pending |

**The mypy ratchet list is empty (2026-07-16)** — `mypy src/adsyslib` is clean with no
grandfathered modules. Remaining type-strictness ratchets: untyped defs (step 2) and the
global `implicit_optional` flag.

Ruff `UP` rules are now in the gate codebase-wide; `B` (bugbear) is the next rule-set
ratchet. Global `implicit_optional = true` in mypy config is the other standing ratchet —
fix `param: str = None` signatures module-by-module, then drop the flag.
