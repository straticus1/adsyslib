"""
ShellProtocol — the one interface every execution target implements.

Local (`core.Shell`), SSH (`remote.RemoteShell`), Docker (`host.docker_shell.DockerShell`),
and Kubernetes (`host.kube_shell.KubeShell`) shells all satisfy this protocol, so
higher-level code (scanners, compliance collectors, fleet operations) is written once
and runs unmodified against any target.

Semantics every implementation must honor:
- ``run`` never raises for a non-zero exit unless ``check=True`` (then ``ShellError``).
- ``read_text`` returns ``None`` for missing/unreadable files, never raises.
- ``list_dir`` returns ``[]`` for missing/non-directories, never raises.
- ``path_stat`` returns ``{"permissions": str, "owner_uid": int, "mtime": float}``
  or ``None``.
- ``connect`` returns ``self`` and raises ``ShellConnectionError`` on failure;
  stateless shells make it a validity check or a no-op. ``disconnect`` is idempotent.

Conformance is enforced by the contract suite in ``tests/test_shell_contract.py``.
"""
from typing import Any, Optional, Protocol, Union, runtime_checkable

from adsyslib.core import CommandResult

__all__ = ["ShellProtocol"]


@runtime_checkable
class ShellProtocol(Protocol):
    """Structural interface for all execution targets (local, SSH, Docker, K8s)."""

    def run(self, cmd: Union[str, list[str]], check: bool = False, **kwargs: Any) -> CommandResult:
        ...

    def read_text(self, path: str) -> Optional[str]:
        ...

    def list_dir(self, path: str) -> list[str]:
        ...

    def path_exists(self, path: str) -> bool:
        ...

    def is_dir(self, path: str) -> bool:
        ...

    def path_stat(self, path: str) -> Optional[dict[str, Any]]:
        ...

    def connect(self) -> "ShellProtocol":
        ...

    def disconnect(self) -> None:
        ...
