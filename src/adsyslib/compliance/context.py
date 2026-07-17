"""
DEPRECATED — collectors now accept any ShellProtocol object directly.

This module remains as a compatibility shim for one release cycle. Instead of:

    collect(ctx=LocalContext())                  # old
    collect(ctx=RemoteContext(remote_shell))     # old

pass the shell itself:

    collect(ctx=Shell())            # local
    collect(ctx=remote_shell)       # SSH — RemoteShell already satisfies ShellProtocol
"""
import warnings
from typing import Any, Optional

from adsyslib.core import CommandResult, Shell
from adsyslib.protocols import ShellProtocol

# Kept as an alias so existing type hints / isinstance checks keep working.
CollectionContext = ShellProtocol


def _warn(old: str, new: str) -> None:
    warnings.warn(
        f"{old} is deprecated; {new}. See adsyslib.protocols.ShellProtocol.",
        DeprecationWarning,
        stacklevel=3,
    )


class LocalContext(Shell):
    """DEPRECATED: use adsyslib.core.Shell directly."""

    def __init__(self) -> None:
        _warn("LocalContext", "use adsyslib.core.Shell()")
        super().__init__()


class RemoteContext:
    """DEPRECATED: pass the RemoteShell itself — it already satisfies ShellProtocol."""

    def __init__(self, shell: Any):
        _warn("RemoteContext", "pass the RemoteShell directly")
        self._shell = shell

    def run(self, cmd: Any, check: bool = False, **kwargs: Any) -> CommandResult:
        return self._shell.run(cmd, check=check)

    def read_text(self, path: str) -> Optional[str]:
        return self._shell.read_text(path)

    def list_dir(self, path: str) -> list[str]:
        return self._shell.list_dir(path)

    def is_dir(self, path: str) -> bool:
        return self._shell.is_dir(path)

    def path_exists(self, path: str) -> bool:
        return self._shell.path_exists(path)

    def path_stat(self, path: str) -> Optional[dict[str, Any]]:
        return self._shell.path_stat(path)

    def connect(self) -> Any:
        return self._shell.connect()

    def disconnect(self) -> None:
        self._shell.disconnect()
