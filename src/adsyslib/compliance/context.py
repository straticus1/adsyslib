"""
CollectionContext — abstracts local vs. remote command execution and file I/O.

Every collector accepts an optional ctx parameter. Pass a RemoteContext to
run the same collector logic against a remote host over SSH.
"""
import os
from typing import Any, Dict, List, Optional

from adsyslib.core import CommandResult
from adsyslib.core import run as _local_run


class CollectionContext:
    """Abstract base — implement run, read_text, list_dir, is_dir, path_exists, path_stat."""

    def run(self, cmd, check: bool = False, **kwargs) -> CommandResult:
        raise NotImplementedError

    def read_text(self, path: str) -> Optional[str]:
        """Return file contents or None if missing / permission denied."""
        raise NotImplementedError

    def list_dir(self, path: str) -> List[str]:
        """Return directory entries or [] if missing."""
        raise NotImplementedError

    def is_dir(self, path: str) -> bool:
        raise NotImplementedError

    def path_exists(self, path: str) -> bool:
        raise NotImplementedError

    def path_stat(self, path: str) -> Optional[Dict[str, Any]]:
        """Return dict with permissions (oct str), owner_uid, mtime — or None."""
        raise NotImplementedError


class LocalContext(CollectionContext):
    """Runs everything in the current process on the local machine."""

    def run(self, cmd, check: bool = False, **kwargs) -> CommandResult:
        return _local_run(cmd, check=check, **kwargs)

    def read_text(self, path: str) -> Optional[str]:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except (FileNotFoundError, PermissionError):
            return None

    def list_dir(self, path: str) -> List[str]:
        try:
            return os.listdir(path)
        except (FileNotFoundError, PermissionError, NotADirectoryError):
            return []

    def is_dir(self, path: str) -> bool:
        return os.path.isdir(path)

    def path_exists(self, path: str) -> bool:
        return os.path.exists(path)

    def path_stat(self, path: str) -> Optional[Dict[str, Any]]:
        try:
            s = os.stat(path)
            return {
                "permissions": oct(s.st_mode)[-3:],
                "owner_uid": s.st_uid,
                "mtime": s.st_mtime,
            }
        except (FileNotFoundError, PermissionError):
            return None


class RemoteContext(CollectionContext):
    """Wraps a RemoteShell to implement CollectionContext over SSH."""

    def __init__(self, shell: Any):  # shell: adsyslib.remote.RemoteShell
        self._shell = shell

    def run(self, cmd, check: bool = False, **kwargs) -> CommandResult:
        return self._shell.run(cmd, check=check)

    def read_text(self, path: str) -> Optional[str]:
        return self._shell.read_text(path)

    def list_dir(self, path: str) -> List[str]:
        return self._shell.list_dir(path)

    def is_dir(self, path: str) -> bool:
        return self._shell.is_dir(path)

    def path_exists(self, path: str) -> bool:
        return self._shell.path_exists(path)

    def path_stat(self, path: str) -> Optional[Dict[str, Any]]:
        return self._shell.path_stat(path)
