"""
DockerShell — runs commands inside a Docker container via `docker exec`.

Implements the same interface as RemoteShell so all existing service
scanners work inside containers without modification.
"""
import logging
from typing import Any, Dict, List, Optional

from adsyslib.core import CommandResult, ShellConnectionError
from adsyslib.core import run as _run

logger = logging.getLogger(__name__)


class DockerShell:
    """
    Executes commands inside a running Docker container.

    The container must already be running — this does not start it.
    No connection step needed; docker exec is stateless.
    """

    def __init__(
        self,
        container: str,
        docker_cmd: str = "docker",
        user: Optional[str] = None,
    ):
        self.container = container
        self.host = f"docker:{container}"
        self.user = user or "root"
        self._docker = docker_cmd

    def connect(self) -> "DockerShell":
        # Verify the container is actually running
        r = _run([self._docker, "inspect", "--format", "{{.State.Running}}", self.container])
        if not r.ok() or r.stdout.strip() != "true":
            raise ShellConnectionError(f"Container '{self.container}' is not running")
        logger.info(f"Attached to container {self.container}")
        return self

    def disconnect(self) -> None:
        pass  # stateless

    def __enter__(self) -> "DockerShell":
        return self.connect()

    def __exit__(self, *_) -> None:
        self.disconnect()

    def run(self, cmd, check: bool = False, **_) -> CommandResult:
        if isinstance(cmd, list):
            full = [self._docker, "exec", self.container] + [str(c) for c in cmd]
        else:
            full = [self._docker, "exec", self.container, "sh", "-c", str(cmd)]
        result = _run(full, check=check)
        return result

    def read_text(self, path: str) -> Optional[str]:
        r = self.run(["cat", path])
        return r.stdout if r.ok() else None

    def list_dir(self, path: str) -> List[str]:
        r = self.run(["ls", "-1", path])
        return [e.strip() for e in r.stdout.splitlines() if e.strip()] if r.ok() else []

    def path_exists(self, path: str) -> bool:
        return self.run(["test", "-e", path]).exit_code == 0

    def is_dir(self, path: str) -> bool:
        return self.run(["test", "-d", path]).exit_code == 0

    def path_stat(self, path: str) -> Optional[Dict[str, Any]]:
        r = self.run(["stat", "-c", "%a %u %Y", path])
        if not r.ok():
            return None
        parts = r.stdout.strip().split()
        if len(parts) < 3:
            return None
        try:
            return {
                "permissions": parts[0],
                "owner_uid": int(parts[1]),
                "mtime": float(parts[2]),
            }
        except (ValueError, IndexError):
            return None

    def __repr__(self) -> str:
        return f"DockerShell({self.container})"
