"""
KubeShell — runs commands inside a Kubernetes pod via `kubectl exec`.

Implements the same interface as RemoteShell so all existing service
scanners work inside pods without modification.
"""
import logging
from typing import Any, Dict, List, Optional

from adsyslib.core import CommandResult, run as _run

logger = logging.getLogger(__name__)


class KubeShell:
    """
    Executes commands inside a running Kubernetes pod.

    Uses kubectl exec — no direct API access needed. The pod must be
    in Running state. Specify container if the pod has multiple containers.
    """

    def __init__(
        self,
        pod: str,
        namespace: str = "default",
        container: Optional[str] = None,
        context: Optional[str] = None,
        kubectl_cmd: str = "kubectl",
    ):
        self.pod = pod
        self.namespace = namespace
        self.container = container
        self.context = context
        self.host = f"k8s:{namespace}/{pod}"
        self.user = "root"
        self._kubectl = kubectl_cmd

    def _base(self) -> List[str]:
        cmd = [self._kubectl]
        if self.context:
            cmd += ["--context", self.context]
        cmd += ["exec", self.pod, "-n", self.namespace]
        if self.container:
            cmd += ["-c", self.container]
        cmd += ["--"]
        return cmd

    def connect(self) -> "KubeShell":
        # Verify pod is running
        r = _run([
            self._kubectl, "get", "pod", self.pod,
            "-n", self.namespace,
            "-o", "jsonpath={.status.phase}",
        ])
        phase = r.stdout.strip()
        if not r.ok() or phase != "Running":
            raise RuntimeError(f"Pod '{self.namespace}/{self.pod}' is not Running (phase={phase!r})")
        logger.info(f"Attached to pod {self.namespace}/{self.pod}")
        return self

    def disconnect(self) -> None:
        pass  # stateless

    def __enter__(self) -> "KubeShell":
        return self.connect()

    def __exit__(self, *_) -> None:
        self.disconnect()

    def run(self, cmd, check: bool = False, **_) -> CommandResult:
        if isinstance(cmd, list):
            full = self._base() + [str(c) for c in cmd]
        else:
            full = self._base() + ["sh", "-c", str(cmd)]
        return _run(full, check=check)

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
        c = f"/{self.container}" if self.container else ""
        return f"KubeShell({self.namespace}/{self.pod}{c})"
