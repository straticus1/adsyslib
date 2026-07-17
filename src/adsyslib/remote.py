"""
RemoteShell — SSH-based command execution and file I/O via paramiko.

Usage:
    with RemoteShell("10.0.0.5", "sysadmin", key_file="~/.ssh/id_ed25519") as shell:
        result = shell.run(["systemctl", "is-active", "auditd"])
        content = shell.read_text("/etc/ssh/sshd_config")
"""
import logging
import stat
import time
from typing import TYPE_CHECKING, Any, Optional

from adsyslib.core import CommandResult, ShellConnectionError, ShellError

if TYPE_CHECKING:
    import paramiko

logger = logging.getLogger(__name__)


class RemoteShell:
    """
    SSH connection that mirrors the local run/read_text interface.
    Use as a context manager (with statement) or call connect()/disconnect() manually.
    """

    def __init__(
        self,
        host: str,
        user: str,
        port: int = 22,
        key_file: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.host = host
        self.user = user
        self.port = port
        self.key_file = key_file
        self.password = password
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None
        self._sftp: Optional[paramiko.SFTPClient] = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> "RemoteShell":
        try:
            import paramiko
        except ImportError:
            raise ImportError(
                "paramiko is required for remote collection:\n"
                "  pip install adsyslib[remote]\n"
                "  or: pip install paramiko"
            )

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        kwargs: dict[str, Any] = {
            "hostname": self.host,
            "username": self.user,
            "port": self.port,
            "timeout": self.timeout,
        }
        if self.key_file:
            kwargs["key_filename"] = self.key_file
        if self.password:
            kwargs["password"] = self.password

        client.connect(**kwargs)
        self._client = client
        self._sftp = client.open_sftp()
        logger.info(f"Connected to {self.user}@{self.host}:{self.port}")
        return self

    def disconnect(self) -> None:
        if self._sftp:
            self._sftp.close()
            self._sftp = None
        if self._client:
            self._client.close()
            self._client = None
        logger.info(f"Disconnected from {self.host}")

    def __enter__(self) -> "RemoteShell":
        return self.connect()

    def __exit__(self, *_) -> None:
        self.disconnect()

    def _require_client(self) -> "paramiko.SSHClient":
        if self._client is None:
            raise ShellConnectionError(f"Not connected to {self.host} — call connect() first")
        return self._client

    def _require_sftp(self) -> "paramiko.SFTPClient":
        if self._sftp is None:
            raise ShellConnectionError(f"Not connected to {self.host} — call connect() first")
        return self._sftp

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    def run(self, cmd, check: bool = False, **_kwargs) -> CommandResult:
        if isinstance(cmd, list):
            # Quote arguments that contain spaces
            cmd_str = " ".join(f"'{c}'" if " " in str(c) else str(c) for c in cmd)
        else:
            cmd_str = str(cmd)

        start = time.time()
        _stdin, stdout, stderr = self._require_client().exec_command(cmd_str, timeout=self.timeout)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        exit_code = stdout.channel.recv_exit_status()
        duration = time.time() - start

        result = CommandResult(
            stdout=out, stderr=err,
            exit_code=exit_code, command=cmd_str, duration=duration,
        )
        if check and exit_code != 0:
            raise ShellError(result)
        return result

    # ------------------------------------------------------------------
    # File I/O
    # ------------------------------------------------------------------

    def read_text(self, path: str) -> Optional[str]:
        """Return file contents as a string, or None if not found / permission denied."""
        try:
            with self._require_sftp().open(path, "r") as f:
                return f.read().decode("utf-8", errors="replace")
        except OSError:
            return None

    def list_dir(self, path: str) -> list[str]:
        """Return directory listing, or [] if not found."""
        try:
            return self._require_sftp().listdir(path)
        except OSError:
            return []

    def path_exists(self, path: str) -> bool:
        try:
            self._require_sftp().stat(path)
            return True
        except OSError:
            return False

    def is_dir(self, path: str) -> bool:
        try:
            s = self._require_sftp().stat(path)
            return stat.S_ISDIR(s.st_mode) if s.st_mode else False
        except OSError:
            return False

    def path_stat(self, path: str) -> Optional[dict[str, Any]]:
        """Return {permissions, owner_uid, mtime} or None."""
        try:
            s = self._require_sftp().stat(path)
            return {
                "permissions": oct(s.st_mode)[-3:] if s.st_mode else None,
                "owner_uid": s.st_uid,
                "mtime": s.st_mtime,
            }
        except OSError:
            return None
