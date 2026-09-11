"""
RemoteShell — SSH-based command execution and file I/O via paramiko.

Usage:
    with RemoteShell("10.0.0.5", "sysadmin", key_file="~/.ssh/id_ed25519") as shell:
        result = shell.run(["systemctl", "is-active", "auditd"])
        content = shell.read_text("/etc/ssh/sshd_config")
"""

import logging
import os
import shlex
import stat
import time
from typing import TYPE_CHECKING, Any, Optional, Union

from adsyslib.core import CommandResult, ShellConnectionError, ShellError, ShellTimeoutError

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
        known_hosts: Optional[str] = None,
    ):
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.known_hosts = known_hosts
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
        if self._client is not None:
            return self
        try:
            import paramiko
        except ImportError:
            raise ImportError(
                "paramiko is required for remote collection:\n"
                "  pip install adsyslib[remote]\n"
                "  or: pip install paramiko"
            ) from None

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        kwargs: dict[str, Any] = {
            "hostname": self.host,
            "username": self.user,
            "port": self.port,
            "timeout": self.timeout,
            "banner_timeout": self.timeout,
            "auth_timeout": self.timeout,
        }
        if self.key_file:
            kwargs["key_filename"] = os.path.expanduser(self.key_file)
        if self.password:
            kwargs["password"] = self.password

        try:
            client.load_system_host_keys()
            if self.known_hosts:
                client.load_host_keys(os.path.expanduser(self.known_hosts))
            client.connect(**kwargs)
            sftp = client.open_sftp()
        except Exception as exc:
            client.close()
            raise ShellConnectionError(f"Unable to connect to {self.host}: {exc}") from exc
        self._client = client
        self._sftp = sftp
        logger.info(f"Connected to {self.user}@{self.host}:{self.port}")
        return self

    def disconnect(self) -> None:
        sftp, client = self._sftp, self._client
        self._sftp = None
        self._client = None
        try:
            if sftp:
                sftp.close()
        finally:
            if client:
                client.close()
        logger.info(f"Disconnected from {self.host}")

    def __enter__(self) -> "RemoteShell":
        return self.connect()

    def __exit__(self, *_: object) -> None:
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

    def run(
        self,
        cmd: Union[str, list[str]],
        check: bool = False,
        timeout: Optional[float] = None,
        shell: bool = True,
        input: Optional[str] = None,
        strip_output: bool = True,
        log_output: bool = False,
        sensitive: bool = False,
        **kwargs: Any,
    ) -> CommandResult:
        """Execute remotely; lists are literal argv, strings retain SSH shell semantics."""
        if kwargs:
            raise TypeError(f"Unsupported SSH options: {', '.join(kwargs)}")
        deadline = self.timeout if timeout is None else timeout
        if deadline <= 0 or not cmd:
            raise ValueError("command must be nonempty and timeout positive")
        cmd_str = shlex.join(cmd) if isinstance(cmd, list) else cmd
        if not shell and isinstance(cmd, str):
            cmd_str = shlex.join(shlex.split(cmd))
        display = "[redacted]" if sensitive else cmd_str
        start = time.monotonic()
        stdin, stdout, stderr = self._require_client().exec_command(cmd_str, timeout=deadline)
        channel = stdout.channel
        out, err = bytearray(), bytearray()
        pending = memoryview(input.encode() if input is not None else b"")
        closed_input = False
        try:
            while True:
                if time.monotonic() - start >= deadline:
                    raise ShellTimeoutError(display, deadline, bytes(out), bytes(err))
                if pending and channel.send_ready():
                    sent = channel.send(pending[:32768].tobytes())
                    if sent == 0:
                        raise ShellConnectionError("SSH channel closed while sending input")
                    pending = pending[sent:]
                if not pending and not closed_input:
                    channel.shutdown_write()
                    closed_input = True
                if channel.recv_ready():
                    out.extend(channel.recv(65536))
                if channel.recv_stderr_ready():
                    err.extend(channel.recv_stderr(65536))
                if (
                    channel.exit_status_ready()
                    and not channel.recv_ready()
                    and not channel.recv_stderr_ready()
                ):
                    break
                time.sleep(0.001)
            exit_code = channel.recv_exit_status()
        finally:
            channel.close()
            stdin.close()
            stdout.close()
            stderr.close()
        out_text, err_text = out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
        if strip_output:
            out_text, err_text = out_text.strip(), err_text.strip()
        result = CommandResult(out_text, err_text, exit_code, display, time.monotonic() - start)
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
