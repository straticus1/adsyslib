import logging
import os
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Optional, Union

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Result of a command execution."""

    stdout: str
    stderr: str
    exit_code: int
    command: str
    duration: float

    @property
    def output(self) -> str:
        """Combined stdout and stderr if needed, or just stdout."""
        return self.stdout

    def ok(self) -> bool:
        return self.exit_code == 0


class AdsysError(Exception):
    """Base class for all adsyslib errors."""


class ShellError(AdsysError):
    """Raised when a command fails and check=True."""

    def __init__(self, result: CommandResult):
        self.result = result
        stderr = "[redacted]" if result.command == "[redacted]" else result.stderr
        super().__init__(
            f"Command '{result.command}' failed with exit code {result.exit_code}.\nStderr: {stderr}"
        )


class ShellTimeoutError(AdsysError, subprocess.TimeoutExpired):
    """Execution exceeded its deadline (also a subprocess.TimeoutExpired)."""

    def __init__(self, command: str, timeout: float, output: Any = None, stderr: Any = None):
        subprocess.TimeoutExpired.__init__(self, command, timeout, output=output, stderr=stderr)


class ShellConnectionError(AdsysError, RuntimeError):
    """Raised when a shell cannot connect to (or attach to) its target."""


class CollectionError(AdsysError):
    """Raised when compliance evidence collection fails irrecoverably."""


def run(
    cmd: Union[str, list[str]],
    cwd: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
    check: bool = False,
    timeout: Optional[float] = None,
    shell: bool = False,
    log_output: bool = True,
    input: Optional[str] = None,
    capture_output: bool = True,
    text: bool = True,
    strip_output: bool = True,
    sensitive: bool = False,
) -> CommandResult:
    """
    Run a shell command safely with logging and better typing.

    Args:
        cmd: Command string or list of arguments.
        cwd: Current working directory.
        env: Environment variables.
        check: If True, raise ShellError on non-zero exit code.
        timeout: Timeout in seconds.
        shell: If True, run through the shell (use carefully).
        log_output: If True, log the stdout/stderr to debug log.
        input: Optional input to pipe to the command's stdin.
        capture_output: Capture stdout/stderr (default True).
        text: Must be True; results are decoded as UTF-8 with replacement.
        strip_output: Strip surrounding whitespace (default True for compatibility).
        sensitive: Hide command metadata and suppress captured-output logging.
    """
    if timeout is not None and timeout <= 0:
        raise ValueError("timeout must be positive")
    if not cmd:
        raise ValueError("command must not be empty")
    if not text:
        raise ValueError("CommandResult is text-only; text=False is unsupported")
    args: Union[str, list[str]]
    if isinstance(cmd, list):
        cmd_str = " ".join(shlex.quote(s) for s in cmd)
        args = cmd_str if shell else cmd
    else:
        cmd_str = cmd
        if not shell:
            args = shlex.split(cmd)
        else:
            args = cmd

    if not args:
        raise ValueError("command must contain an executable")
    if sensitive:
        cmd_str = "[redacted]"
        log_output = False
    logger.debug("Running command: %s", cmd_str)
    start_time = time.monotonic()

    # Merge environment if needed
    run_env = os.environ.copy()
    if env:
        run_env.update(env)

    try:
        with subprocess.Popen(
            args,
            cwd=cwd,
            env=run_env,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            stdin=subprocess.PIPE if input is not None else None,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=shell,
            start_new_session=os.name == "posix",
        ) as proc:
            try:
                stdout, stderr = proc.communicate(input, timeout=timeout)
            except BaseException:
                # Descendants may retain stdout/stderr and otherwise defeat the deadline.
                if os.name == "posix":
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    proc.kill()
                proc.communicate()
                raise
        duration = time.monotonic() - start_time

        stdout = stdout or ""
        stderr = stderr or ""
        if strip_output:
            stdout, stderr = stdout.strip(), stderr.strip()

        if log_output and stdout:
            logger.debug(f"STDOUT: {stdout}")
        if log_output and stderr:
            logger.debug(f"STDERR: {stderr}")

        result = CommandResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=proc.returncode,
            command=cmd_str,
            duration=duration,
        )

        if check and proc.returncode != 0:
            raise ShellError(result)

        return result

    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - start_time
        logger.error(f"Command timed out after {duration:.2f}s: {cmd_str}")
        raise ShellTimeoutError(cmd_str, timeout or 0, exc.output, exc.stderr) from None
    except FileNotFoundError as e:
        duration = time.monotonic() - start_time
        logger.debug(f"Command not found: {cmd_str}")
        result = CommandResult(
            stdout="",
            stderr=f"command not found: {cmd_str}",
            exit_code=127,
            command=cmd_str,
            duration=duration,
        )
        if check:
            raise ShellError(result) from e
        return result


class Shell:
    """
    Stateful internal shell representation.
    Keeps track of CWD and simulates a session.
    """

    def __init__(self, cwd: Optional[str] = None, env: Optional[dict[str, str]] = None):
        self.cwd = cwd or os.getcwd()
        self.env = dict(env) if env is not None else os.environ.copy()

    def run(
        self,
        cmd: Union[str, list[str]],
        check: bool = False,
        timeout: Optional[float] = None,
        shell: bool = False,
        **kwargs: Any,
    ) -> CommandResult:
        """Run a command within the context of this shell (cwd/env)."""
        return run(
            cmd, cwd=self.cwd, env=self.env, check=check, timeout=timeout, shell=shell, **kwargs
        )

    def cd(self, path: str) -> None:
        """Change current working directory of the shell wrapper."""
        # Resolve path relative to current self.cwd
        new_path = os.path.abspath(os.path.join(self.cwd, path))
        if not os.path.isdir(new_path):
            raise FileNotFoundError(f"Directory not found: {new_path}")
        self.cwd = new_path
        logger.debug(f"Shell CWD changed to: {self.cwd}")

    def setenv(self, key: str, value: str) -> None:
        self.env[key] = value

    def getenv(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self.env.get(key, default)

    # ------------------------------------------------------------------
    # Connection lifecycle (no-ops locally; present for ShellProtocol parity)
    # ------------------------------------------------------------------

    def connect(self) -> "Shell":
        return self

    def disconnect(self) -> None:
        pass

    def __enter__(self) -> "Shell":
        return self.connect()

    def __exit__(self, *_: object) -> None:
        self.disconnect()

    # ------------------------------------------------------------------
    # File inspection (same semantics as RemoteShell/DockerShell/KubeShell:
    # missing or unreadable paths yield None/[]/False, never raise)
    # ------------------------------------------------------------------

    def _resolve(self, path: str) -> str:
        return os.path.join(self.cwd, os.path.expanduser(path))

    def read_text(self, path: str) -> Optional[str]:
        """Return file contents, or None if not found / permission denied."""
        try:
            with open(self._resolve(path), encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return None

    def list_dir(self, path: str) -> list[str]:
        """Return directory entries, or [] if missing / not a directory."""
        try:
            return os.listdir(self._resolve(path))
        except OSError:
            return []

    def path_exists(self, path: str) -> bool:
        return os.path.exists(self._resolve(path))

    def is_dir(self, path: str) -> bool:
        return os.path.isdir(self._resolve(path))

    def path_stat(self, path: str) -> Optional[dict[str, object]]:
        """Return {permissions, owner_uid, mtime} or None."""
        try:
            s = os.stat(self._resolve(path))
            return {
                "permissions": oct(s.st_mode)[-3:],
                "owner_uid": s.st_uid,
                "mtime": s.st_mtime,
            }
        except OSError:
            return None
