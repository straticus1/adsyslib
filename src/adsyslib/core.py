import subprocess
import logging
import shlex
import time
from dataclasses import dataclass
from typing import Optional, Union, List, Dict
import os

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

class ShellError(Exception):
    """Raised when a command fails and check=True."""
    def __init__(self, result: CommandResult):
        self.result = result
        super().__init__(f"Command '{result.command}' failed with exit code {result.exit_code}.\nStderr: {result.stderr}")

def run(
    cmd: Union[str, List[str]],
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    check: bool = False,
    timeout: Optional[float] = None,
    shell: bool = False,
    log_output: bool = True,
    input: Optional[str] = None,
    capture_output: bool = True,
    text: bool = True
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
        text: Text mode for input/output (default True).
    """
    if isinstance(cmd, list):
        cmd_str = " ".join(shlex.quote(s) for s in cmd)
        args = cmd
    else:
        cmd_str = cmd
        if not shell:
            args = shlex.split(cmd)
        else:
            args = cmd

    logger.debug(f"Running command: {cmd_str}")
    start_time = time.time()

    # Merge environment if needed
    run_env = os.environ.copy()
    if env:
        run_env.update(env)

    try:
        proc = subprocess.run(
            args,
            cwd=cwd,
            env=run_env,
            capture_output=capture_output,
            text=text,
            shell=shell,
            timeout=timeout,
            input=input
        )
        duration = time.time() - start_time
        
        stdout = proc.stdout.strip() if proc.stdout else ""
        stderr = proc.stderr.strip() if proc.stderr else ""

        if log_output and stdout:
            logger.debug(f"STDOUT: {stdout}")
        if log_output and stderr:
            logger.debug(f"STDERR: {stderr}")

        result = CommandResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=proc.returncode,
            command=cmd_str,
            duration=duration
        )

        if check and proc.returncode != 0:
            raise ShellError(result)

        return result

    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        logger.error(f"Command timed out after {duration:.2f}s: {cmd_str}")
        raise

class Shell:
    """
    Stateful internal shell representation. 
    Keeps track of CWD and simulates a session.
    """
    def __init__(self, cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None):
        self.cwd = cwd or os.getcwd()
        self.env = env or os.environ.copy()

    def run(self, cmd: Union[str, List[str]], check: bool = False, timeout: Optional[float] = None) -> CommandResult:
        """Run a command within the context of this shell (cwd/env)."""
        return run(cmd, cwd=self.cwd, env=self.env, check=check, timeout=timeout)

    def cd(self, path: str):
        """Change current working directory of the shell wrapper."""
        # Resolve path relative to current self.cwd
        new_path = os.path.abspath(os.path.join(self.cwd, path))
        if not os.path.isdir(new_path):
            raise FileNotFoundError(f"Directory not found: {new_path}")
        self.cwd = new_path
        logger.debug(f"Shell CWD changed to: {self.cwd}")

    def setenv(self, key: str, value: str):
        self.env[key] = value

    def getenv(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self.env.get(key, default)

