import os
import sys
import tempfile
from contextlib import contextmanager
from typing import Generator, Tuple

class IOCatcher:
    """
    captures stdout and stderr at the file descriptor level,
    allowing it to catch output even from C extensions or subprocesses
    that inherit FDs (though subprocesses usually need their own handling).
    """
    def __init__(self, capture_stdout: bool = True, capture_stderr: bool = True):
        self.capture_stdout = capture_stdout
        self.capture_stderr = capture_stderr
        self._stdout_fd = None
        self._stderr_fd = None
        self._saved_stdout_fd = None
        self._saved_stderr_fd = None
        self._temp_stdout = None
        self._temp_stderr = None

    def __enter__(self):
        # Save original file descriptors
        if self.capture_stdout:
            self._saved_stdout_fd = os.dup(sys.stdout.fileno())
            self._temp_stdout = tempfile.TemporaryFile(mode='w+b')
            self._stdout_fd = sys.stdout.fileno()
            # Redirect stdout to temp file
            sys.stdout.flush()
            os.dup2(self._temp_stdout.fileno(), self._stdout_fd)

        if self.capture_stderr:
            self._saved_stderr_fd = os.dup(sys.stderr.fileno())
            self._temp_stderr = tempfile.TemporaryFile(mode='w+b')
            self._stderr_fd = sys.stderr.fileno()
            # Redirect stderr to temp file
            sys.stderr.flush()
            os.dup2(self._temp_stderr.fileno(), self._stderr_fd)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            # Restore stdout
            if self.capture_stdout and self._saved_stdout_fd is not None:
                sys.stdout.flush()
                os.dup2(self._saved_stdout_fd, self._stdout_fd)
                os.close(self._saved_stdout_fd)
        finally:
            # Restore stderr (ensure this runs even if stdout restoration fails)
            if self.capture_stderr and self._saved_stderr_fd is not None:
                try:
                    sys.stderr.flush()
                    os.dup2(self._saved_stderr_fd, self._stderr_fd)
                    os.close(self._saved_stderr_fd)
                except Exception:
                    pass  # Best effort cleanup

    def get_output(self) -> Tuple[str, str]:
        """Returns captured (stdout, stderr) as strings (decoded from utf-8)."""
        stdout_str = ""
        stderr_str = ""

        if self._temp_stdout:
            self._temp_stdout.seek(0)
            stdout_str = self._temp_stdout.read().decode('utf-8', errors='replace')
            self._temp_stdout.close()

        if self._temp_stderr:
            self._temp_stderr.seek(0)
            stderr_str = self._temp_stderr.read().decode('utf-8', errors='replace')
            self._temp_stderr.close()

        return stdout_str, stderr_str

@contextmanager
def capture_io() -> Generator[IOCatcher, None, None]:
    """Convenience context manager for IOCatcher."""
    catcher = IOCatcher()
    with catcher:
        yield catcher
