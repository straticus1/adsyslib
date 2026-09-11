"""Private, atomic persistence for reports and credentials."""

import os
import tempfile
from pathlib import Path


def write_private(path: str, content: str) -> None:
    """Replace a file atomically with mode 0600, without following destination symlinks."""
    target = Path(path).absolute()
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
