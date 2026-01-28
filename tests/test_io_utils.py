"""
Tests for IO capture utilities.
"""
import pytest
import sys
from adsyslib.io_utils import IOCatcher, capture_io


def test_iocatcher_captures_stdout():
    """Test that IOCatcher captures stdout."""
    with IOCatcher() as catcher:
        print("test output")

    stdout, stderr = catcher.get_output()
    assert "test output" in stdout


def test_iocatcher_captures_stderr():
    """Test that IOCatcher captures stderr."""
    with IOCatcher() as catcher:
        print("error output", file=sys.stderr)

    stdout, stderr = catcher.get_output()
    assert "error output" in stderr


def test_iocatcher_selective_capture():
    """Test capturing only stdout or stderr."""
    with IOCatcher(capture_stdout=True, capture_stderr=False) as catcher:
        print("stdout message")
        print("stderr message", file=sys.stderr)

    stdout, stderr = catcher.get_output()
    assert "stdout message" in stdout
    assert stderr == ""  # stderr not captured


def test_capture_io_context_manager():
    """Test the convenience context manager."""
    with capture_io() as catcher:
        print("convenience test")

    stdout, stderr = catcher.get_output()
    assert "convenience test" in stdout


def test_iocatcher_restores_streams():
    """Test that streams are properly restored after capture."""
    original_stdout = sys.stdout
    original_stderr = sys.stderr

    with IOCatcher():
        print("captured")

    assert sys.stdout == original_stdout
    assert sys.stderr == original_stderr
