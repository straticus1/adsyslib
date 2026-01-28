"""
Tests for core shell execution functionality.
"""
import pytest
import os
from adsyslib.core import run, Shell, CommandResult, ShellError


def test_run_simple_command():
    """Test basic command execution."""
    result = run("echo 'hello world'", shell=True)
    assert result.ok()
    assert "hello world" in result.stdout
    assert result.exit_code == 0


def test_run_with_check_success():
    """Test that check=True doesn't raise on success."""
    result = run(["echo", "test"], check=True)
    assert result.ok()


def test_run_with_check_failure():
    """Test that check=True raises ShellError on failure."""
    with pytest.raises(ShellError) as exc_info:
        run(["false"], check=True)
    assert exc_info.value.result.exit_code != 0


def test_run_captures_stderr():
    """Test that stderr is properly captured."""
    result = run("echo 'error' >&2", shell=True)
    assert "error" in result.stderr


def test_command_result_output_property():
    """Test that .output property returns stdout."""
    result = run(["echo", "test"])
    assert result.output == result.stdout


def test_shell_maintains_cwd():
    """Test that Shell class maintains working directory."""
    original_cwd = os.getcwd()
    temp_dir = "/tmp"

    shell = Shell(cwd=temp_dir)
    result = shell.run("pwd", shell=True)

    # Shell should run in /tmp but not change our actual process cwd
    assert temp_dir in result.stdout
    assert os.getcwd() == original_cwd


def test_shell_cd_changes_context():
    """Test that shell.cd() changes the shell context."""
    shell = Shell()
    original = shell.cwd
    shell.cd("/tmp")
    assert shell.cwd != original
    assert "/tmp" in shell.cwd


def test_shell_env_management():
    """Test environment variable management in Shell."""
    shell = Shell()
    shell.setenv("TEST_VAR", "test_value")
    assert shell.getenv("TEST_VAR") == "test_value"

    result = shell.run("echo $TEST_VAR", shell=True)
    assert "test_value" in result.stdout


def test_run_with_timeout():
    """Test that timeout works."""
    with pytest.raises(Exception):  # subprocess.TimeoutExpired
        run(["sleep", "10"], timeout=0.1)


def test_run_list_vs_string():
    """Test that both list and string commands work."""
    result1 = run(["echo", "test"])
    result2 = run("echo test", shell=True)
    assert result1.ok() and result2.ok()
    assert "test" in result1.stdout
    assert "test" in result2.stdout
