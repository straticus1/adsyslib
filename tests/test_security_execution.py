"""Regression tests for command boundaries, SSH trust, deadlines and target routing."""

import ast
import io
import logging
import shlex
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from adsyslib.authentik.oauth import AuthentikOAuthManager, OAuthProviderConfig
from adsyslib.core import AdsysError, ShellError, ShellTimeoutError, run
from adsyslib.host.docker_shell import DockerShell
from adsyslib.host.kube_shell import KubeShell
from adsyslib.remote import RemoteShell


def test_literal_arguments_do_not_execute_shell(tmp_path):
    marker = tmp_path / "owned"
    payload = f"$(touch {marker}); echo bad"
    assert run(["printf", "%s", payload]).stdout == payload
    assert not marker.exists()


def test_list_with_shell_preserves_arguments():
    assert run(["printf", "%s", "a b; $HOME"], shell=True).stdout == "a b; $HOME"


def test_output_preservation_and_stdin():
    assert run(["cat"], input="  evidence\n\n", strip_output=False).stdout == "  evidence\n\n"


def test_timeout_is_both_library_and_subprocess_error():
    with pytest.raises(ShellTimeoutError) as caught:
        run([sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.02)
    assert isinstance(caught.value, (AdsysError, subprocess.TimeoutExpired))


@pytest.mark.parametrize("kwargs", [{"timeout": 0}, {"text": False}])
def test_invalid_execution_options(kwargs):
    with pytest.raises(ValueError):
        run(["echo", "test"], **kwargs)


def test_sensitive_command_does_not_enter_logs_or_error(caplog):
    with caplog.at_level(logging.DEBUG), pytest.raises(ShellError) as caught:
        run(
            [sys.executable, "-c", "import sys; sys.stderr.write('secret-canary'); sys.exit(3)"],
            check=True,
            sensitive=True,
        )
    assert "secret-canary" not in caplog.text
    assert "secret-canary" not in str(caught.value)
    assert caught.value.result.exit_code == 3


def test_ssh_rejects_unknown_hosts_and_loads_trust():
    with patch("paramiko.SSHClient") as factory:
        client = factory.return_value
        with RemoteShell("host", "user", known_hosts="/tmp/known_hosts") as shell:
            shell.connect()  # idempotent
            client.load_system_host_keys.assert_called_once()
            client.load_host_keys.assert_called_once_with("/tmp/known_hosts")
            import paramiko

            assert isinstance(
                client.set_missing_host_key_policy.call_args.args[0], paramiko.RejectPolicy
            )
            client.connect.assert_called_once()
        client.close.assert_called_once()


def test_ssh_failed_sftp_setup_closes_client():
    with patch("paramiko.SSHClient") as factory:
        factory.return_value.open_sftp.side_effect = OSError("SFTP unavailable")
        shell = RemoteShell("host", "user")
        with pytest.raises(AdsysError):
            shell.connect()
        assert shell._client is None
        factory.return_value.close.assert_called_once()


class Channel:
    def __init__(self, out=b"hello", err=b"error", code=0):
        self.out, self.err, self.code = out, err, code
        self.closed = False
        self.input = bytearray()

    def recv_ready(self):
        return bool(self.out)

    def recv_stderr_ready(self):
        return bool(self.err)

    def recv(self, size):
        result, self.out = self.out[:size], self.out[size:]
        return result

    def recv_stderr(self, size):
        result, self.err = self.err[:size], self.err[size:]
        return result

    def send_ready(self):
        return True

    def send(self, data):
        self.input.extend(data)
        return len(data)

    def shutdown_write(self):
        pass

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return self.code

    def close(self):
        self.closed = True


def remote_with_channel(channel):
    shell = RemoteShell("host", "user")
    shell._client = MagicMock()
    stdout = io.BytesIO()
    stdout.channel = channel
    shell._client.exec_command.return_value = (io.BytesIO(), stdout, io.BytesIO())
    return shell


def test_ssh_quotes_all_metacharacters_and_drains_both_streams():
    channel = Channel(out=b"o" * 150000, err=b"e" * 150000)
    shell = remote_with_channel(channel)
    args = ["echo", "a'b", "$(id)", ";touch /tmp/owned", ""]
    result = shell.run(args, timeout=3)
    sent = shell._client.exec_command.call_args.args[0]
    assert shlex.split(sent) == args
    assert result.stdout == "o" * 150000
    assert result.stderr == "e" * 150000
    assert channel.closed


def test_ssh_timeout_closes_channel():
    channel = Channel(out=b"", err=b"")
    channel.exit_status_ready = lambda: False
    shell = remote_with_channel(channel)
    with pytest.raises(ShellTimeoutError):
        shell.run(["sleep", "10"], timeout=0.01)
    assert channel.closed


def test_ssh_input_preserves_bytes():
    channel = Channel()
    shell = remote_with_channel(channel)
    shell.run(["cat"], input="hello\n")
    assert channel.input == b"hello\n"


@pytest.mark.parametrize(
    "factory,module",
    [
        (lambda: DockerShell("web", user="1001"), "docker"),
        (lambda: KubeShell("web", context="production"), "kube"),
    ],
)
def test_container_options_propagate(factory, module):
    with patch(f"adsyslib.host.{module}_shell._run") as execute:
        factory().run(["cat"], input="abc", timeout=2, log_output=False)
        cmd = execute.call_args.args[0]
        assert "-i" in cmd
        assert execute.call_args.kwargs["timeout"] == 2
        if module == "docker":
            assert cmd[cmd.index("--user") + 1] == "1001"
        else:
            assert cmd[cmd.index("--context") + 1] == "production"


def test_kube_connection_uses_selected_context():
    with patch("adsyslib.host.kube_shell._run") as execute:
        execute.return_value.stdout = "Running"
        KubeShell("web", context="staging").connect()
        assert execute.call_args.args[0][:3] == ["kubectl", "--context", "staging"]


@pytest.mark.parametrize("payload", ['x"; __import__("os").system("id"); #', "a\nb'c", "${HOME}"])
def test_oauth_source_treats_names_as_data(payload):
    config = OAuthProviderConfig(payload, payload, payload, [payload], payload)
    source = AuthentikOAuthManager()._generate_create_script(config)
    tree = ast.parse(source)
    # No injected import/system call exists; the complete malicious value remains a literal.
    assert any(isinstance(node, ast.Constant) and node.value == payload for node in ast.walk(tree))
    assert not any(
        isinstance(node, ast.Name) and node.id == "__import__" for node in ast.walk(tree)
    )
    manager = AuthentikOAuthManager()
    manager._docker_exec_python = MagicMock(return_value={})
    manager.get_provider(payload)
    ast.parse(manager._docker_exec_python.call_args.args[0])
    manager.delete_provider(payload)
    ast.parse(manager._docker_exec_python.call_args.args[0])


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")
def test_timeout_also_kills_descendants_holding_output_pipes():
    import time

    start = time.monotonic()
    with pytest.raises(ShellTimeoutError):
        run(["sh", "-c", "sleep 5 & wait"], timeout=0.05)
    assert time.monotonic() - start < 2
