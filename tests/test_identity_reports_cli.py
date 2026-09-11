"""Identity pagination, private exports, and end-user CLI regression coverage."""

import json
import os
import shlex
from unittest.mock import MagicMock, patch

import pytest
import requests
from typer.testing import CliRunner

from adsyslib.authentik.client import AuthentikClient
from adsyslib.authentik.oauth import generate_env_file
from adsyslib.cli.main import app
from adsyslib.compliance.package import AuditPackage, ControlResult
from adsyslib.core import CommandResult
from adsyslib.files import write_private
from adsyslib.host.fleet import scan_fleet
from adsyslib.http import APIError, request, validate_url
from adsyslib.keycloak.client import KeycloakClient
from adsyslib.packages import get_package_manager
from adsyslib.packages.apt import Apt
from adsyslib.packages.dnf import Dnf


def response(data=None, status=200):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(data).encode() if data is not None else b""
    return result


def test_http_deadline_and_no_redirects():
    session = MagicMock()
    session.request.return_value = response({"ok": True})
    assert request(session, "GET", "https://example.test", 5) == {"ok": True}
    assert session.request.call_args.kwargs == {"timeout": 5, "allow_redirects": False}
    session.request.return_value = response(status=302)
    with pytest.raises(APIError, match="redirect"):
        request(session, "POST", "https://example.test", 5)


def test_http_error_hides_response_and_exception_secrets():
    session = MagicMock()
    session.request.side_effect = requests.ConnectionError("token=canary")
    with pytest.raises(APIError) as caught:
        request(session, "GET", "https://example.test", 5)
    assert "canary" not in str(caught.value)
    session.request.side_effect = None
    session.request.return_value = response({"token": "canary"}, status=401)
    with pytest.raises(APIError, match="401") as caught:
        request(session, "GET", "https://example.test", 5)
    assert "canary" not in str(caught.value)


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "example.com", "https://u:p@host", "https://host?token=x"]
)
def test_invalid_identity_urls(url):
    with pytest.raises(ValueError):
        validate_url(url)


def test_authentik_collects_all_pages_preserving_search():
    with AuthentikClient("https://id.example", "token") as client:
        client.session.request = MagicMock(
            side_effect=[
                response({"results": [{"pk": 1}], "pagination": {"total_pages": 2}}),
                response({"results": [{"pk": 2}], "pagination": {"total_pages": 2}}),
            ]
        )
        assert client.list_users(search="alice") == [{"pk": 1}, {"pk": 2}]
        calls = client.session.request.call_args_list
        assert [c.kwargs["params"] for c in calls] == [
            {"search": "alice", "page": 1},
            {"search": "alice", "page": 2},
        ]
        assert all(c.args[1] == "https://id.example/api/v3/core/users/" for c in calls)


def test_keycloak_paginates_even_when_server_caps_page_size():
    client = KeycloakClient("https://id.example", realm="team")
    client._request = MagicMock(side_effect=[[{"id": "one"}], [{"id": "two"}], []])
    assert list(client.iter_users(page_size=100)) == [{"id": "one"}, {"id": "two"}]
    assert [c.kwargs["params"]["first"] for c in client._request.call_args_list] == [0, 1, 2]


def test_keycloak_detects_repeated_page():
    client = KeycloakClient("https://id.example")
    client._request = MagicMock(return_value=[{"id": "one"}])
    with pytest.raises(APIError, match="repeated"):
        list(client.iter_users())


def test_keycloak_auth_uses_configured_realm_and_deadline():
    with patch("requests.Session") as factory:
        factory.return_value.request.return_value = response({"access_token": "token"})
        KeycloakClient(
            "https://id.example", username="admin", password="secret", auth_realm="staff", timeout=4
        )
        call = factory.return_value.request.call_args
        assert call.args[1] == "https://id.example/realms/staff/protocol/openid-connect/token"
        assert call.kwargs["timeout"] == 4
        assert call.kwargs["allow_redirects"] is False


def test_atomic_private_export_replaces_symlink_without_touching_target(tmp_path):
    original = tmp_path / "original"
    original.write_text("keep")
    output = tmp_path / "report"
    output.symlink_to(original)
    write_private(str(output), "private evidence")
    assert original.read_text() == "keep"
    assert not output.is_symlink()
    assert output.read_text() == "private evidence"
    assert os.stat(output).st_mode & 0o777 == 0o600


def test_failed_atomic_write_preserves_previous_file(tmp_path):
    target = tmp_path / "report"
    target.write_text("original")
    with patch("adsyslib.files.os.replace", side_effect=OSError("full")), pytest.raises(OSError):
        write_private(str(target), "replacement")
    assert target.read_text() == "original"
    assert list(tmp_path.iterdir()) == [target]


def test_audit_validation_checks_actual_uuid_timestamp_and_duplicates():
    control = ControlResult("AC-1", "Policy", "pass", framework="nist-800-53")
    package = AuditPackage(
        ["fedramp"], controls=[control, control], package_id="bad", generated_at="yesterday"
    )
    errors = package.validate()
    assert any("UUID" in error for error in errors)
    assert any("ISO-8601" in error for error in errors)
    assert any("duplicate" in error for error in errors)


def test_csv_neutralizes_formulas():
    package = AuditPackage(
        ["fedramp"], controls=[ControlResult("AC-1", "title", "pass", evidence="=HYPERLINK(1)")]
    )
    assert "'=HYPERLINK(1)" in package.to_csv()


def test_oauth_env_is_private_and_shell_quoted(tmp_path):
    output = tmp_path / ".env"
    value = "$(touch owned) secret'quoted"
    generate_env_file(
        [{"app_slug": "my-app", "client_id": "id", "client_secret": value}], str(output)
    )
    text = output.read_text()
    assignment = next(
        line for line in text.splitlines() if line.startswith("MY_APP_CLIENT_SECRET=")
    )
    assert shlex.split(assignment.split("=", 1)[1]) == [value]
    assert output.stat().st_mode & 0o777 == 0o600


def test_oauth_env_rejects_newline_injection(tmp_path):
    with pytest.raises(ValueError):
        generate_env_file(
            [{"app_slug": "app", "client_id": "id", "client_secret": "x\nEVIL=y"}],
            str(tmp_path / ".env"),
        )
    assert not (tmp_path / ".env").exists()


def test_fleet_rejects_duplicate_labels_before_connecting():
    session = MagicMock(host="same")
    with pytest.raises(ValueError, match="unique"):
        scan_fleet([session, session])
    session.connect.assert_not_called()


def result(stdout="", code=0):
    return CommandResult(stdout, "", code, "cmd", 0)


@pytest.mark.parametrize("manager", [Apt, Dnf])
@pytest.mark.parametrize("name", ["--assumeyes", "-oAPT::Update::Pre-Invoke::=id", "", "a\nb"])
def test_package_option_injection_rejected(manager, name):
    shell = MagicMock()
    manager = manager(use_sudo=False, shell=shell)
    with pytest.raises(ValueError):
        manager.install(name)
    shell.run.assert_not_called()


def test_package_detection_uses_yum_executable_on_target():
    shell = MagicMock()
    shell.run.side_effect = [result(code=1), result(code=1), result()]
    manager = get_package_manager(shell, use_sudo=False)
    assert isinstance(manager, Dnf)
    shell.run.reset_mock(side_effect=True)
    shell.run.return_value = result()
    manager.update()
    assert shell.run.call_args.args[0] == ["yum", "check-update"]


def test_apt_removed_config_is_not_installed():
    shell = MagicMock()
    shell.run.return_value = result("Status: deinstall ok config-files")
    assert not Apt(use_sudo=False, shell=shell).is_installed("nginx")
    shell.run.return_value = result("Status: install ok installed")
    assert Apt(use_sudo=False, shell=shell).is_installed("nginx")


def test_cli_output_and_exit_code():
    runner = CliRunner()
    success = runner.invoke(app, ["run", "exec", "printf hello"])
    assert success.exit_code == 0, success.output
    assert success.stdout == "hello"
    failure = runner.invoke(app, ["run", "exec", "sh -c 'exit 7'", "--json"])
    assert failure.exit_code == 7, failure.output
    assert json.loads(failure.stdout)["exit_code"] == 7


def test_cli_doctor_and_help():
    runner = CliRunner()
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "integrations" in json.loads(result.stdout)
    for group in ["k8s", "host", "compliance", "pkg", "authentik", "iac", "container", "cloud"]:
        assert runner.invoke(app, [group, "--help"]).exit_code == 0


def test_k8s_cli_routes_context_and_errors():
    with patch("adsyslib.k8s.kubectl.Shell") as shell:
        shell.return_value.run.return_value = result('{"items": []}')
        invocation = CliRunner().invoke(
            app, ["k8s", "--context", "prod", "-n", "apps", "get", "pods"]
        )
        assert invocation.exit_code == 0, invocation.output
        assert json.loads(invocation.stdout) == {"items": []}
        assert shell.return_value.run.call_args.args[0][:5] == [
            "kubectl",
            "--context",
            "prod",
            "--namespace",
            "apps",
        ]
        shell.return_value.run.side_effect = APIError("unavailable")
        invocation = CliRunner().invoke(app, ["k8s", "get", "pods"])
        assert invocation.exit_code == 1
        assert "unavailable" in invocation.output
        assert "Traceback" not in invocation.output


def test_apt_sets_environment_inside_target_after_sudo():
    calls = []

    class Target:
        def run(self, cmd, check=False, log_output=True):
            calls.append(cmd)
            return result(code=1 if cmd[0] == "dpkg" else 0)

    assert Apt(shell=Target(), use_sudo=True).install("nginx")
    assert calls[-1] == [
        "sudo",
        "env",
        "DEBIAN_FRONTEND=noninteractive",
        "apt-get",
        "install",
        "-y",
        "nginx",
    ]
