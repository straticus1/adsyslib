"""Hermetic lifecycle tests for cloud and container integrations."""

from unittest.mock import MagicMock, patch

import pytest

from adsyslib.core import AdsysError


@pytest.fixture(autouse=True)
def docker_exceptions(monkeypatch):
    from adsyslib.container import manager

    if manager.NotFound is None:

        class NotFound(Exception):
            pass

        monkeypatch.setattr(manager, "NotFound", NotFound)


def docker_manager():
    from adsyslib.container.manager import DockerManager

    manager = object.__new__(DockerManager)
    manager.client = MagicMock()
    return manager


def test_existing_container_is_never_silently_deleted():
    manager = docker_manager()
    with pytest.raises(AdsysError, match="replace=True"):
        manager.run_container("image", name="database")
    manager.client.containers.get.return_value.remove.assert_not_called()
    manager.client.containers.run.assert_not_called()


def test_explicit_container_replacement_and_security_options():
    manager = docker_manager()
    manager.run_container(
        "image",
        name="database",
        replace=True,
        user="1001",
        read_only=True,
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
    )
    manager.client.containers.get.return_value.remove.assert_called_once_with(force=True)
    options = manager.client.containers.run.call_args.kwargs
    assert options["read_only"] is True
    assert options["user"] == "1001"
    assert options["cap_drop"] == ["ALL"]


def test_silent_container_readiness_times_out_and_stops():
    manager = docker_manager()
    container = manager.client.containers.run.return_value
    container.logs.return_value = b""
    container.status = "running"
    with (
        patch("adsyslib.container.manager.time.monotonic", side_effect=[0, 0, 10, 10]),
        patch("adsyslib.container.manager.time.sleep"),
        pytest.raises(AdsysError, match="timed out"),
    ):
        manager.run_container("image", wait_for_log="ready", wait_timeout=1)
    container.stop.assert_called_once()


def test_container_early_exit_is_not_success():
    manager = docker_manager()
    container = manager.client.containers.run.return_value
    container.logs.return_value = b"error"
    container.status = "exited"
    with pytest.raises(AdsysError, match="exited"):
        manager.run_container("image", wait_for_log="ready")
    container.stop.assert_called_once()


def test_container_ready_and_context_cleanup():
    manager = docker_manager()
    client = manager.client
    client.containers.run.return_value.logs.return_value = b"ready"
    with manager:
        manager.run_container("image", wait_for_log="ready")
    client.close.assert_called_once()


def test_aws_all_reservation_pages():
    from adsyslib.cloud.aws import AWSProvider

    provider = object.__new__(AWSProvider)
    provider.ec2 = MagicMock()
    provider.ec2.get_paginator.return_value.paginate.return_value = [
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-one",
                            "State": {"Name": "running"},
                            "InstanceType": "t3.micro",
                        }
                    ]
                }
            ]
        },
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-two",
                            "State": {"Name": "stopped"},
                            "InstanceType": "t3.micro",
                        }
                    ]
                }
            ]
        },
    ]
    assert [item["id"] for item in provider.list_instances()] == ["i-one", "i-two"]


def test_dockerfile_fields_do_not_inject_instructions():
    from adsyslib.container.builder import DockerfileBuilder, PackageAwareBuilder

    with pytest.raises(ValueError):
        DockerfileBuilder("ubuntu\nRUN touch /owned")
    with pytest.raises(ValueError):
        DockerfileBuilder("ubuntu").env("KEY\nRUN", "x")
    with pytest.raises(ValueError):
        PackageAwareBuilder("ubuntu").install(["nginx; id"])
    assert (
        'COPY ["file with spaces", "/app/file"]'
        in DockerfileBuilder("ubuntu").copy("file with spaces", "/app/file").build()
    )


def test_terraform_apply_requires_explicit_intent():
    from adsyslib.iac.terraform import TerraformRunner

    with patch("adsyslib.iac.terraform.run") as execute:
        terraform = TerraformRunner(timeout=5)
        with pytest.raises(ValueError, match="saved plan"):
            terraform.apply()
        execute.assert_not_called()
        terraform.apply(plan_file="reviewed.tfplan")
        assert "reviewed.tfplan" in execute.call_args.args[0]
        assert "-auto-approve" not in execute.call_args.args[0]
        assert execute.call_args.kwargs["sensitive"] is True
        assert execute.call_args.kwargs["timeout"] == 5
        terraform.apply(auto_approve=True)
        assert "-auto-approve" in execute.call_args.args[0]
