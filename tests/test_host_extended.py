"""
Tests for DockerShell, KubeShell, KubernetesClusterScanner, and FleetReport.
Uses FakeProcess to intercept local subprocess calls without real Docker/kubectl.
"""
import json
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from adsyslib.core import CommandResult
from adsyslib.host.docker_shell import DockerShell
from adsyslib.host.kube_shell import KubeShell
from adsyslib.host.fleet import FleetReport, scan_fleet
from adsyslib.host.scanners.k8s import (
    KubernetesClusterScanner, ClusterReport,
    NodeStatus, PodStatus, DeploymentStatus, PVCStatus,
)
from adsyslib.host.session import HostReport, HostSession
from adsyslib.host.scanners import ScanResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _result(stdout="", exit_code=0):
    return CommandResult(stdout=stdout, stderr="", exit_code=exit_code, command="", duration=0.0)


def _patch_run(responses: Dict[str, str]):
    """
    Returns a mock for adsyslib.core.run that maps command strings to stdout.
    Unrecognised commands return exit_code=1.
    """
    def fake_run(cmd, check=False, **_):
        if isinstance(cmd, list):
            key = " ".join(str(c) for c in cmd)
        else:
            key = str(cmd)
        # Prefix match — let callers use partial command strings as keys
        for pattern, stdout in responses.items():
            if key == pattern or key.startswith(pattern):
                return _result(stdout=stdout)
        return _result(exit_code=1)
    return fake_run


# ---------------------------------------------------------------------------
# DockerShell
# ---------------------------------------------------------------------------

class TestDockerShell:
    def _shell(self, cmds=None):
        shell = DockerShell("my-container")
        shell.run = lambda cmd, **_: _result(
            stdout={
                " ".join(cmd) if isinstance(cmd, list) else cmd: v
                for k, v in (cmds or {}).items()
            }.get(" ".join(cmd) if isinstance(cmd, list) else cmd, ""),
            exit_code=0 if (cmds or {}).get(
                " ".join(cmd) if isinstance(cmd, list) else cmd
            ) is not None else 1,
        )
        return shell

    def test_label(self):
        shell = DockerShell("nginx-proxy")
        assert shell.host == "docker:nginx-proxy"

    def test_read_text_uses_cat(self):
        results = {}

        def fake_run(cmd, **_):
            key = " ".join(cmd) if isinstance(cmd, list) else cmd
            if "cat /etc/passwd" in key:
                return _result(stdout="root:x:0:0:root:/root:/bin/bash")
            return _result(exit_code=1)

        shell = DockerShell("test")
        shell.run = fake_run
        text = shell.read_text("/etc/passwd")
        assert text == "root:x:0:0:root:/root:/bin/bash"

    def test_read_text_missing_returns_none(self):
        shell = DockerShell("test")
        shell.run = lambda cmd, **_: _result(exit_code=1)
        assert shell.read_text("/no/such/file") is None

    def test_path_exists_true(self):
        shell = DockerShell("test")
        shell.run = lambda cmd, **_: _result(exit_code=0)
        assert shell.path_exists("/etc/passwd") is True

    def test_path_exists_false(self):
        shell = DockerShell("test")
        shell.run = lambda cmd, **_: _result(exit_code=1)
        assert shell.path_exists("/no/such/path") is False

    def test_is_dir(self):
        shell = DockerShell("test")
        shell.run = lambda cmd, **_: _result(exit_code=0)
        assert shell.is_dir("/etc") is True

    def test_list_dir(self):
        shell = DockerShell("test")
        shell.run = lambda cmd, **_: _result(stdout="nginx.conf\nconf.d\n")
        assert shell.list_dir("/etc/nginx") == ["nginx.conf", "conf.d"]

    def test_path_stat_parsed(self):
        shell = DockerShell("test")
        shell.run = lambda cmd, **_: _result(stdout="755 0 1700000000")
        stat = shell.path_stat("/etc")
        assert stat["permissions"] == "755"
        assert stat["owner_uid"] == 0
        assert stat["mtime"] == 1700000000.0

    def test_path_stat_missing(self):
        shell = DockerShell("test")
        shell.run = lambda cmd, **_: _result(exit_code=1)
        assert shell.path_stat("/no/such") is None

    def test_connect_verifies_running(self):
        with patch("adsyslib.host.docker_shell._run") as mock_run:
            mock_run.return_value = _result(stdout="true")
            shell = DockerShell("running-container")
            result = shell.connect()
            assert result is shell

    def test_connect_raises_if_not_running(self):
        with patch("adsyslib.host.docker_shell._run") as mock_run:
            mock_run.return_value = _result(stdout="false")
            shell = DockerShell("stopped-container")
            with pytest.raises(RuntimeError, match="not running"):
                shell.connect()


# ---------------------------------------------------------------------------
# KubeShell
# ---------------------------------------------------------------------------

class TestKubeShell:
    def test_label(self):
        shell = KubeShell("my-pod", namespace="prod")
        assert shell.host == "k8s:prod/my-pod"

    def test_base_cmd_no_container(self):
        shell = KubeShell("my-pod", namespace="prod")
        base = shell._base()
        assert "exec" in base
        assert "my-pod" in base
        assert "-n" in base
        assert "prod" in base
        assert "--" in base
        assert "-c" not in base

    def test_base_cmd_with_container(self):
        shell = KubeShell("my-pod", namespace="prod", container="sidecar")
        base = shell._base()
        assert "-c" in base
        assert "sidecar" in base

    def test_base_cmd_with_context(self):
        shell = KubeShell("my-pod", namespace="prod", context="prod-cluster")
        base = shell._base()
        assert "--context" in base
        assert "prod-cluster" in base

    def test_read_text(self):
        shell = KubeShell("my-pod", namespace="default")
        shell.run = lambda cmd, **_: _result(stdout="file contents")
        assert shell.read_text("/etc/config") == "file contents"

    def test_path_exists(self):
        shell = KubeShell("my-pod")
        shell.run = lambda cmd, **_: _result(exit_code=0)
        assert shell.path_exists("/etc") is True

    def test_connect_raises_if_not_running(self):
        with patch("adsyslib.host.kube_shell._run") as mock_run:
            mock_run.return_value = _result(stdout="Pending")
            shell = KubeShell("pending-pod", namespace="default")
            with pytest.raises(RuntimeError, match="not Running"):
                shell.connect()

    def test_connect_ok_if_running(self):
        with patch("adsyslib.host.kube_shell._run") as mock_run:
            mock_run.return_value = _result(stdout="Running")
            shell = KubeShell("running-pod", namespace="default")
            result = shell.connect()
            assert result is shell


# ---------------------------------------------------------------------------
# KubernetesClusterScanner
# ---------------------------------------------------------------------------

def _node_item(name, ready=True, version="v1.28.0", roles=None):
    condition_status = "True" if ready else "False"
    roles = roles or ["worker"]
    labels = {f"node-role.kubernetes.io/{r}": "" for r in roles}
    return {
        "metadata": {"name": name, "labels": labels},
        "spec": {"taints": []},
        "status": {
            "nodeInfo": {"kubeletVersion": version},
            "conditions": [
                {"type": "Ready", "status": condition_status, "message": ""},
            ],
        },
    }


def _pod_item(name, namespace="default", phase="Running", restarts=0, node="node-1", crash=False):
    waiting = {"reason": "CrashLoopBackOff", "message": "back-off"} if crash else {}
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"nodeName": node},
        "status": {
            "phase": phase,
            "containerStatuses": [{
                "name": "app",
                "ready": not crash and phase == "Running",
                "restartCount": restarts,
                "state": {"waiting": waiting} if crash else {"running": {}},
            }],
        },
    }


def _deployment_item(name, namespace="default", desired=3, ready=3):
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"replicas": desired},
        "status": {"readyReplicas": ready, "availableReplicas": ready},
    }


def _pvc_item(name, namespace="default", phase="Bound", storage="10Gi", sc="standard"):
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"storageClassName": sc},
        "status": {"phase": phase, "capacity": {"storage": storage}},
    }


class TestKubernetesClusterScanner:
    def _scanner(self, kubectl_responses):
        scanner = KubernetesClusterScanner()
        scanner._kubectl_json = lambda *args: kubectl_responses.get(" ".join(args))
        scanner._scan_events = lambda limit=20: []
        return scanner

    def test_nodes_all_ready(self):
        scanner = self._scanner({
            "get nodes": {"items": [_node_item("node-1"), _node_item("node-2")]},
            "get pods --all-namespaces": {"items": []},
            "get deployments --all-namespaces": {"items": []},
            "get pvc --all-namespaces": {"items": []},
        })
        report = scanner.scan()
        assert len(report.nodes) == 2
        assert all(n.ready for n in report.nodes)
        assert report.nodes[0].name == "node-1"

    def test_not_ready_node_has_issue(self):
        scanner = self._scanner({
            "get nodes": {"items": [_node_item("bad-node", ready=False)]},
            "get pods --all-namespaces": {"items": []},
            "get deployments --all-namespaces": {"items": []},
            "get pvc --all-namespaces": {"items": []},
        })
        report = scanner.scan()
        assert not report.nodes[0].ready
        assert report.nodes[0].issues

    def test_crashloop_pod_detected(self):
        scanner = self._scanner({
            "get nodes": {"items": []},
            "get pods --all-namespaces": {"items": [
                _pod_item("crasher", crash=True),
            ]},
            "get deployments --all-namespaces": {"items": []},
            "get pvc --all-namespaces": {"items": []},
        })
        report = scanner.scan()
        assert len(report.failing_pods) == 1
        assert any("CrashLoopBackOff" in i for i in report.failing_pods[0].issues)

    def test_high_restart_pod_detected(self):
        scanner = self._scanner({
            "get nodes": {"items": []},
            "get pods --all-namespaces": {"items": [
                _pod_item("restarter", restarts=10),
            ]},
            "get deployments --all-namespaces": {"items": []},
            "get pvc --all-namespaces": {"items": []},
        })
        report = scanner.scan()
        assert len(report.failing_pods) == 1
        assert any("restart" in i for i in report.failing_pods[0].issues)

    def test_healthy_pod_not_in_failing(self):
        scanner = self._scanner({
            "get nodes": {"items": []},
            "get pods --all-namespaces": {"items": [
                _pod_item("healthy", restarts=0),
            ]},
            "get deployments --all-namespaces": {"items": []},
            "get pvc --all-namespaces": {"items": []},
        })
        report = scanner.scan()
        assert report.failing_pods == []

    def test_degraded_deployment_has_issue(self):
        scanner = self._scanner({
            "get nodes": {"items": []},
            "get pods --all-namespaces": {"items": []},
            "get deployments --all-namespaces": {"items": [
                _deployment_item("api", desired=3, ready=1),
            ]},
            "get pvc --all-namespaces": {"items": []},
        })
        report = scanner.scan()
        assert report.deployments[0].issues

    def test_healthy_deployment_no_issue(self):
        scanner = self._scanner({
            "get nodes": {"items": []},
            "get pods --all-namespaces": {"items": []},
            "get deployments --all-namespaces": {"items": [
                _deployment_item("api", desired=3, ready=3),
            ]},
            "get pvc --all-namespaces": {"items": []},
        })
        report = scanner.scan()
        assert report.deployments[0].issues == []

    def test_unbound_pvc_has_issue(self):
        scanner = self._scanner({
            "get nodes": {"items": []},
            "get pods --all-namespaces": {"items": []},
            "get deployments --all-namespaces": {"items": []},
            "get pvc --all-namespaces": {"items": [
                _pvc_item("data-vol", phase="Pending"),
            ]},
        })
        report = scanner.scan()
        assert report.pvcs[0].issues

    def test_cluster_ok_when_all_healthy(self):
        scanner = self._scanner({
            "get nodes": {"items": [_node_item("node-1")]},
            "get pods --all-namespaces": {"items": []},
            "get deployments --all-namespaces": {"items": [
                _deployment_item("api", desired=2, ready=2),
            ]},
            "get pvc --all-namespaces": {"items": [
                _pvc_item("vol-1", phase="Bound"),
            ]},
        })
        report = scanner.scan()
        assert report.ok() is True

    def test_cluster_not_ok_when_node_not_ready(self):
        scanner = self._scanner({
            "get nodes": {"items": [_node_item("bad-node", ready=False)]},
            "get pods --all-namespaces": {"items": []},
            "get deployments --all-namespaces": {"items": []},
            "get pvc --all-namespaces": {"items": []},
        })
        report = scanner.scan()
        assert report.ok() is False

    def test_summary_structure(self):
        scanner = self._scanner({
            "get nodes": {"items": [_node_item("node-1")]},
            "get pods --all-namespaces": {"items": []},
            "get deployments --all-namespaces": {"items": []},
            "get pvc --all-namespaces": {"items": []},
        })
        report = scanner.scan()
        s = report.summary()
        assert "nodes" in s
        assert "pods" in s
        assert "deployments" in s
        assert "pvcs" in s

    def test_node_roles_parsed(self):
        item = _node_item("control-plane-1", roles=["control-plane", "master"])
        scanner = self._scanner({
            "get nodes": {"items": [item]},
            "get pods --all-namespaces": {"items": []},
            "get deployments --all-namespaces": {"items": []},
            "get pvc --all-namespaces": {"items": []},
        })
        report = scanner.scan()
        assert "control-plane" in report.nodes[0].roles


# ---------------------------------------------------------------------------
# FleetReport / scan_fleet
# ---------------------------------------------------------------------------

def _make_host_report(host, ok=True):
    issues = [] if ok else ["something is wrong"]
    results = {
        "nginx": ScanResult(service="nginx", active=ok, issues=issues),
    }
    return HostReport(host=host, results=results)


class TestFleetReport:
    def test_ok_when_all_hosts_ok(self):
        report = FleetReport(host_reports={
            "web-01": _make_host_report("web-01", ok=True),
            "web-02": _make_host_report("web-02", ok=True),
        })
        assert report.ok() is True

    def test_not_ok_when_any_host_has_issues(self):
        report = FleetReport(host_reports={
            "web-01": _make_host_report("web-01", ok=True),
            "web-02": _make_host_report("web-02", ok=False),
        })
        assert report.ok() is False

    def test_not_ok_when_connection_error(self):
        report = FleetReport(
            host_reports={"web-01": _make_host_report("web-01", ok=True)},
            errors={"web-02": "Connection refused"},
        )
        assert report.ok() is False

    def test_hosts_with_issues(self):
        report = FleetReport(host_reports={
            "web-01": _make_host_report("web-01", ok=True),
            "web-02": _make_host_report("web-02", ok=False),
        })
        assert report.hosts_with_issues() == ["web-02"]

    def test_all_issues_includes_errors(self):
        report = FleetReport(
            host_reports={"web-01": _make_host_report("web-01", ok=False)},
            errors={"web-02": "Connection refused"},
        )
        issues = report.all_issues()
        assert "web-01" in issues
        assert "_connection_errors" in issues

    def test_summary_keys(self):
        report = FleetReport(host_reports={
            "web-01": _make_host_report("web-01"),
        })
        s = report.summary()
        assert "total_hosts" in s
        assert "scanned" in s
        assert "hosts_ok" in s
        assert "hosts_with_issues" in s

    def test_to_json(self):
        report = FleetReport(host_reports={"web-01": _make_host_report("web-01")})
        data = json.loads(report.to_json())
        assert "hosts" in data

    def test_save(self, tmp_path):
        report = FleetReport(host_reports={"web-01": _make_host_report("web-01")})
        out = str(tmp_path / "fleet.json")
        report.save(out)
        data = json.loads(open(out).read())
        assert "hosts" in data


class TestScanFleet:
    def test_scan_fleet_parallel(self):
        """scan_fleet connects/scans/disconnects each session."""
        sessions = []
        for i in range(3):
            host = f"web-0{i}"
            session = MagicMock()
            session.host = host
            session.connect.return_value = session
            session.scan_all.return_value = _make_host_report(host)
            sessions.append(session)

        report = scan_fleet(sessions, workers=3)
        assert len(report.host_reports) == 3
        assert report.ok() is True
        for session in sessions:
            session.connect.assert_called_once()
            session.disconnect.assert_called_once()

    def test_scan_fleet_connection_error_isolated(self):
        """A failed host doesn't prevent others from scanning."""
        good_session = MagicMock()
        good_session.host = "web-01"
        good_session.connect.return_value = good_session
        good_session.scan_all.return_value = _make_host_report("web-01")

        bad_session = MagicMock()
        bad_session.host = "web-02"
        bad_session.connect.side_effect = ConnectionRefusedError("refused")

        report = scan_fleet([good_session, bad_session], workers=2)
        assert "web-01" in report.host_reports
        assert "web-02" in report.errors
        assert "web-02" not in report.host_reports


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------

class TestFactories:
    def test_docker_container_factory(self):
        from adsyslib.host import docker_container
        session = docker_container("my-container")
        assert isinstance(session, HostSession)
        assert session.host == "docker:my-container"

    def test_kube_pod_factory(self):
        from adsyslib.host import kube_pod
        session = kube_pod("my-pod", namespace="prod")
        assert isinstance(session, HostSession)
        assert session.host == "k8s:prod/my-pod"

    def test_ssh_to_host_factory(self):
        from adsyslib.host import ssh_to_host
        session = ssh_to_host("10.0.0.1", user="admin")
        assert isinstance(session, HostSession)
        assert session.host == "10.0.0.1"
