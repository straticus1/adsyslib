"""
Contract tests: every shell implementation must satisfy ShellProtocol with
identical semantics (None/[]/False for missing paths, never raising).

Shell runs against a real tmp directory; DockerShell/KubeShell/RemoteShell run
against fakes so the suite is hermetic.
"""
import pytest

from adsyslib.core import CommandResult, Shell
from adsyslib.host.docker_shell import DockerShell
from adsyslib.host.kube_shell import KubeShell
from adsyslib.protocols import ShellProtocol
from adsyslib.remote import RemoteShell


def _result(stdout="", stderr="", exit_code=0, command="cmd"):
    return CommandResult(
        stdout=stdout, stderr=stderr, exit_code=exit_code, command=command, duration=0.0
    )


def _fake_exec_run(shell, tree):
    """Give a Docker/Kube shell a fake run() backed by a {path: content} tree."""

    def fake_run(cmd, check=False, **_):
        args = cmd if isinstance(cmd, list) else cmd.split()
        prog, rest = args[0], args[1:]
        if prog == "cat":
            path = rest[0]
            if path in tree and tree[path] is not None:
                return _result(stdout=tree[path])
            return _result(exit_code=1)
        if prog == "ls":
            path = rest[-1]
            entries = tree.get(path)
            if isinstance(entries, list):
                return _result(stdout="\n".join(entries))
            return _result(exit_code=1)
        if prog == "test":
            flag, path = rest[0], rest[1]
            if flag == "-e":
                return _result(exit_code=0 if path in tree else 1)
            if flag == "-d":
                return _result(exit_code=0 if isinstance(tree.get(path), list) else 1)
        if prog == "stat":
            path = rest[-1]
            if path in tree and tree[path] is not None:
                return _result(stdout="644 0 1700000000")
            return _result(exit_code=1)
        return _result(exit_code=127)

    shell.run = fake_run
    return shell


class FakeSFTPAttrs:
    st_mode = 0o100644
    st_uid = 0
    st_mtime = 1700000000.0


class FakeSFTP:
    """Minimal paramiko-SFTP stand-in over a {path: content} tree."""

    def __init__(self, tree):
        self.tree = tree

    def open(self, path, _mode="r"):
        if path not in self.tree or self.tree[path] is None:
            raise OSError(path)
        import io

        class _F(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

        return _F(self.tree[path].encode())

    def listdir(self, path):
        entries = self.tree.get(path)
        if not isinstance(entries, list):
            raise OSError(path)
        return entries

    def stat(self, path):
        if path not in self.tree:
            raise OSError(path)
        attrs = FakeSFTPAttrs()
        if isinstance(self.tree[path], list):
            attrs.st_mode = 0o040755
        return attrs


TREE = {
    "/etc/motd": "hello world",
    "/etc": ["motd"],
}


def make_shells(tmp_path):
    local = Shell(cwd=str(tmp_path))
    docker = _fake_exec_run(DockerShell("c1"), dict(TREE))
    kube = _fake_exec_run(KubeShell("p1"), dict(TREE))
    remote = RemoteShell("h", "u")
    remote._sftp = FakeSFTP(dict(TREE))
    return {"local": local, "docker": docker, "kube": kube, "remote": remote}


@pytest.fixture
def shells(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "motd").write_text("hello world")
    return make_shells(tmp_path)


PATHS = {
    "local": {"file": "etc/motd", "dir": "etc", "missing": "nope/missing"},
    "docker": {"file": "/etc/motd", "dir": "/etc", "missing": "/nope/missing"},
    "kube": {"file": "/etc/motd", "dir": "/etc", "missing": "/nope/missing"},
    "remote": {"file": "/etc/motd", "dir": "/etc", "missing": "/nope/missing"},
}

ALL = ["local", "docker", "kube", "remote"]


@pytest.mark.parametrize("name", ALL)
def test_satisfies_protocol(shells, name):
    assert isinstance(shells[name], ShellProtocol)


@pytest.mark.parametrize("name", ALL)
def test_read_text_present(shells, name):
    assert shells[name].read_text(PATHS[name]["file"]) == "hello world"


@pytest.mark.parametrize("name", ALL)
def test_read_text_missing_is_none(shells, name):
    assert shells[name].read_text(PATHS[name]["missing"]) is None


@pytest.mark.parametrize("name", ALL)
def test_list_dir_present(shells, name):
    assert shells[name].list_dir(PATHS[name]["dir"]) == ["motd"]


@pytest.mark.parametrize("name", ALL)
def test_list_dir_missing_is_empty(shells, name):
    assert shells[name].list_dir(PATHS[name]["missing"]) == []


@pytest.mark.parametrize("name", ALL)
def test_path_exists(shells, name):
    assert shells[name].path_exists(PATHS[name]["file"]) is True
    assert shells[name].path_exists(PATHS[name]["missing"]) is False


@pytest.mark.parametrize("name", ALL)
def test_is_dir(shells, name):
    assert shells[name].is_dir(PATHS[name]["dir"]) is True
    assert shells[name].is_dir(PATHS[name]["file"]) is False


@pytest.mark.parametrize("name", ALL)
def test_path_stat_shape(shells, name):
    st = shells[name].path_stat(PATHS[name]["file"])
    assert st is not None
    assert set(st) == {"permissions", "owner_uid", "mtime"}
    assert isinstance(st["permissions"], str) and len(st["permissions"]) == 3
    assert shells[name].path_stat(PATHS[name]["missing"]) is None


def test_local_shell_lifecycle(tmp_path):
    with Shell(cwd=str(tmp_path)) as sh:
        assert sh.connect() is sh
    sh.disconnect()  # idempotent


def test_local_run_still_works(tmp_path):
    sh = Shell(cwd=str(tmp_path))
    assert sh.run(["pwd"]).stdout.strip().endswith(tmp_path.name)


def test_collectors_accept_bare_shell(tmp_path):
    """The whole point: a collector runs against any ShellProtocol, no wrapper."""
    from adsyslib.compliance.collectors import auth

    data = auth.collect(ctx=_fake_exec_run(DockerShell("c1"), dict(TREE)))
    assert isinstance(data, dict)


def test_deprecated_contexts_still_work():
    from adsyslib.compliance.context import LocalContext, RemoteContext

    with pytest.warns(DeprecationWarning):
        ctx = LocalContext()
    assert isinstance(ctx, ShellProtocol)

    with pytest.warns(DeprecationWarning):
        wrapped = RemoteContext(Shell())
    assert wrapped.path_exists("/") is True
