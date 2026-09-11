"""Read-only capability discovery; never connects to services or reads credentials."""

import importlib.util
import platform
import shutil
from importlib.metadata import version
from typing import Any


def capabilities() -> dict[str, Any]:
    """Describe installed optional integrations and locally available executables."""
    return {
        "version": version("adsyslib"),
        "python": platform.python_version(),
        "platform": platform.system(),
        "integrations": {
            extra: importlib.util.find_spec(module) is not None
            for extra, module in {
                "remote": "paramiko",
                "aws": "boto3",
                "oracle": "oci",
                "container": "docker",
                "interact": "pexpect",
            }.items()
        },
        "executables": {
            name: shutil.which(name)
            for name in (
                "ssh",
                "docker",
                "kubectl",
                "terraform",
                "ansible-playbook",
                "apt-get",
                "dnf",
                "yum",
            )
        },
    }
