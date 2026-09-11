"""
Package management utilities.
Supports apt (Debian/Ubuntu), dnf (RHEL/Fedora), and auto-detection.
"""

from typing import Optional

from adsyslib.core import AdsysError, Shell
from adsyslib.packages.apt import Apt
from adsyslib.packages.base import PackageManager
from adsyslib.packages.dnf import Dnf
from adsyslib.protocols import ShellProtocol


def get_package_manager(
    shell: Optional[ShellProtocol] = None, use_sudo: Optional[bool] = None
) -> PackageManager:
    """Detect apt, dnf or yum on the supplied shell (local by default)."""
    target = shell if shell is not None else Shell()
    for executable, manager in [("apt-get", Apt), ("dnf", Dnf), ("yum", Dnf)]:
        if target.run(["sh", "-c", f"command -v {executable}"], log_output=False).ok():
            return manager(use_sudo=use_sudo, shell=target, executable=executable)
    raise AdsysError("No supported package manager found (apt-get, dnf, or yum).")


__all__ = ["PackageManager", "Apt", "Dnf", "get_package_manager"]
