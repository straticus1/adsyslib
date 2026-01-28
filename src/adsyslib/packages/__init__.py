"""
Package management utilities.
Supports apt (Debian/Ubuntu), dnf (RHEL/Fedora), and auto-detection.
"""
from adsyslib.packages.base import PackageManager
from adsyslib.packages.apt import Apt
from adsyslib.packages.dnf import Dnf
from adsyslib.core import run

def get_package_manager() -> PackageManager:
    """
    Auto-detect and return the appropriate package manager for the current system.
    
    Returns:
        PackageManager: An Apt or Dnf instance.
    
    Raises:
        RuntimeError: If no supported package manager is found.
    """
    # Check for apt-get (Debian/Ubuntu)
    res = run("which apt-get", check=False, log_output=False)
    if res.ok():
        return Apt()
    
    # Check for dnf (RHEL 8+, Fedora)
    res = run("which dnf", check=False, log_output=False)
    if res.ok():
        return Dnf()
    
    # Check for yum (RHEL 7, CentOS 7) - falls back to Dnf wrapper
    res = run("which yum", check=False, log_output=False)
    if res.ok():
        # yum is often symlinked to dnf on modern systems, but use Dnf anyway
        return Dnf()
    
    raise RuntimeError("No supported package manager found (apt-get, dnf, or yum).")

__all__ = ["PackageManager", "Apt", "Dnf", "get_package_manager"]
