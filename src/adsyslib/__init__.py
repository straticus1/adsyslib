"""
adsyslib - Advanced Systems Library for Python.

A production-grade library for system administration, container management,
cloud operations, infrastructure-as-code automation, and compliance auditing.

Example Usage:
    from adsyslib.core import run, Shell
    from adsyslib.packages import get_package_manager
    from adsyslib.container import DockerManager, PackageAwareBuilder
    from adsyslib.cloud import get_cloud_provider
    from adsyslib.iac import TerraformRunner, AnsibleRunner
    from adsyslib.compliance import build_package, compare_packages
"""

__version__ = "0.1.0"

# Core
# Compliance
from adsyslib.compliance import (
    AuditPackage,
    ControlResult,
    DriftReport,
    build_package,
    compare_packages,
    load_package,
)
from adsyslib.core import (
    AdsysError,
    CommandResult,
    Shell,
    ShellConnectionError,
    ShellError,
    run,
)

# Host scanning
from adsyslib.host import HostReport, HostSession, ssh_to_host

# Interactive
from adsyslib.interact import InteractiveSession

# IO Utils
from adsyslib.io_utils import IOCatcher, capture_io

# Logging
from adsyslib.logger import configure_logging, get_logger

# Protocol
from adsyslib.protocols import ShellProtocol

__all__ = [
    # Core
    "run",
    "Shell",
    "CommandResult",
    "ShellProtocol",
    "AdsysError",
    "ShellError",
    "ShellConnectionError",
    # Logging
    "configure_logging",
    "get_logger",
    # IO
    "IOCatcher",
    "capture_io",
    # Interactive
    "InteractiveSession",
    # Compliance
    "build_package",
    "compare_packages",
    "load_package",
    "AuditPackage",
    "ControlResult",
    "DriftReport",
    # Host scanning
    "ssh_to_host",
    "HostSession",
    "HostReport",
    # Version
    "__version__",
]
