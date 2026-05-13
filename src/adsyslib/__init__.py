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
from adsyslib.core import run, Shell, CommandResult, ShellError

# Logging
from adsyslib.logger import configure_logging, get_logger

# IO Utils
from adsyslib.io_utils import IOCatcher, capture_io

# Interactive
from adsyslib.interact import InteractiveSession

# Compliance
from adsyslib.compliance import build_package, compare_packages, load_package, AuditPackage, ControlResult, DriftReport

__all__ = [
    # Core
    "run",
    "Shell", 
    "CommandResult",
    "ShellError",
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
    # Version
    "__version__",
]
