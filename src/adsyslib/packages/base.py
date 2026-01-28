from abc import ABC, abstractmethod
from typing import List, Union
import os

class PackageManager(ABC):
    """Abstract base class for package managers (apt, dnf, etc)."""

    def _is_root(self) -> bool:
        """Check if running as root."""
        return os.geteuid() == 0

    def _needs_sudo(self) -> bool:
        """Check if we need sudo (not root and sudo available)."""
        if self._is_root():
            return False
        # Check if sudo is available
        import shutil
        return shutil.which("sudo") is not None

    @abstractmethod
    def install(self, packages: Union[str, List[str]], update: bool = False) -> bool:
        """
        Install one or more packages.
        
        Args:
            packages: Single package name or list of names.
            update: Whether to update package lists before installing.
        """
        pass

    @abstractmethod
    def uninstall(self, packages: Union[str, List[str]]) -> bool:
        """Uninstall one or more packages."""
        pass

    @abstractmethod
    def is_installed(self, package: str) -> bool:
        """Check if a specific package is installed."""
        pass

    @abstractmethod
    def update(self) -> bool:
        """Update package repository lists."""
        pass

    def _ensure_list(self, packages: Union[str, List[str]]) -> List[str]:
        if isinstance(packages, str):
            return [packages]
        return packages
