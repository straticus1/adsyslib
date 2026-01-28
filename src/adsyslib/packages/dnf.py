import logging
from typing import List, Union
from adsyslib.core import run, ShellError
from adsyslib.packages.base import PackageManager

logger = logging.getLogger(__name__)

class Dnf(PackageManager):
    """DNF (RHEL/Fedora/Oracle Linux) package manager implementation."""

    def __init__(self, use_sudo: bool = None):
        """
        Initialize DNF package manager.

        Args:
            use_sudo: If True, prefix commands with sudo. If None (default), auto-detect.
        """
        if use_sudo is None:
            self.use_sudo = self._needs_sudo()
        else:
            self.use_sudo = use_sudo

    def _build_cmd(self, cmd: List[str]) -> List[str]:
        """Prepend sudo if needed."""
        if self.use_sudo:
            return ["sudo"] + cmd
        return cmd

    def install(self, packages: Union[str, List[str]], update: bool = False) -> bool:
        pkg_list = self._ensure_list(packages)
        if not pkg_list:
            return True

        # Idempotency: filter out installed
        to_install = [p for p in pkg_list if not self.is_installed(p)]

        if not to_install:
            logger.info(f"All packages already installed: {pkg_list}")
            return True

        # DNF usually updates metadata automatically, but we can force check-update if requested
        if update:
            self.update()

        logger.info(f"Installing packages: {to_install}")
        try:
            cmd = self._build_cmd(["dnf", "install", "-y"] + to_install)
            run(cmd, check=True)
            return True
        except ShellError as e:
            logger.error(f"Failed to install packages {to_install}: {e}")
            raise

    def uninstall(self, packages: Union[str, List[str]]) -> bool:
        pkg_list = self._ensure_list(packages)
        if not pkg_list:
            return True
        
        logger.info(f"Uninstalling packages: {pkg_list}")
        try:
            cmd = self._build_cmd(["dnf", "remove", "-y"] + pkg_list)
            run(cmd, check=True)
            return True
        except ShellError as e:
            logger.error(f"Failed to uninstall packages {pkg_list}: {e}")
            raise

    def is_installed(self, package: str) -> bool:
        # rpm -q <package>
        res = run(["rpm", "-q", package], check=False, log_output=False)
        return res.exit_code == 0

    def update(self) -> bool:
        logger.info("Checking for package updates...")
        try:
            # dnf check-update returns 100 if updates available, 0 if nothing, 1 on error
            cmd = self._build_cmd(["dnf", "check-update"])
            res = run(cmd, check=False)
            if res.exit_code in (0, 100):
                return True
            raise ShellError(res)
        except ShellError as e:
            logger.warning(f"Failed to check updates (might be non-fatal): {e}")
            return False
