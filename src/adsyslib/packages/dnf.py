import logging
from typing import Optional, Union

from adsyslib.core import ShellError, run
from adsyslib.packages.base import PackageManager
from adsyslib.protocols import ShellProtocol

logger = logging.getLogger(__name__)


class Dnf(PackageManager):
    """DNF (RHEL/Fedora/Oracle Linux) package manager implementation."""

    def __init__(
        self,
        use_sudo: Optional[bool] = None,
        shell: Optional[ShellProtocol] = None,
        executable: str = "dnf",
    ):
        """
        Initialize DNF package manager.

        Args:
            use_sudo: If True, prefix commands with sudo. If None (default), auto-detect.
        """
        self._run = shell.run if shell is not None else run
        self.executable = executable
        if use_sudo is None and shell is not None:
            self.use_sudo = self._run(["id", "-u"], check=True).stdout.strip() != "0"
        elif use_sudo is None:
            self.use_sudo = self._needs_sudo()
        else:
            self.use_sudo = use_sudo

    def _build_cmd(self, cmd: list[str]) -> list[str]:
        """Prepend sudo if needed."""
        if self.use_sudo:
            return ["sudo"] + cmd
        return cmd

    def install(self, packages: Union[str, list[str]], update: bool = False) -> bool:
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
            cmd = self._build_cmd([self.executable, "install", "-y"] + to_install)
            self._run(cmd, check=True)
            return True
        except ShellError as e:
            logger.error(f"Failed to install packages {to_install}: {e}")
            raise

    def uninstall(self, packages: Union[str, list[str]]) -> bool:
        pkg_list = self._ensure_list(packages)
        if not pkg_list:
            return True

        logger.info(f"Uninstalling packages: {pkg_list}")
        try:
            cmd = self._build_cmd([self.executable, "remove", "-y"] + pkg_list)
            self._run(cmd, check=True)
            return True
        except ShellError as e:
            logger.error(f"Failed to uninstall packages {pkg_list}: {e}")
            raise

    def is_installed(self, package: str) -> bool:
        self._ensure_list(package)
        # rpm -q <package>
        res = self._run(["rpm", "-q", package], check=False, log_output=False)
        return res.exit_code == 0

    def update(self) -> bool:
        logger.info("Checking for package updates...")
        try:
            # dnf check-update returns 100 if updates available, 0 if nothing, 1 on error
            cmd = self._build_cmd([self.executable, "check-update"])
            res = self._run(cmd, check=False)
            if res.exit_code in (0, 100):
                return True
            raise ShellError(res)
        except ShellError as e:
            logger.warning(f"Failed to check updates (might be non-fatal): {e}")
            return False
