import logging
from typing import Optional, Union

from adsyslib.core import ShellError, run
from adsyslib.packages.base import PackageManager
from adsyslib.protocols import ShellProtocol

logger = logging.getLogger(__name__)


class Apt(PackageManager):
    """APT (Debian/Ubuntu) package manager implementation."""

    def __init__(
        self,
        use_sudo: Optional[bool] = None,
        shell: Optional[ShellProtocol] = None,
        executable: str = "apt-get",
    ):
        """
        Initialize Apt package manager.

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
        command = ["env", "DEBIAN_FRONTEND=noninteractive"] + cmd
        return ["sudo"] + command if self.use_sudo else command

    def install(self, packages: Union[str, list[str]], update: bool = False) -> bool:
        pkg_list = self._ensure_list(packages)
        if not pkg_list:
            return True

        # Idempotency check: filter out already installed packages
        to_install = [p for p in pkg_list if not self.is_installed(p)]

        if not to_install:
            logger.info(f"All packages already installed: {pkg_list}")
            return True

        if update:
            self.update()

        logger.info(f"Installing packages: {to_install}")
        try:
            # DEBIAN_FRONTEND=noninteractive prevents prompts
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
        # dpkg -s <package> returns 0 if installed, 1 if not
        res = self._run(["dpkg", "-s", package], check=False, log_output=False)
        return res.exit_code == 0 and "Status: install ok installed" in res.stdout

    def update(self) -> bool:
        logger.info("Updating apt package lists...")
        try:
            cmd = self._build_cmd([self.executable, "update"])
            self._run(cmd, check=True)
            return True
        except ShellError as e:
            logger.error(f"Failed to update apt lists: {e}")
            raise
