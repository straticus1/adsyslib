import logging
import time
from typing import Optional, Union

from adsyslib.core import AdsysError, ShellConnectionError

try:
    import docker
    from docker.errors import DockerException, NotFound
    from docker.models.containers import Container
except ImportError:  # optional dependency — pip install 'adsyslib[container]'
    docker = None
    DockerException = NotFound = Container = None

logger = logging.getLogger(__name__)


class DockerManager:
    """
    High-level wrapper around docker-py for 10x developer experience.
    Handles connection, running containers with health checks, and cleanup.
    """

    def __init__(self, base_url: Optional[str] = None, timeout: float = 30.0):
        if docker is None:
            raise ImportError(
                "docker (docker-py) is required for DockerManager:\n"
                "  pip install 'adsyslib[container]'"
            )
        try:
            self.client = (
                docker.DockerClient(base_url=base_url, timeout=timeout)
                if base_url
                else docker.from_env(timeout=timeout)
            )
            self.client.ping()
        except DockerException as e:
            if getattr(self, "client", None) is not None:
                self.client.close()
            raise ShellConnectionError("Could not connect to Docker") from e

    def _check_client(self) -> None:
        if not self.client:
            raise ShellConnectionError("Docker client not initialized (daemon might be down).")

    def run_container(
        self,
        image: str,
        name: Optional[str] = None,
        detach: bool = True,
        ports: Optional[dict[str, str]] = None,
        env: Optional[dict[str, str]] = None,
        volumes: Optional[dict[str, dict[str, str]]] = None,
        command: Optional[Union[str, list[str]]] = None,
        wait_for_log: Optional[str] = None,
        wait_timeout: int = 30,
        auto_remove: bool = False,
        replace: bool = False,
        user: Optional[str] = None,
        read_only: bool = False,
        cap_drop: Optional[list[str]] = None,
        security_opt: Optional[list[str]] = None,
    ) -> Container:
        """
        Run a container with advanced features:
        - wait_for_log: Blocks until a specific string appears in logs.
        """
        self._check_client()
        if wait_timeout <= 0:
            raise ValueError("wait_timeout must be positive")
        if wait_for_log and not detach:
            raise ValueError("wait_for_log requires detach=True")

        # Pull if missing
        try:
            self.client.images.get(image)
        except NotFound:
            logger.info(f"Pulling image {image}...")
            self.client.images.pull(image)

        # Cleanup existing if needed
        if name:
            try:
                existing = self.client.containers.get(name)
                if not replace:
                    raise AdsysError(
                        f"Container {name!r} already exists; pass replace=True to replace it"
                    )
                logger.info(f"Removing existing container {name}...")
                existing.remove(force=True)
            except NotFound:
                pass

        logger.info(f"Starting container {name or image}...")
        container = self.client.containers.run(
            image,
            name=name,
            detach=detach,
            ports=ports,
            environment=env,
            volumes=volumes,
            command=command,
            remove=auto_remove,
            user=user,
            read_only=read_only,
            cap_drop=cap_drop,
            security_opt=security_opt,
        )

        if wait_for_log and detach:
            logger.info(f"Waiting for log pattern '{wait_for_log}' in {container.name}...")
            deadline = time.monotonic() + wait_timeout
            try:
                while time.monotonic() < deadline:
                    logs = container.logs(stream=False, tail=1000).decode("utf-8", "replace")
                    if wait_for_log in logs:
                        break
                    container.reload()
                    if container.status in {"exited", "dead"}:
                        raise AdsysError("Container exited before becoming ready")
                    time.sleep(min(0.1, max(0, deadline - time.monotonic())))
                else:
                    raise AdsysError(f"Container readiness timed out after {wait_timeout}s")
            except Exception:
                container.stop()
                raise

        return container

    def stop_container(self, name_or_id: str, timeout: int = 10) -> None:
        self._check_client()
        try:
            container = self.client.containers.get(name_or_id)
            container.stop(timeout=timeout)
            logger.info(f"Stopped container {name_or_id}")
        except NotFound:
            logger.warning(f"Container {name_or_id} not found to stop.")

    def get_container_ip(self, container: Container) -> str:
        """Helper to get primary IP address of a container."""
        container.reload()
        return container.attrs["NetworkSettings"]["IPAddress"]

    def close(self) -> None:
        """Release the Docker API connection."""
        if self.client is not None:
            self.client.close()
            self.client = None

    def __enter__(self) -> "DockerManager":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
