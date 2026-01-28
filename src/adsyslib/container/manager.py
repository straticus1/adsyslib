import logging
import time
from typing import Optional, Dict, List, Any, Union
import docker
from docker.errors import DockerException, NotFound, APIError
from docker.models.containers import Container

logger = logging.getLogger(__name__)

class DockerManager:
    """
    High-level wrapper around docker-py for 10x developer experience.
    Handles connection, running containers with health checks, and cleanup.
    """
    def __init__(self, base_url: str = None):
        try:
            self.client = docker.DockerClient(base_url=base_url or "unix://var/run/docker.sock")
            self.client.ping()
        except DockerException as e:
            logger.warning(f"Could not connect to Docker: {e}")
            self.client = None

    def _check_client(self):
        if not self.client:
            raise RuntimeError("Docker client not initialized (daemon might be down).")

    def run_container(
        self, 
        image: str, 
        name: Optional[str] = None, 
        detach: bool = True,
        ports: Optional[Dict[str, str]] = None,
        env: Optional[Dict[str, str]] = None,
        volumes: Optional[Dict[str, Dict[str, str]]] = None,
        command: Optional[Union[str, List[str]]] = None,
        wait_for_log: Optional[str] = None,
        wait_timeout: int = 30,
        auto_remove: bool = False
    ) -> Container:
        """
        Run a container with advanced features:
        - wait_for_log: Blocks until a specific string appears in logs.
        """
        self._check_client()
        
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
            remove=auto_remove
        )

        if wait_for_log and detach:
            logger.info(f"Waiting for log pattern '{wait_for_log}' in {container.name}...")
            start_time = time.time()
            found = False

            try:
                for line in container.logs(stream=True, follow=True):
                    line_str = line.decode('utf-8').strip()
                    logger.debug(f"Container log: {line_str}")

                    if wait_for_log in line_str:
                        logger.info(f"Found match: {line_str}")
                        found = True
                        break

                    if time.time() - start_time > wait_timeout:
                        logger.error(f"Timeout waiting for log '{wait_for_log}'")
                        container.stop()
                        raise TimeoutError(f"Container did not match log '{wait_for_log}' in {wait_timeout}s")
            except Exception as e:
                if not found:
                    logger.error(f"Error while waiting for log: {e}")
                    container.stop()
                    raise

        return container

    def stop_container(self, name_or_id: str, timeout: int = 10):
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
        return container.attrs['NetworkSettings']['IPAddress']
