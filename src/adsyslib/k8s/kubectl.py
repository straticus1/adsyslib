"""
Kubectl wrapper for managing Kubernetes resources.
Provides high-level methods for common kubectl operations.
"""
import logging
import json
import yaml
from typing import List, Dict, Any, Optional, Union
from adsyslib.core import run, Shell, ShellError

logger = logging.getLogger(__name__)


class KubectlRunner:
    """
    High-level wrapper around kubectl for managing Kubernetes resources.
    """

    def __init__(
        self,
        context: Optional[str] = None,
        namespace: Optional[str] = None,
        kubeconfig: Optional[str] = None,
    ):
        """
        Initialize kubectl runner.

        Args:
            context: Kubernetes context to use
            namespace: Default namespace for operations
            kubeconfig: Path to kubeconfig file
        """
        self.context = context
        self.namespace = namespace
        self.kubeconfig = kubeconfig
        self.shell = Shell()

    def _build_base_cmd(self, extra_args: List[str] = None) -> List[str]:
        """Build base kubectl command with context/namespace/kubeconfig."""
        cmd = ["kubectl"]

        if self.kubeconfig:
            cmd.extend(["--kubeconfig", self.kubeconfig])
        if self.context:
            cmd.extend(["--context", self.context])
        if self.namespace:
            cmd.extend(["--namespace", self.namespace])

        if extra_args:
            cmd.extend(extra_args)

        return cmd

    def run_command(
        self, args: List[str], check: bool = True, parse_json: bool = False
    ) -> Union[Dict, List, str]:
        """
        Run a kubectl command.

        Args:
            args: Command arguments (without 'kubectl')
            check: Raise error on failure
            parse_json: Parse output as JSON

        Returns:
            Command output (parsed JSON if parse_json=True, otherwise string)
        """
        cmd = self._build_base_cmd(args)
        result = self.shell.run(cmd, check=check)

        if parse_json and result.ok():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.warning("Failed to parse kubectl output as JSON")
                return result.stdout

        return result.stdout

    # ==================== RESOURCE MANAGEMENT ====================

    def apply(self, file_path: str, namespace: Optional[str] = None) -> str:
        """
        Apply a configuration file.

        Args:
            file_path: Path to YAML/JSON file
            namespace: Override default namespace
        """
        args = ["apply", "-f", file_path]
        if namespace:
            args.extend(["-n", namespace])

        logger.info(f"Applying configuration from {file_path}")
        return self.run_command(args)

    def delete(
        self,
        resource_type: str,
        name: str,
        namespace: Optional[str] = None,
        force: bool = False,
    ):
        """
        Delete a resource.

        Args:
            resource_type: Type of resource (pod, service, deployment, etc.)
            name: Name of the resource
            namespace: Override default namespace
            force: Force deletion
        """
        args = ["delete", resource_type, name]
        if namespace:
            args.extend(["-n", namespace])
        if force:
            args.append("--force")

        logger.info(f"Deleting {resource_type}/{name}")
        return self.run_command(args)

    def get(
        self,
        resource_type: str,
        name: Optional[str] = None,
        namespace: Optional[str] = None,
        output: str = "json",
        all_namespaces: bool = False,
    ) -> Union[Dict, List]:
        """
        Get resource(s).

        Args:
            resource_type: Type of resource
            name: Optional specific resource name
            namespace: Override default namespace
            output: Output format (json, yaml, wide, etc.)
            all_namespaces: Get from all namespaces

        Returns:
            Parsed JSON/YAML or raw output
        """
        args = ["get", resource_type]
        if name:
            args.append(name)
        if namespace:
            args.extend(["-n", namespace])
        if all_namespaces:
            args.append("--all-namespaces")
        if output:
            args.extend(["-o", output])

        logger.debug(f"Getting {resource_type}" + (f"/{name}" if name else ""))
        return self.run_command(args, parse_json=(output == "json"))

    def describe(
        self, resource_type: str, name: str, namespace: Optional[str] = None
    ) -> str:
        """Describe a resource in detail."""
        args = ["describe", resource_type, name]
        if namespace:
            args.extend(["-n", namespace])

        return self.run_command(args)

    # ==================== POD OPERATIONS ====================

    def list_pods(
        self,
        namespace: Optional[str] = None,
        label_selector: Optional[str] = None,
        field_selector: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        List pods with optional filters.

        Args:
            namespace: Override default namespace
            label_selector: Label selector (e.g., "app=nginx")
            field_selector: Field selector (e.g., "status.phase=Running")

        Returns:
            List of pod dictionaries
        """
        args = ["get", "pods", "-o", "json"]
        if namespace:
            args.extend(["-n", namespace])
        if label_selector:
            args.extend(["-l", label_selector])
        if field_selector:
            args.extend(["--field-selector", field_selector])

        result = self.run_command(args, parse_json=True)
        return result.get("items", []) if isinstance(result, dict) else []

    def logs(
        self,
        pod_name: str,
        namespace: Optional[str] = None,
        container: Optional[str] = None,
        follow: bool = False,
        tail: Optional[int] = None,
        previous: bool = False,
    ) -> str:
        """
        Get pod logs.

        Args:
            pod_name: Name of the pod
            namespace: Override default namespace
            container: Specific container name
            follow: Stream logs
            tail: Number of recent lines to show
            previous: Show logs from previous instance

        Returns:
            Log output
        """
        args = ["logs", pod_name]
        if namespace:
            args.extend(["-n", namespace])
        if container:
            args.extend(["-c", container])
        if follow:
            args.append("-f")
        if tail:
            args.extend(["--tail", str(tail)])
        if previous:
            args.append("--previous")

        return self.run_command(args)

    def exec(
        self,
        pod_name: str,
        command: List[str],
        namespace: Optional[str] = None,
        container: Optional[str] = None,
        stdin: bool = False,
        tty: bool = False,
    ) -> str:
        """
        Execute a command in a pod.

        Args:
            pod_name: Name of the pod
            command: Command to execute
            namespace: Override default namespace
            container: Specific container name
            stdin: Pass stdin to container
            tty: Allocate a TTY

        Returns:
            Command output
        """
        args = ["exec", pod_name]
        if namespace:
            args.extend(["-n", namespace])
        if container:
            args.extend(["-c", container])
        if stdin:
            args.append("-i")
        if tty:
            args.append("-t")

        args.append("--")
        args.extend(command)

        return self.run_command(args)

    def port_forward(
        self,
        resource: str,
        ports: str,
        namespace: Optional[str] = None,
        background: bool = True,
    ):
        """
        Forward port(s) from a resource.

        Args:
            resource: Resource name (pod/name or service/name)
            ports: Port spec (e.g., "8080:80" or "8080")
            namespace: Override default namespace
            background: Run in background

        Note: Background port-forwarding requires additional process management
        """
        args = ["port-forward", resource, ports]
        if namespace:
            args.extend(["-n", namespace])

        cmd = self._build_base_cmd(args)
        logger.info(f"Port forwarding {resource} {ports}")

        if background:
            logger.warning(
                "Background port-forward not fully implemented - use kubectl directly or manage process"
            )

        return self.shell.run(cmd, check=False)

    # ==================== DEPLOYMENT MANAGEMENT ====================

    def scale(
        self,
        resource_type: str,
        name: str,
        replicas: int,
        namespace: Optional[str] = None,
    ) -> str:
        """Scale a deployment/replicaset/statefulset."""
        args = ["scale", resource_type, name, f"--replicas={replicas}"]
        if namespace:
            args.extend(["-n", namespace])

        logger.info(f"Scaling {resource_type}/{name} to {replicas} replicas")
        return self.run_command(args)

    def rollout_status(
        self, resource_type: str, name: str, namespace: Optional[str] = None
    ) -> str:
        """Check rollout status of a deployment."""
        args = ["rollout", "status", resource_type, name]
        if namespace:
            args.extend(["-n", namespace])

        return self.run_command(args)

    def rollout_restart(
        self, resource_type: str, name: str, namespace: Optional[str] = None
    ) -> str:
        """Restart a deployment."""
        args = ["rollout", "restart", resource_type, name]
        if namespace:
            args.extend(["-n", namespace])

        logger.info(f"Restarting {resource_type}/{name}")
        return self.run_command(args)

    # ==================== NAMESPACE MANAGEMENT ====================

    def create_namespace(self, name: str) -> str:
        """Create a namespace."""
        logger.info(f"Creating namespace: {name}")
        return self.run_command(["create", "namespace", name])

    def delete_namespace(self, name: str) -> str:
        """Delete a namespace."""
        logger.warning(f"Deleting namespace: {name}")
        return self.run_command(["delete", "namespace", name])

    def list_namespaces(self) -> List[Dict[str, Any]]:
        """List all namespaces."""
        result = self.run_command(["get", "namespaces", "-o", "json"], parse_json=True)
        return result.get("items", []) if isinstance(result, dict) else []

    # ==================== CONTEXT MANAGEMENT ====================

    def get_current_context(self) -> str:
        """Get current context."""
        return self.run_command(["config", "current-context"]).strip()

    def use_context(self, context: str):
        """Switch to a different context."""
        logger.info(f"Switching to context: {context}")
        self.run_command(["config", "use-context", context])
        self.context = context

    def list_contexts(self) -> List[str]:
        """List available contexts."""
        result = self.run_command(["config", "get-contexts", "-o", "name"])
        return [ctx.strip() for ctx in result.split("\n") if ctx.strip()]

    # ==================== UTILITY METHODS ====================

    def version(self) -> Dict[str, Any]:
        """Get kubectl and server version."""
        return self.run_command(["version", "-o", "json"], parse_json=True)

    def cluster_info(self) -> str:
        """Get cluster information."""
        return self.run_command(["cluster-info"])

    def top_nodes(self) -> str:
        """Show node resource usage (requires metrics-server)."""
        return self.run_command(["top", "nodes"])

    def top_pods(self, namespace: Optional[str] = None) -> str:
        """Show pod resource usage (requires metrics-server)."""
        args = ["top", "pods"]
        if namespace:
            args.extend(["-n", namespace])
        return self.run_command(args)
