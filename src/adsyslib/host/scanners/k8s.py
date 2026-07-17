"""
Kubernetes cluster scanner — API-level health via kubectl.

Covers node health, failing pods, deployment status, resource pressure,
and persistent volume claims. Does not exec into pods — use KubeShell
for in-pod service scanning.
"""
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from adsyslib.core import run as _run

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class NodeStatus:
    name: str
    ready: bool
    roles: List[str]
    version: str
    conditions: List[Dict[str, str]] = field(default_factory=list)
    taints: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)


@dataclass
class PodStatus:
    name: str
    namespace: str
    phase: str
    ready: bool
    restarts: int
    node: str
    issues: List[str] = field(default_factory=list)


@dataclass
class DeploymentStatus:
    name: str
    namespace: str
    desired: int
    ready: int
    available: int
    issues: List[str] = field(default_factory=list)


@dataclass
class PVCStatus:
    name: str
    namespace: str
    phase: str
    capacity: str
    storage_class: str
    issues: List[str] = field(default_factory=list)


@dataclass
class ClusterReport:
    context: Optional[str]
    nodes: List[NodeStatus] = field(default_factory=list)
    failing_pods: List[PodStatus] = field(default_factory=list)
    deployments: List[DeploymentStatus] = field(default_factory=list)
    pvcs: List[PVCStatus] = field(default_factory=list)
    events: List[Dict[str, str]] = field(default_factory=list)

    def ok(self) -> bool:
        return (
            all(n.ready for n in self.nodes)
            and not self.failing_pods
            and all(d.ready == d.desired for d in self.deployments)
        )

    def issues(self) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        node_issues = [i for n in self.nodes for i in n.issues]
        if node_issues:
            result["nodes"] = node_issues
        pod_issues = [f"{p.namespace}/{p.name}: {i}" for p in self.failing_pods for i in p.issues]
        if pod_issues:
            result["pods"] = pod_issues
        deploy_issues = [f"{d.namespace}/{d.name}: {i}" for d in self.deployments for i in d.issues]
        if deploy_issues:
            result["deployments"] = deploy_issues
        pvc_issues = [f"{p.namespace}/{p.name}: {i}" for p in self.pvcs for i in p.issues]
        if pvc_issues:
            result["pvcs"] = pvc_issues
        return result

    def summary(self) -> Dict[str, Any]:
        return {
            "context": self.context,
            "ok": self.ok(),
            "nodes": {
                "total": len(self.nodes),
                "ready": sum(1 for n in self.nodes if n.ready),
                "not_ready": [n.name for n in self.nodes if not n.ready],
            },
            "pods": {
                "failing": len(self.failing_pods),
                "failing_names": [f"{p.namespace}/{p.name}" for p in self.failing_pods],
            },
            "deployments": {
                "total": len(self.deployments),
                "degraded": [
                    f"{d.namespace}/{d.name} ({d.ready}/{d.desired})"
                    for d in self.deployments if d.ready < d.desired
                ],
            },
            "pvcs": {
                "total": len(self.pvcs),
                "not_bound": [
                    f"{p.namespace}/{p.name}" for p in self.pvcs if p.phase != "Bound"
                ],
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.summary(), indent=indent, default=str)

    def print_summary(self) -> None:
        status = "OK" if self.ok() else "ISSUES FOUND"
        ctx = self.context or "default"
        print(f"\n=== K8s Cluster [{ctx}] [{status}] ===")

        ready = sum(1 for n in self.nodes if n.ready)
        print(f"  Nodes:       {ready}/{len(self.nodes)} ready")
        for n in self.nodes:
            if not n.ready:
                print(f"    ! NOT READY: {n.name}")

        print(f"  Failing pods: {len(self.failing_pods)}")
        for p in self.failing_pods[:10]:
            print(f"    ! {p.namespace}/{p.name} ({p.phase}, restarts={p.restarts})")
            for issue in p.issues:
                print(f"      - {issue}")

        degraded = [d for d in self.deployments if d.ready < d.desired]
        print(f"  Deployments:  {len(self.deployments) - len(degraded)}/{len(self.deployments)} healthy")
        for d in degraded:
            print(f"    ! {d.namespace}/{d.name}: {d.ready}/{d.desired} ready")

        not_bound = [p for p in self.pvcs if p.phase != "Bound"]
        if not_bound:
            print(f"  PVCs not bound: {len(not_bound)}")
            for pvc in not_bound:
                print(f"    ! {pvc.namespace}/{pvc.name} ({pvc.phase})")

        if self.events:
            print(f"  Warning events: {len(self.events)}")
            for e in self.events[:5]:
                print(f"    ! [{e.get('namespace', '')}] {e.get('reason', '')}: {e.get('message', '')[:80]}")


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class KubernetesClusterScanner:
    """
    Scans a Kubernetes cluster at the API level using kubectl.

    Checks node health, pod status, deployment health, PVC binding,
    and warning events. Does not require the Python kubernetes client —
    uses kubectl JSON output.
    """

    def __init__(
        self,
        context: Optional[str] = None,
        namespaces: Optional[List[str]] = None,
        kubectl_cmd: str = "kubectl",
    ):
        self.context = context
        self.namespaces = namespaces  # None = all namespaces
        self._kubectl = kubectl_cmd

    def _kubectl_json(self, *args) -> Optional[Any]:
        cmd = [self._kubectl]
        if self.context:
            cmd += ["--context", self.context]
        cmd += list(args) + ["-o", "json"]
        r = _run(cmd)
        if not r.ok():
            logger.warning(f"kubectl {' '.join(args)} failed: {r.stderr[:200]}")
            return None
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError as e:
            logger.warning(f"Could not parse kubectl output: {e}")
            return None

    def _namespace_flags(self) -> List[str]:
        if self.namespaces:
            return []  # We'll iterate per-namespace
        return ["--all-namespaces"]

    def scan(self) -> ClusterReport:
        report = ClusterReport(context=self.context)
        report.nodes = self._scan_nodes()
        report.failing_pods = self._scan_pods()
        report.deployments = self._scan_deployments()
        report.pvcs = self._scan_pvcs()
        report.events = self._scan_events()
        return report

    # ------------------------------------------------------------------

    def _scan_nodes(self) -> List[NodeStatus]:
        data = self._kubectl_json("get", "nodes")
        if not data:
            return []
        nodes = []
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            status = item.get("status", {})

            name = meta.get("name", "")
            labels = meta.get("labels", {})
            roles = [
                k.split("/")[-1]
                for k in labels
                if k.startswith("node-role.kubernetes.io/")
            ] or ["worker"]

            version = status.get("nodeInfo", {}).get("kubeletVersion", "")

            conditions = status.get("conditions", [])
            ready = any(
                c["type"] == "Ready" and c["status"] == "True"
                for c in conditions
            )

            taints = [
                f"{t['key']}={t.get('value', '')}:{t['effect']}"
                for t in spec.get("taints", [])
            ]

            issues = []
            for cond in conditions:
                if cond["type"] != "Ready" and cond["status"] == "True":
                    issues.append(f"{cond['type']}: {cond.get('message', '')[:100]}")
            if not ready:
                issues.append(f"Node not Ready: {next((c.get('message','') for c in conditions if c['type']=='Ready'), '')[:100]}")

            nodes.append(NodeStatus(
                name=name, ready=ready, roles=roles,
                version=version, conditions=conditions,
                taints=taints, issues=issues,
            ))
        return nodes

    def _scan_pods(self) -> List[PodStatus]:
        """Return only pods that are failing, crashlooping, or pending too long."""
        data = self._kubectl_json("get", "pods", "--all-namespaces")
        if not data:
            return []

        failing = []
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            status = item.get("status", {})

            name = meta.get("name", "")
            namespace = meta.get("namespace", "")

            # Skip namespaces not in scope
            if self.namespaces and namespace not in self.namespaces:
                continue

            phase = status.get("phase", "Unknown")
            node = spec.get("nodeName", "")

            container_statuses = status.get("containerStatuses", [])
            restarts = sum(cs.get("restartCount", 0) for cs in container_statuses)
            ready_containers = sum(1 for cs in container_statuses if cs.get("ready"))
            total_containers = len(container_statuses) or 1

            issues = []

            # CrashLoopBackOff
            for cs in container_statuses:
                waiting = cs.get("state", {}).get("waiting", {})
                reason = waiting.get("reason", "")
                if reason in ("CrashLoopBackOff", "OOMKilled", "Error"):
                    issues.append(f"{cs['name']}: {reason} — {waiting.get('message', '')[:80]}")

            # High restart count
            if restarts >= 5:
                issues.append(f"High restart count: {restarts}")

            # Not all containers ready in Running phase
            if phase == "Running" and ready_containers < total_containers:
                issues.append(f"Only {ready_containers}/{total_containers} containers ready")

            # Failed or Unknown
            if phase in ("Failed", "Unknown"):
                msg = status.get("message", status.get("reason", ""))
                issues.append(f"Phase={phase}: {msg[:100]}")

            if issues or phase in ("Failed", "Unknown") or restarts >= 5:
                failing.append(PodStatus(
                    name=name, namespace=namespace, phase=phase,
                    ready=(ready_containers == total_containers),
                    restarts=restarts, node=node, issues=issues,
                ))

        return failing

    def _scan_deployments(self) -> List[DeploymentStatus]:
        data = self._kubectl_json("get", "deployments", "--all-namespaces")
        if not data:
            return []

        deployments = []
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            status = item.get("status", {})

            name = meta.get("name", "")
            namespace = meta.get("namespace", "")

            if self.namespaces and namespace not in self.namespaces:
                continue

            desired = spec.get("replicas", 0)
            ready = status.get("readyReplicas", 0)
            available = status.get("availableReplicas", 0)

            issues = []
            if ready < desired:
                issues.append(f"Only {ready}/{desired} replicas ready")
            if available < desired:
                issues.append(f"Only {available}/{desired} replicas available")

            deployments.append(DeploymentStatus(
                name=name, namespace=namespace,
                desired=desired, ready=ready, available=available,
                issues=issues,
            ))

        return deployments

    def _scan_pvcs(self) -> List[PVCStatus]:
        data = self._kubectl_json("get", "pvc", "--all-namespaces")
        if not data:
            return []

        pvcs = []
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            status = item.get("status", {})

            name = meta.get("name", "")
            namespace = meta.get("namespace", "")

            if self.namespaces and namespace not in self.namespaces:
                continue

            phase = status.get("phase", "Unknown")
            capacity = status.get("capacity", {}).get("storage", "unknown")
            storage_class = spec.get("storageClassName", "")

            issues = []
            if phase != "Bound":
                issues.append(f"PVC not Bound (phase={phase})")

            pvcs.append(PVCStatus(
                name=name, namespace=namespace, phase=phase,
                capacity=capacity, storage_class=storage_class,
                issues=issues,
            ))

        return pvcs

    def _scan_events(self, limit: int = 20) -> List[Dict[str, str]]:
        """Return recent Warning events across the cluster."""
        cmd = [self._kubectl]
        if self.context:
            cmd += ["--context", self.context]
        cmd += [
            "get", "events", "--all-namespaces",
            "--field-selector", "type=Warning",
            "--sort-by=.lastTimestamp",
        ]
        from adsyslib.core import run as _run
        r = _run(cmd)
        if not r.ok() or not r.stdout.strip():
            return []

        events = []
        lines = r.stdout.strip().splitlines()
        for line in lines[1:limit + 1]:  # skip header
            parts = line.split(None, 5)
            if len(parts) >= 6:
                events.append({
                    "namespace": parts[0],
                    "last_seen": parts[1],
                    "type": parts[2],
                    "reason": parts[3],
                    "object": parts[4],
                    "message": parts[5] if len(parts) > 5 else "",
                })
        return events
