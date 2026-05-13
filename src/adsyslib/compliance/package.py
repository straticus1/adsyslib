import csv
import io
import json
import socket
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class ControlResult:
    id: str
    title: str
    status: str  # pass | fail | not_applicable | error
    evidence: str = ""
    framework: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditPackage:
    frameworks: List[str]
    auth: Dict[str, Any] = field(default_factory=dict)
    config_mgmt_proof: Dict[str, Any] = field(default_factory=dict)
    admin: Dict[str, Any] = field(default_factory=dict)
    entitlements: Dict[str, Any] = field(default_factory=dict)
    logging: Dict[str, Any] = field(default_factory=dict)
    network: Dict[str, Any] = field(default_factory=dict)
    storage: Dict[str, Any] = field(default_factory=dict)
    patching: Dict[str, Any] = field(default_factory=dict)
    controls: List[ControlResult] = field(default_factory=list)
    package_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    hostname: str = field(default_factory=socket.getfqdn)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_yaml(self) -> str:
        if not HAS_YAML:
            raise ImportError("pyyaml is required: pip install pyyaml")
        return yaml.dump(self.to_dict(), default_flow_style=False, allow_unicode=True)

    def to_csv(self) -> str:
        """Flatten controls to one row per control result."""
        buf = io.StringIO()
        fieldnames = [
            "package_id", "generated_at", "hostname", "frameworks",
            "control_id", "control_title", "status", "framework", "evidence",
        ]
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        frameworks_str = "|".join(self.frameworks)
        for ctrl in self.controls:
            writer.writerow({
                "package_id": self.package_id,
                "generated_at": self.generated_at,
                "hostname": self.hostname,
                "frameworks": frameworks_str,
                "control_id": ctrl.id,
                "control_title": ctrl.title,
                "status": ctrl.status,
                "framework": ctrl.framework,
                "evidence": ctrl.evidence,
            })
        return buf.getvalue()

    def save(self, path: str, fmt: str = "json") -> None:
        fmt = fmt.lower().lstrip(".")
        if fmt == "json":
            content = self.to_json()
        elif fmt in ("yaml", "yml"):
            content = self.to_yaml()
        elif fmt == "csv":
            content = self.to_csv()
        else:
            raise ValueError(f"Unsupported format '{fmt}'. Use json, yaml, or csv.")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def summary(self) -> Dict[str, Any]:
        counts = {"pass": 0, "fail": 0, "not_applicable": 0, "error": 0}
        for c in self.controls:
            counts[c.status] = counts.get(c.status, 0) + 1
        return {
            "package_id": self.package_id,
            "generated_at": self.generated_at,
            "hostname": self.hostname,
            "frameworks": self.frameworks,
            "control_counts": counts,
            "total": len(self.controls),
        }
