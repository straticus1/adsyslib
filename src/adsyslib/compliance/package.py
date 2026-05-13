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

    def validate(self) -> List[str]:
        """
        Validate that this AuditPackage meets ERS ingest requirements.

        Returns a list of validation error strings.  An empty list means the
        package is valid and ready for ERS ingest.

        ERS requires:
        - package_id: non-empty UUID string
        - generated_at: non-empty ISO-8601 timestamp
        - hostname: non-empty string
        - frameworks: at least one known framework
        - controls: at least one ControlResult
        - Each ControlResult must have: id, title, status in allowed values,
          framework non-empty
        """
        errors = []
        known_frameworks = {"fedramp", "hipaa", "sox", "glba"}
        allowed_statuses = {"pass", "fail", "not_applicable", "error"}

        if not self.package_id or not self.package_id.strip():
            errors.append("package_id is empty")
        if not self.generated_at or not self.generated_at.strip():
            errors.append("generated_at is empty")
        if not self.hostname or not self.hostname.strip():
            errors.append("hostname is empty")
        if not self.frameworks:
            errors.append("frameworks list is empty")
        else:
            unknown = set(self.frameworks) - known_frameworks
            if unknown:
                errors.append(f"unknown framework(s): {sorted(unknown)}")
        if not self.controls:
            errors.append("controls list is empty — package has no evaluated controls")
        for i, ctrl in enumerate(self.controls):
            prefix = f"controls[{i}] (id={ctrl.id!r})"
            if not ctrl.id or not ctrl.id.strip():
                errors.append(f"{prefix}: id is empty")
            if not ctrl.title or not ctrl.title.strip():
                errors.append(f"{prefix}: title is empty")
            if ctrl.status not in allowed_statuses:
                errors.append(
                    f"{prefix}: invalid status {ctrl.status!r} "
                    f"(allowed: {sorted(allowed_statuses)})"
                )
            if not ctrl.framework or not ctrl.framework.strip():
                errors.append(f"{prefix}: framework is empty")
        return errors

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
