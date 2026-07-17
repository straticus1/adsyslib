"""
Drift detection — compare two AuditPackages to surface regressions over time.

Usage:
    baseline = load_package("audit_jan.json")
    current  = build_package(["fedramp"])
    report   = compare_packages(baseline, current)
    report.save("drift.json")
    print(report.summary())
"""
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .package import AuditPackage, ControlResult


@dataclass
class ControlDrift:
    control_id: str
    control_title: str
    baseline_status: str
    current_status: str
    baseline_evidence: str = ""
    current_evidence: str = ""

    @property
    def regressed(self) -> bool:
        """pass → fail: highest priority finding."""
        return self.baseline_status == "pass" and self.current_status == "fail"

    @property
    def resolved(self) -> bool:
        """fail → pass: improvement."""
        return self.baseline_status == "fail" and self.current_status == "pass"

    @property
    def changed(self) -> bool:
        return self.baseline_status != self.current_status


@dataclass
class DriftReport:
    baseline_package_id: str
    current_package_id: str
    baseline_generated_at: str
    current_generated_at: str
    hostname: str
    frameworks: list[str]
    control_drifts: list[ControlDrift] = field(default_factory=list)
    new_controls: list[str] = field(default_factory=list)
    removed_controls: list[str] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def regressions(self) -> list[ControlDrift]:
        return [d for d in self.control_drifts if d.regressed]

    @property
    def resolutions(self) -> list[ControlDrift]:
        return [d for d in self.control_drifts if d.resolved]

    def summary(self) -> dict[str, Any]:
        unchanged = [d for d in self.control_drifts if not d.changed]
        return {
            "baseline_package_id": self.baseline_package_id,
            "current_package_id": self.current_package_id,
            "baseline_generated_at": self.baseline_generated_at,
            "current_generated_at": self.current_generated_at,
            "hostname": self.hostname,
            "regressions": len(self.regressions),
            "resolutions": len(self.resolutions),
            "unchanged": len(unchanged),
            "new_controls": self.new_controls,
            "removed_controls": self.removed_controls,
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())


def compare_packages(baseline: AuditPackage, current: AuditPackage) -> DriftReport:
    """
    Compare two AuditPackages and return a DriftReport.

    Controls are diffed by ID. Regressions (pass→fail) sort first
    so the most critical findings are immediately visible.
    """
    baseline_map = {c.id: c for c in baseline.controls}
    current_map = {c.id: c for c in current.controls}

    baseline_ids = set(baseline_map)
    current_ids = set(current_map)

    drifts: list[ControlDrift] = []
    for ctrl_id in sorted(baseline_ids & current_ids):
        b = baseline_map[ctrl_id]
        c = current_map[ctrl_id]
        drifts.append(ControlDrift(
            control_id=ctrl_id,
            control_title=b.title,
            baseline_status=b.status,
            current_status=c.status,
            baseline_evidence=b.evidence,
            current_evidence=c.evidence,
        ))

    # Regressions first, then resolutions, then unchanged — all sorted by ID within group
    drifts.sort(key=lambda d: (0 if d.regressed else 1 if d.resolved else 2, d.control_id))

    return DriftReport(
        baseline_package_id=baseline.package_id,
        current_package_id=current.package_id,
        baseline_generated_at=baseline.generated_at,
        current_generated_at=current.generated_at,
        hostname=current.hostname,
        frameworks=current.frameworks,
        control_drifts=drifts,
        new_controls=sorted(current_ids - baseline_ids),
        removed_controls=sorted(baseline_ids - current_ids),
    )


def load_package(path: str) -> AuditPackage:
    """Deserialize an AuditPackage from a saved JSON file."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    controls = [ControlResult(**c) for c in data.pop("controls", [])]
    return AuditPackage(controls=controls, **data)
