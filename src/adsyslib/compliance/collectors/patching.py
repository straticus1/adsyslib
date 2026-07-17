"""
Patching collector — patch status and malware protection evidence.
Maps to controls: SI-2, SI-3.
"""
import logging
from typing import Any, Optional

from adsyslib.core import Shell
from adsyslib.protocols import ShellProtocol

logger = logging.getLogger(__name__)


def _pending_apt(ctx: ShellProtocol) -> dict[str, Any]:
    result = ctx.run(["apt-get", "--simulate", "upgrade"], check=False)
    if not result.ok():
        return {"available": False}
    lines = result.stdout.splitlines()
    summary_line = next((line for line in lines if "upgraded," in line), "")
    pending_count = sum(1 for line in lines if line.startswith("Inst "))
    return {"available": True, "summary": summary_line.strip(), "pending_count": pending_count}


def _pending_dnf(ctx: ShellProtocol) -> dict[str, Any]:
    result = ctx.run(["dnf", "check-update", "--quiet"], check=False)
    # 0 = up-to-date, 100 = updates available
    if result.exit_code not in (0, 100):
        return {"available": False}
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    return {"available": result.exit_code == 100, "pending_count": len(lines)}


def _pending_updates(ctx: ShellProtocol) -> dict[str, Any]:
    if ctx.run(["which", "apt-get"], check=False).ok():
        return {"manager": "apt", **_pending_apt(ctx)}
    if ctx.run(["which", "dnf"], check=False).ok():
        return {"manager": "dnf", **_pending_dnf(ctx)}
    return {"manager": "unknown", "available": False}


def _malware_protection(ctx: ShellProtocol) -> dict[str, Any]:
    active_services: list[str] = []
    for svc in ("clamav-daemon", "clamd", "sophos-av", "falco", "osqueryd"):
        if ctx.run(["systemctl", "is-active", svc], check=False).stdout.strip() == "active":
            active_services.append(svc)

    installed_tools: list[str] = []
    for binary in ("clamscan", "freshclam", "falco", "osqueryi"):
        if ctx.run(["which", binary], check=False).ok():
            installed_tools.append(binary)

    return {
        "active_services": active_services,
        "installed_tools": installed_tools,
        "protection_active": bool(active_services),
        "tools_found": list(set(active_services + installed_tools)),
    }


def collect(ctx: Optional[ShellProtocol] = None) -> dict[str, Any]:
    """Collect patch status and malware protection evidence."""
    ctx = ctx or Shell()
    return {
        "pending_updates": _pending_updates(ctx),
        "malware_protection": _malware_protection(ctx),
    }
