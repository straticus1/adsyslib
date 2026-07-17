"""
Logging collector — audit logging configuration evidence.
Maps to controls: AU-2, AU-9.
"""
import logging
from typing import Any, Dict, List, Optional

from adsyslib.core import Shell
from adsyslib.protocols import ShellProtocol

logger = logging.getLogger(__name__)


def _auditd_status(ctx: ShellProtocol) -> Dict[str, Any]:
    result = ctx.run(["systemctl", "is-active", "auditd"], check=False)
    active = result.stdout.strip() == "active"

    rules_text = ctx.read_text("/etc/audit/audit.rules") or ""
    rules = [ln.strip() for ln in rules_text.splitlines() if ln.strip() and not ln.startswith("#")]

    return {"active": active, "rules_count": len(rules), "rules": rules[:20]}


def _syslog_status(ctx: ShellProtocol) -> Dict[str, Any]:
    for svc in ("rsyslog", "syslog-ng", "syslogd"):
        result = ctx.run(["systemctl", "is-active", svc], check=False)
        if result.stdout.strip() == "active":
            return {"service": svc, "active": True}
    return {"service": None, "active": False}


def _log_forwarding(ctx: ShellProtocol) -> Dict[str, Any]:
    targets: List[Dict[str, str]] = []
    paths_to_check: List[str] = []

    if ctx.path_exists("/etc/rsyslog.conf"):
        paths_to_check.append("/etc/rsyslog.conf")
    if ctx.is_dir("/etc/rsyslog.d"):
        paths_to_check += [
            f"/etc/rsyslog.d/{f}"
            for f in ctx.list_dir("/etc/rsyslog.d")
            if f.endswith(".conf")
        ]

    for path in paths_to_check:
        content = ctx.read_text(path)
        if not content:
            continue
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("*.*") and "@" in stripped:
                targets.append({"file": path, "rule": stripped})

    return {"remote_targets": targets, "forwarding_configured": bool(targets)}


def _audit_log_permissions(ctx: ShellProtocol) -> Dict[str, Any]:
    log_dir = "/var/log/audit"
    if not ctx.path_exists(log_dir):
        return {"path": log_dir, "exists": False}
    stat_info = ctx.path_stat(log_dir)
    if not stat_info:
        return {"path": log_dir, "exists": True}
    return {
        "path": log_dir,
        "exists": True,
        "permissions": stat_info.get("permissions"),
        "owner_uid": stat_info.get("owner_uid"),
    }


def collect(ctx: Optional[ShellProtocol] = None) -> Dict[str, Any]:
    """Collect audit logging configuration evidence."""
    ctx = ctx or Shell()
    return {
        "auditd": _auditd_status(ctx),
        "syslog": _syslog_status(ctx),
        "log_forwarding": _log_forwarding(ctx),
        "audit_log_permissions": _audit_log_permissions(ctx),
    }
