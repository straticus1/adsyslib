"""
Admin collector — privileged account and system hardening evidence.
Maps to controls: AC-6, CM-6, CM-7.
"""
import logging
import re
from typing import Any, Dict, List, Optional

from adsyslib.compliance.context import CollectionContext, LocalContext

logger = logging.getLogger(__name__)

_SUDOERS_GRANT_RE = re.compile(r"^(%?[\w][\w-]*\s|ALL\s)")


def _parse_sudoers_text(text: str, source: str, lineno_offset: int = 1) -> List[Dict[str, Any]]:
    rules = []
    for i, line in enumerate(text.splitlines(), lineno_offset):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("@"):
            continue
        rule_type = None
        if stripped.startswith("Defaults"):
            rule_type = "default"
        elif _SUDOERS_GRANT_RE.match(stripped):
            rule_type = "grant"
        if rule_type:
            rules.append({"type": rule_type, "rule": stripped, "source": source, "line": i})
    return rules


def _privileged_accounts(ctx: CollectionContext) -> List[Dict[str, Any]]:
    text = None
    result = ctx.run("getent passwd", check=False)
    if result.ok() and result.stdout:
        text = result.stdout
    else:
        text = ctx.read_text("/etc/passwd") or ""

    accounts = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 4 and parts[2] == "0":
            accounts.append({
                "username": parts[0],
                "uid": 0,
                "gid": int(parts[3]) if parts[3].isdigit() else parts[3],
                "home": parts[5] if len(parts) > 5 else "",
                "shell": parts[6] if len(parts) > 6 else "",
            })
    return accounts


def _sshd_hardening(ctx: CollectionContext, path: str = "/etc/ssh/sshd_config") -> Dict[str, str]:
    settings: Dict[str, str] = {}
    text = ctx.read_text(path) or ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            settings[parts[0].lower()] = parts[1]

    keys = [
        "permitrootlogin", "passwordauthentication", "x11forwarding",
        "maxauthtries", "logingracetime", "permitemptypasswords",
        "clientaliveinterval", "clientalivecountmax",
    ]
    return {k: settings.get(k, "unknown") for k in keys}


def collect(ctx: Optional[CollectionContext] = None) -> Dict[str, Any]:
    """Collect administrative configuration evidence."""
    ctx = ctx or LocalContext()

    sudoers_files = ["/etc/sudoers"]
    if ctx.is_dir("/etc/sudoers.d"):
        sudoers_files += [
            f"/etc/sudoers.d/{f}"
            for f in sorted(ctx.list_dir("/etc/sudoers.d"))
            if not f.endswith("~")
        ]

    rules: List[Dict[str, Any]] = []
    for path in sudoers_files:
        text = ctx.read_text(path)
        if text:
            rules.extend(_parse_sudoers_text(text, source=path))

    return {
        "sudoers": rules,
        "privileged_accounts": _privileged_accounts(ctx),
        "sshd_hardening": _sshd_hardening(ctx),
    }
