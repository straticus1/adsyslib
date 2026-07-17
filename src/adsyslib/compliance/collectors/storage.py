"""
Storage security collector — encryption at rest evidence.
Maps to controls: SC-28.
"""
import json
import logging
from typing import Any, Dict, List, Optional

from adsyslib.core import Shell
from adsyslib.protocols import ShellProtocol

logger = logging.getLogger(__name__)


def _luks_volumes(ctx: ShellProtocol) -> List[Dict[str, Any]]:
    result = ctx.run(["lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT", "--json"], check=False)
    if not result.ok():
        return []
    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"Could not parse lsblk output: {e}")
        return []

    luks: List[Dict[str, Any]] = []

    def walk(devices: List[Dict]) -> None:
        for d in devices:
            if d.get("fstype") == "crypto_LUKS" or d.get("type") == "crypt":
                luks.append({
                    "name": d.get("name"),
                    "type": d.get("type"),
                    "fstype": d.get("fstype"),
                    "mountpoint": d.get("mountpoint"),
                })
            if d.get("children"):
                walk(d["children"])

    walk(data.get("blockdevices", []))
    return luks


def _crypttab(ctx: ShellProtocol) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    text = ctx.read_text("/etc/crypttab") or ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            parts = stripped.split()
            entries.append({
                "name": parts[0] if len(parts) > 0 else None,
                "device": parts[1] if len(parts) > 1 else None,
                "keyfile": parts[2] if len(parts) > 2 else None,
                "options": parts[3] if len(parts) > 3 else None,
            })
    return entries


def collect(ctx: Optional[ShellProtocol] = None) -> Dict[str, Any]:
    """Collect encryption-at-rest evidence."""
    ctx = ctx or Shell()
    luks = _luks_volumes(ctx)
    crypt = _crypttab(ctx)
    return {
        "luks_volumes": luks,
        "crypttab": crypt,
        "encryption_detected": bool(luks) or bool(crypt),
    }
