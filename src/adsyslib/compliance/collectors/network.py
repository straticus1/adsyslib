"""
Network security collector — TLS and cipher enforcement evidence.
Maps to controls: SC-8.
"""
import logging
import re
from typing import Any, Dict, List, Optional

from adsyslib.core import Shell
from adsyslib.protocols import ShellProtocol

logger = logging.getLogger(__name__)

WEAK_CIPHERS = frozenset([
    "3des-cbc", "arcfour", "arcfour128", "arcfour256",
    "blowfish-cbc", "cast128-cbc",
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
])
WEAK_MACS = frozenset([
    "hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
    "umac-64@openssh.com",
])
WEAK_KEX = frozenset([
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
])


def _sshd_crypto(ctx: ShellProtocol, path: str = "/etc/ssh/sshd_config") -> Dict[str, Any]:
    settings: Dict[str, str] = {}
    text = ctx.read_text(path) or ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            settings[parts[0].lower()] = parts[1]

    def split_csv(val: str) -> List[str]:
        return [v.strip() for v in val.split(",") if v.strip()]

    ciphers = split_csv(settings.get("ciphers", ""))
    macs = split_csv(settings.get("macs", ""))
    kex = split_csv(settings.get("kexalgorithms", ""))

    return {
        "ciphers": ciphers,
        "weak_ciphers_found": [c for c in ciphers if c in WEAK_CIPHERS],
        "macs": macs,
        "weak_macs_found": [m for m in macs if m in WEAK_MACS],
        "kex_algorithms": kex,
        "weak_kex_found": [k for k in kex if k in WEAK_KEX],
        "protocol": settings.get("protocol", "2"),
    }


def _tls_services(ctx: ShellProtocol) -> List[Dict[str, Any]]:
    services = []

    result = ctx.run(["nginx", "-T"], check=False)
    if result.ok():
        protocols = re.findall(r"ssl_protocols\s+([^;]+);", result.stdout)
        ciphers = re.findall(r"ssl_ciphers\s+([^;]+);", result.stdout)
        services.append({
            "service": "nginx",
            "ssl_protocols": [p.strip() for p in protocols],
            "ssl_ciphers": [c.strip() for c in ciphers],
        })

    result = ctx.run(["apachectl", "-M"], check=False)
    if result.ok() and "ssl_module" in result.stdout:
        services.append({"service": "apache", "ssl_module_loaded": True})

    return services


def collect(ctx: Optional[ShellProtocol] = None) -> Dict[str, Any]:
    """Collect network security / TLS configuration evidence."""
    ctx = ctx or Shell()
    return {
        "sshd_crypto": _sshd_crypto(ctx),
        "tls_services": _tls_services(ctx),
    }
