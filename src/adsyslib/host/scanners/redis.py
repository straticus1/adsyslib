"""
Redis scanner — service status, version, auth config, bind address, TLS.
"""
from typing import Any, Dict, List

from .base import ScanResult, ServiceScanner


class RedisScanner(ServiceScanner):
    service_name = "redis"

    def scan(self) -> ScanResult:
        active = self._is_active("redis") or self._is_active("redis-server")
        version = self._version(["redis-server", "--version"])
        ping_ok = self._ping()
        config = self._read_config()
        issues = self._check_issues(active, ping_ok, config)

        return ScanResult(
            service="redis",
            active=active,
            version=version,
            config=config,
            issues=issues,
            metrics={"ping_ok": ping_ok},
        )

    def _ping(self) -> bool:
        r = self._run(["redis-cli", "ping"])
        return r.ok() and "pong" in r.stdout.lower()

    def _read_config(self) -> Dict[str, Any]:
        for path in ("/etc/redis/redis.conf", "/etc/redis.conf"):
            r = self._run(["cat", path])
            if r.ok() and r.stdout:
                return self._parse_conf(r.stdout)
        return {}

    def _parse_conf(self, text: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                result[parts[0].lower()] = parts[1]
        bind = result.get("bind", "127.0.0.1")
        return {
            "bind": bind,
            "requirepass_set": bool(result.get("requirepass", "").strip()),
            "protected_mode": result.get("protected-mode", "yes"),
            "tls_port": result.get("tls-port", ""),
            "tls_cert_file": result.get("tls-cert-file", ""),
        }

    def _check_issues(self, active: bool, ping_ok: bool, config: Dict) -> List[str]:
        issues = []
        if not active:
            issues.append("redis is not running")
        if active and not ping_ok:
            issues.append("redis is active but not responding to PING")
        bind = config.get("bind", "")
        if "0.0.0.0" in bind or "::" in bind:
            issues.append(f"redis bound to all interfaces: bind={bind!r}")
        if not config.get("requirepass_set"):
            issues.append("redis has no requirepass set — unauthenticated access possible")
        if config.get("protected_mode", "yes").lower() == "no":
            issues.append("redis protected-mode is disabled")
        if not config.get("tls_port") and not config.get("tls_cert_file"):
            issues.append("redis TLS not configured")
        return issues
