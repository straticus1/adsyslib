"""
Auth collector — authentication configuration evidence.
Maps to controls: IA-2, IA-5, AC-17.
"""
import logging
from typing import Any, Dict, List, Optional

from adsyslib.core import Shell
from adsyslib.protocols import ShellProtocol

logger = logging.getLogger(__name__)


def _parse_kv_text(text: str, comment_char: str = "#") -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(comment_char):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            result[parts[0].lower()] = parts[1]
    return result


def _detect_mfa(sshd: Dict[str, str], ctx: ShellProtocol) -> Dict[str, Any]:
    mfa_modules: List[str] = []
    for pam_path in ("/etc/pam.d/sshd", "/etc/pam.d/common-auth", "/etc/pam.d/system-auth"):
        content = ctx.read_text(pam_path)
        if content:
            for module in ("pam_google_authenticator", "pam_duo", "pam_radius", "pam_oath"):
                if module in content and module not in mfa_modules:
                    mfa_modules.append(module)

    auth_methods = sshd.get("authmethods")
    return {
        "mfa_detected": bool(mfa_modules) or (auth_methods is not None and "," in auth_methods),
        "pam_modules": mfa_modules,
        "auth_methods": auth_methods,
        "challenge_response": sshd.get("challengeresponseauthentication", "no").lower() == "yes",
        "keyboard_interactive": sshd.get("kbdinteractiveauthentication", "no").lower() == "yes",
        "use_pam": sshd.get("usepam", "no").lower() == "yes",
    }


def collect(
    ctx: Optional[ShellProtocol] = None,
    sshd_config_path: str = "/etc/ssh/sshd_config",
    login_defs_path: str = "/etc/login.defs",
) -> Dict[str, Any]:
    """Collect authentication configuration evidence."""
    ctx = ctx or Shell()

    sshd = _parse_kv_text(ctx.read_text(sshd_config_path) or "")
    login_defs = _parse_kv_text(ctx.read_text(login_defs_path) or "")

    return {
        "sshd": {
            "permit_root_login": sshd.get("permitrootlogin", "unknown"),
            "password_authentication": sshd.get("passwordauthentication", "unknown"),
            "pubkey_authentication": sshd.get("pubkeyauthentication", "unknown"),
            "use_pam": sshd.get("usepam", "unknown"),
            "protocol": sshd.get("protocol", "2"),
            "allowed_users": sshd.get("allowusers"),
            "allowed_groups": sshd.get("allowgroups"),
        },
        "password_policy": {
            "pass_max_days": login_defs.get("pass_max_days"),
            "pass_min_days": login_defs.get("pass_min_days"),
            "pass_min_len": login_defs.get("pass_min_len"),
            "pass_warn_age": login_defs.get("pass_warn_age"),
        },
        "mfa": _detect_mfa(sshd, ctx),
    }
