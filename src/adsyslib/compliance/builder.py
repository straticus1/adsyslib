"""
Orchestrates collectors → evaluates controls → builds an AuditPackage.
"""
import logging
from typing import Any, Dict, List, Optional

from .collectors import admin, auth, config_mgmt, entitlements
from .collectors import logging as logging_col
from .collectors import network, patching, storage
from .context import CollectionContext, LocalContext, RemoteContext
from .controls import control_title, get_controls_for_frameworks
from .package import AuditPackage, ControlResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-section control evaluators
# ---------------------------------------------------------------------------

def _auth_controls(data: Dict[str, Any]) -> List[ControlResult]:
    results = []
    sshd = data.get("sshd", {})
    mfa = data.get("mfa", {})
    policy = data.get("password_policy", {})

    # IA-2: MFA detected
    results.append(ControlResult(
        id="IA-2",
        title=control_title("IA-2"),
        status="pass" if mfa.get("mfa_detected") else "fail",
        evidence=f"mfa_detected={mfa.get('mfa_detected')}, modules={mfa.get('pam_modules', [])}",
        framework="nist-800-53",
    ))

    # AC-17: no direct root SSH
    root_login = sshd.get("permit_root_login", "unknown").lower()
    results.append(ControlResult(
        id="AC-17",
        title=control_title("AC-17"),
        status="pass" if root_login in ("no", "prohibit-password") else "fail",
        evidence=f"PermitRootLogin={root_login}",
        framework="nist-800-53",
    ))

    # IA-5: password max age ≤ 90 days
    max_days = policy.get("pass_max_days")
    try:
        ia5_status = "pass" if max_days and int(max_days) <= 90 else "fail"
    except (ValueError, TypeError):
        ia5_status = "not_applicable"
    results.append(ControlResult(
        id="IA-5",
        title=control_title("IA-5"),
        status=ia5_status,
        evidence=f"PASS_MAX_DAYS={max_days}",
        framework="nist-800-53",
    ))

    # IA-8: non-org users require pubkey or MFA — no password-only auth
    pwd_auth = sshd.get("password_authentication", "yes").lower()
    pubkey_auth = sshd.get("pubkey_authentication", "yes").lower()
    ia8_pass = pwd_auth == "no" or pubkey_auth == "yes" or mfa.get("mfa_detected")
    results.append(ControlResult(
        id="IA-8",
        title=control_title("IA-8"),
        status="pass" if ia8_pass else "fail",
        evidence=(
            f"PasswordAuthentication={pwd_auth}, "
            f"PubkeyAuthentication={pubkey_auth}, "
            f"mfa_detected={mfa.get('mfa_detected')}"
        ),
        framework="nist-800-53",
    ))

    return results


def _cm_controls(data: Dict[str, Any]) -> List[ControlResult]:
    detected = data.get("config_mgmt_detected", False)
    git_count = len(data.get("git_repos", []))

    return [
        ControlResult(
            id="CM-2",
            title=control_title("CM-2"),
            status="pass" if detected else "fail",
            evidence=(
                f"ansible_log={data['ansible']['log_exists']}, "
                f"terraform={bool(data.get('terraform'))}, "
                f"git_repos={git_count}"
            ),
            framework="nist-800-53",
        ),
        ControlResult(
            id="CM-3",
            title=control_title("CM-3"),
            status="pass" if git_count > 0 else "fail",
            evidence=f"Git-tracked config repos found: {git_count}",
            framework="nist-800-53",
        ),
    ]


def _admin_controls(data: Dict[str, Any]) -> List[ControlResult]:
    priv = data.get("privileged_accounts", [])
    non_root_uid0 = [a for a in priv if a["username"] != "root"]
    hardening = data.get("sshd_hardening", {})

    return [
        ControlResult(
            id="AC-6",
            title=control_title("AC-6"),
            status="pass" if not non_root_uid0 else "fail",
            evidence=f"Extra UID=0 accounts: {[a['username'] for a in non_root_uid0]}",
            framework="nist-800-53",
        ),
        ControlResult(
            id="CM-6",
            title=control_title("CM-6"),
            status="pass" if hardening.get("permitemptypasswords", "").lower() == "no" else "fail",
            evidence=f"PermitEmptyPasswords={hardening.get('permitemptypasswords')}",
            framework="nist-800-53",
        ),
        ControlResult(
            id="CM-7",
            title=control_title("CM-7"),
            status="pass" if hardening.get("x11forwarding", "").lower() == "no" else "fail",
            evidence=f"X11Forwarding={hardening.get('x11forwarding')}",
            framework="nist-800-53",
        ),
    ]


def _entitlement_controls(data: Dict[str, Any]) -> List[ControlResult]:
    local_groups = data.get("local_groups", [])
    priv_group = next(
        (g for g in local_groups if g["name"] in ("sudo", "wheel", "admin")), None
    )
    priv_members = priv_group["members"] if priv_group else []

    return [
        ControlResult(
            id="AC-2",
            title=control_title("AC-2"),
            status="pass" if len(priv_members) <= 5 else "fail",
            evidence=f"Privileged group members ({len(priv_members)}): {priv_members}",
            framework="nist-800-53",
        ),
        ControlResult(
            id="AC-3",
            title=control_title("AC-3"),
            status="not_applicable",
            evidence="Access enforcement policy requires manual review",
            framework="nist-800-53",
        ),
    ]


def _logging_controls(data: Dict[str, Any]) -> List[ControlResult]:
    auditd = data.get("auditd", {})
    syslog = data.get("syslog", {})
    forwarding = data.get("log_forwarding", {})
    perms = data.get("audit_log_permissions", {})

    # AU-2: auditd active with rules
    au2_pass = auditd.get("active", False) and auditd.get("rules_count", 0) > 0
    results = [
        ControlResult(
            id="AU-2",
            title=control_title("AU-2"),
            status="pass" if au2_pass else "fail",
            evidence=(
                f"auditd_active={auditd.get('active')}, "
                f"rules={auditd.get('rules_count', 0)}, "
                f"syslog={syslog.get('service')}"
            ),
            framework="nist-800-53",
        ),
    ]

    # AU-9: audit log directory not world-readable, owned by root
    au9_pass = (
        perms.get("exists", False)
        and perms.get("owner_uid", -1) == 0
        and perms.get("permissions", "777")[2] == "0"
    )
    results.append(ControlResult(
        id="AU-9",
        title=control_title("AU-9"),
        status="pass" if au9_pass else "fail",
        evidence=(
            f"path={perms.get('path')}, "
            f"permissions={perms.get('permissions')}, "
            f"owner_uid={perms.get('owner_uid')}, "
            f"remote_forwarding={forwarding.get('forwarding_configured')}"
        ),
        framework="nist-800-53",
    ))

    return results


def _network_controls(data: Dict[str, Any]) -> List[ControlResult]:
    crypto = data.get("sshd_crypto", {})
    weak = (
        crypto.get("weak_ciphers_found", [])
        + crypto.get("weak_macs_found", [])
        + crypto.get("weak_kex_found", [])
    )
    protocol_ok = crypto.get("protocol", "2") == "2"

    return [
        ControlResult(
            id="SC-8",
            title=control_title("SC-8"),
            status="pass" if not weak and protocol_ok else "fail",
            evidence=(
                f"weak_ciphers={crypto.get('weak_ciphers_found', [])}, "
                f"weak_macs={crypto.get('weak_macs_found', [])}, "
                f"weak_kex={crypto.get('weak_kex_found', [])}, "
                f"protocol={crypto.get('protocol')}"
            ),
            framework="nist-800-53",
        ),
    ]


def _storage_controls(data: Dict[str, Any]) -> List[ControlResult]:
    return [
        ControlResult(
            id="SC-28",
            title=control_title("SC-28"),
            status="pass" if data.get("encryption_detected") else "fail",
            evidence=(
                f"luks_volumes={len(data.get('luks_volumes', []))}, "
                f"crypttab_entries={len(data.get('crypttab', []))}"
            ),
            framework="nist-800-53",
        ),
    ]


def _patching_controls(data: Dict[str, Any]) -> List[ControlResult]:
    updates = data.get("pending_updates", {})
    malware = data.get("malware_protection", {})

    return [
        ControlResult(
            id="SI-2",
            title=control_title("SI-2"),
            status="pass" if not updates.get("available") else "fail",
            evidence=(
                f"manager={updates.get('manager')}, "
                f"pending={updates.get('pending_count', 'unknown')}, "
                f"summary={updates.get('summary', '')}"
            ),
            framework="nist-800-53",
        ),
        ControlResult(
            id="SI-3",
            title=control_title("SI-3"),
            status="pass" if malware.get("protection_active") else "fail",
            evidence=f"tools_found={malware.get('tools_found', [])}",
            framework="nist-800-53",
        ),
    ]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def build_package(
    frameworks: List[str],
    target: Any = None,
    include_aws_iam: bool = False,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
    ansible_log: str = "/var/log/ansible.log",
    terraform_state_paths: Optional[List[str]] = None,
    git_config_paths: Optional[List[str]] = None,
) -> AuditPackage:
    """
    Collect all evidence, evaluate controls, and return a populated AuditPackage.

    Args:
        frameworks: One or more of fedramp, hipaa, sox, glba.
        target: Optional RemoteShell — if provided, collection runs over SSH.
        include_aws_iam: Collect AWS IAM user/group data (always runs locally).
        aws_region: AWS region for IAM queries.
        aws_profile: AWS named profile.
        ansible_log: Path to ansible log file.
        terraform_state_paths: Paths to search for terraform state files.
        git_config_paths: Directories to check for git-managed config.
    """
    ctx: CollectionContext = RemoteContext(target) if target else LocalContext()
    label = f"{target.user}@{target.host}" if target else "localhost"
    logger.info(f"Building audit package for {label} — frameworks: {frameworks}")

    auth_data = auth.collect(ctx=ctx)
    cm_data = config_mgmt.collect(
        ctx=ctx,
        ansible_log=ansible_log,
        terraform_state_paths=terraform_state_paths,
        git_config_paths=git_config_paths,
    )
    admin_data = admin.collect(ctx=ctx)
    ent_data = entitlements.collect(
        ctx=ctx,
        include_aws=include_aws_iam,
        aws_region=aws_region,
        aws_profile=aws_profile,
    )
    log_data = logging_col.collect(ctx=ctx)
    net_data = network.collect(ctx=ctx)
    stor_data = storage.collect(ctx=ctx)
    patch_data = patching.collect(ctx=ctx)

    all_controls = (
        _auth_controls(auth_data)
        + _cm_controls(cm_data)
        + _admin_controls(admin_data)
        + _entitlement_controls(ent_data)
        + _logging_controls(log_data)
        + _network_controls(net_data)
        + _storage_controls(stor_data)
        + _patching_controls(patch_data)
    )

    relevant = set(get_controls_for_frameworks(frameworks))
    controls = [c for c in all_controls if c.id in relevant]

    return AuditPackage(
        frameworks=frameworks,
        auth=auth_data,
        config_mgmt_proof=cm_data,
        admin=admin_data,
        entitlements=ent_data,
        logging=log_data,
        network=net_data,
        storage=stor_data,
        patching=patch_data,
        controls=controls,
    )
