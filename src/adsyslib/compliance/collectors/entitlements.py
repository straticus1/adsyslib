"""
Entitlements collector — access/permission evidence.
Maps to controls: AC-2, AC-3.
"""
import logging
from typing import Any, Optional

from adsyslib.core import Shell
from adsyslib.protocols import ShellProtocol

logger = logging.getLogger(__name__)


def _local_groups(ctx: ShellProtocol) -> list[dict[str, Any]]:
    text = None
    result = ctx.run("getent group", check=False)
    if result.ok() and result.stdout:
        text = result.stdout
    else:
        text = ctx.read_text("/etc/group") or ""

    groups = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) == 4:
            groups.append({
                "name": parts[0],
                "gid": parts[2],
                "members": [m for m in parts[3].split(",") if m],
            })
    return groups


def _ad_entitlements(ctx: ShellProtocol) -> dict[str, Any]:
    """
    Collect Active Directory entitlement evidence via Linux AD integration tools.

    Tries (in order): sssd/realm list → net ads → wbinfo (Samba/winbind).
    All commands run through ShellProtocol so they work over SSH.
    """
    result: dict[str, Any] = {
        "domain": None,
        "joined": False,
        "privileged_groups": [],
        "domain_users_sample": [],
        "tool_used": None,
    }

    # --- realm / sssd (modern: realmd + sssd) ---
    r = ctx.run(["realm", "list"], check=False)
    if r.ok() and r.stdout:
        domain = None
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line.startswith("realm-name") and not line.startswith("domain-name") and "." in line and not line.startswith(" "):
                domain = line.strip()
            if line.startswith("domain-name:"):
                domain = line.split(":", 1)[1].strip()
        result["domain"] = domain
        result["joined"] = domain is not None
        result["tool_used"] = "realm"

        # privileged groups via getent (sssd exposes AD groups)
        r2 = ctx.run(["getent", "group"], check=False)
        if r2.ok() and r2.stdout:
            for line in r2.stdout.splitlines():
                parts = line.split(":")
                if len(parts) == 4 and any(
                    kw in parts[0].lower()
                    for kw in ("domain admins", "admins", "administrators", "sudo", "wheel")
                ):
                    result["privileged_groups"].append({
                        "name": parts[0],
                        "gid": parts[2],
                        "members": [m for m in parts[3].split(",") if m],
                    })
        return result

    # --- net ads (Samba) ---
    r = ctx.run(["net", "ads", "info"], check=False)
    if r.ok() and r.stdout:
        domain = None
        for line in r.stdout.splitlines():
            if line.startswith("Realm:") or line.startswith("LDAP server name:"):
                domain = line.split(":", 1)[1].strip()
                break
        result["domain"] = domain
        result["joined"] = domain is not None
        result["tool_used"] = "net_ads"

        # Domain admins group
        r2 = ctx.run(["net", "ads", "group", "members", "Domain Admins"], check=False)
        if r2.ok() and r2.stdout:
            members = [m.strip() for m in r2.stdout.splitlines() if m.strip()]
            result["privileged_groups"].append({
                "name": "Domain Admins",
                "members": members,
            })

        # Sample of domain users
        r3 = ctx.run(["net", "ads", "user"], check=False)
        if r3.ok() and r3.stdout:
            result["domain_users_sample"] = [
                u.strip() for u in r3.stdout.splitlines() if u.strip()
            ][:20]
        return result

    # --- wbinfo (winbind) ---
    r = ctx.run(["wbinfo", "--own-domain"], check=False)
    if r.ok() and r.stdout.strip():
        result["domain"] = r.stdout.strip()
        result["joined"] = True
        result["tool_used"] = "wbinfo"

        r2 = ctx.run(["wbinfo", "-u"], check=False)
        if r2.ok() and r2.stdout:
            result["domain_users_sample"] = [
                u.strip() for u in r2.stdout.splitlines() if u.strip()
            ][:20]

        r3 = ctx.run(["wbinfo", "--group-info", "Domain Admins"], check=False)
        if r3.ok() and r3.stdout:
            parts = r3.stdout.strip().split(":")
            if len(parts) >= 4:
                result["privileged_groups"].append({
                    "name": "Domain Admins",
                    "gid": parts[2],
                    "members": [m for m in parts[3].split(",") if m],
                })
        return result

    # Nothing available — AD not configured or no tools installed
    result["joined"] = False
    result["tool_used"] = None
    return result


def _aws_iam(region: Optional[str], profile: Optional[str]) -> dict[str, Any]:
    try:
        import boto3
        session = boto3.Session(region_name=region, profile_name=profile)
        iam = session.client("iam")

        users = []
        for page in iam.get_paginator("list_users").paginate():
            for u in page["Users"]:
                users.append({
                    "username": u["UserName"],
                    "user_id": u["UserId"],
                    "arn": u["Arn"],
                    "created": u["CreateDate"].isoformat(),
                    "password_last_used": (
                        u["PasswordLastUsed"].isoformat()
                        if "PasswordLastUsed" in u else "never"
                    ),
                })

        groups = []
        for page in iam.get_paginator("list_groups").paginate():
            for g in page["Groups"]:
                groups.append({
                    "name": g["GroupName"],
                    "group_id": g["GroupId"],
                    "arn": g["Arn"],
                })

        return {"users": users, "groups": groups}
    except Exception as e:
        logger.warning(f"Could not collect AWS IAM data: {e}")
        return {"error": str(e)}


def collect(
    ctx: Optional[ShellProtocol] = None,
    include_aws: bool = False,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
    include_ad: bool = False,
) -> dict[str, Any]:
    """Collect entitlement evidence."""
    ctx = ctx or Shell()
    data: dict[str, Any] = {"local_groups": _local_groups(ctx)}
    if include_aws:
        data["aws_iam"] = _aws_iam(aws_region, aws_profile)
    if include_ad:
        data["active_directory"] = _ad_entitlements(ctx)
    return data
