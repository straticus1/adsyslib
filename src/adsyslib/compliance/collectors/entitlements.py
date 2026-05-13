"""
Entitlements collector — access/permission evidence.
Maps to controls: AC-2, AC-3.
"""
import logging
from typing import Any, Dict, List, Optional

from adsyslib.compliance.context import CollectionContext, LocalContext

logger = logging.getLogger(__name__)


def _local_groups(ctx: CollectionContext) -> List[Dict[str, Any]]:
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


def _aws_iam(region: Optional[str], profile: Optional[str]) -> Dict[str, Any]:
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
    ctx: Optional[CollectionContext] = None,
    include_aws: bool = False,
    aws_region: Optional[str] = None,
    aws_profile: Optional[str] = None,
) -> Dict[str, Any]:
    """Collect entitlement evidence."""
    ctx = ctx or LocalContext()
    data: Dict[str, Any] = {"local_groups": _local_groups(ctx)}
    if include_aws:
        data["aws_iam"] = _aws_iam(aws_region, aws_profile)
    return data
