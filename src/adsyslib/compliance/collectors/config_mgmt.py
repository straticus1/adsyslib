"""
Config management proof collector.
Maps to controls: CM-2, CM-3.
"""
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from adsyslib.compliance.context import CollectionContext, LocalContext

logger = logging.getLogger(__name__)


def _ansible_evidence(log_path: str, ctx: CollectionContext) -> Dict[str, Any]:
    log_exists = ctx.path_exists(log_path)
    last_run: Optional[str] = None
    if log_exists:
        result = ctx.run(["tail", "-20", log_path], check=False)
        if result.ok() and result.stdout:
            for line in reversed(result.stdout.splitlines()):
                if line.strip():
                    last_run = line[:19]
                    break
    return {"log_path": log_path, "log_exists": log_exists, "last_run": last_run}


def _terraform_evidence(state_paths: List[str], ctx: CollectionContext) -> Dict[str, Any]:
    for path in state_paths:
        if not ctx.path_exists(path):
            continue
        text = ctx.read_text(path)
        if not text:
            continue
        try:
            state = json.loads(text)
            stat_info = ctx.path_stat(path)
            mtime = stat_info.get("mtime") if stat_info else None
            ts = datetime.fromtimestamp(mtime).isoformat() if mtime else "unknown"
            return {
                "state_file": path,
                "last_modified": ts,
                "serial": state.get("serial"),
                "terraform_version": state.get("terraform_version"),
                "lineage": state.get("lineage"),
            }
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Could not parse terraform state {path}: {e}")
    return {}


def _git_evidence(search_paths: List[str], ctx: CollectionContext) -> List[Dict[str, Any]]:
    repos = []
    for path in search_paths:
        if not ctx.is_dir(path):
            continue
        result = ctx.run(
            ["git", "-C", path, "log", "-1", "--format=%H|%ae|%ai|%s"],
            check=False,
        )
        if result.ok() and result.stdout:
            parts = result.stdout.strip().split("|", 3)
            if len(parts) == 4:
                repos.append({
                    "path": path,
                    "last_commit_sha": parts[0],
                    "author_email": parts[1],
                    "committed_at": parts[2],
                    "message": parts[3],
                })
    return repos


def collect(
    ctx: Optional[CollectionContext] = None,
    ansible_log: str = "/var/log/ansible.log",
    terraform_state_paths: Optional[List[str]] = None,
    git_config_paths: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Collect config management proof artifacts."""
    ctx = ctx or LocalContext()

    if terraform_state_paths is None:
        terraform_state_paths = ["terraform.tfstate", ".terraform/terraform.tfstate"]
    if git_config_paths is None:
        git_config_paths = ["/etc/ansible", "/opt/config", os.getcwd()]

    ansible = _ansible_evidence(ansible_log, ctx)
    terraform = _terraform_evidence(terraform_state_paths, ctx)
    git_repos = _git_evidence(git_config_paths, ctx)

    return {
        "ansible": ansible,
        "terraform": terraform,
        "git_repos": git_repos,
        "config_mgmt_detected": ansible["log_exists"] or bool(terraform) or bool(git_repos),
    }
