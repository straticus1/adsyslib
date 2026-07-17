import json
import logging
from typing import Any, Optional

from adsyslib.core import ShellError, run

logger = logging.getLogger(__name__)

class AnsibleRunner:
    """
    Wrapper for ansible-playbook execution.
    """
    def __init__(self, inventory: Optional[str] = None):
        self.inventory = inventory

    def run_playbook(
        self, 
        playbook_path: str, 
        extra_vars: Optional[dict[str, Any]] = None, 
        tags: Optional[list[str]] = None,
        check: bool = False
    ):
        """
        Run an Ansible playbook.
        """
        cmd = ["ansible-playbook", playbook_path]
        
        if self.inventory:
            cmd.extend(["-i", self.inventory])
            
        if extra_vars:
            # Pass as JSON string to handle complex types safely
            cmd.extend(["--extra-vars", json.dumps(extra_vars)])
            
        if tags:
            cmd.extend(["--tags", ",".join(tags)])
            
        if check:
            cmd.append("--check")

        # Force unbuffered output if possible, but standard run captures output anyway
        # ANSIBLE_STDOUT_CALLBACK=json could be useful if we wanted to parse it
        env = {"ANSIBLE_FORCE_COLOR": "1"}
        
        logger.info(f"Running playbook: {playbook_path}")
        try:
            run(cmd, env=env, check=True)
            logger.info("Playbook finished successfully.")
        except ShellError as e:
            logger.error(f"Ansible playbook failed: {e}")
            raise
