import json
import logging
import sys
from typing import Dict, Any, Optional
from adsyslib.core import run, ShellError, CommandResult

logger = logging.getLogger(__name__)

class TerraformRunner:
    """
    Wrapper for Terraform CLI.
    Enables running plan/apply and parsing output.
    """
    def __init__(self, working_dir: str = "."):
        self.working_dir = working_dir

    def _run_tf(self, args: list, env: Dict[str, str] = None) -> CommandResult:
        cmd = ["terraform"] + args
        try:
            return run(cmd, cwd=self.working_dir, env=env, check=True)
        except ShellError as e:
            logger.error(f"Terraform command failed: {e}")
            raise

    def init(self, backend_config: Dict[str, str] = None):
        """Run terraform init."""
        args = ["init", "-input=false"]
        if backend_config:
            for k, v in backend_config.items():
                args.append(f"-backend-config={k}={v}")
        self._run_tf(args)

    def plan(self, var_file: str = None, vars: Dict[str, str] = None, out: str = None) -> str:
        """Run terraform plan. Returns stdout."""
        args = ["plan", "-input=false", "-no-color"]
        if var_file:
            args.append(f"-var-file={var_file}")
        if vars:
            for k, v in vars.items():
                args.append(f"-var={k}={v}")
        if out:
            args.append(f"-out={out}")
        
        return self._run_tf(args).stdout

    def apply(self, plan_file: str = None, auto_approve: bool = True):
        args = ["apply", "-input=false", "-no-color"]
        if auto_approve:
            args.append("-auto-approve")
        if plan_file:
            args.append(plan_file)
        
        self._run_tf(args)

    def output(self, json_format: bool = True) -> Dict[str, Any]:
        """Get terraform outputs."""
        args = ["output"]
        if json_format:
            args.append("-json")
        
        res = self._run_tf(args)
        if json_format:
            return json.loads(res.stdout)
        return {"raw": res.stdout}

def external_data_handler(handler_func):
    """
    Decorator/Helper to create a script that works as a Terraform 'external' data source.
    Reads JSON from stdin, calls handler_func(query_dict), writes JSON to stdout.
    """
    try:
        query = json.load(sys.stdin)
        result = handler_func(query)
        json.dump(result, sys.stdout)
    except Exception as e:
        # Terraform external program protocol expects error on stderr and non-zero exit
        sys.stderr.write(str(e))
        sys.exit(1)
