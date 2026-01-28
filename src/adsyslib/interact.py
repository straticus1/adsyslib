import logging
import pexpect
import sys
from typing import List, Tuple, Optional, Any

logger = logging.getLogger(__name__)

class InteractiveSession:
    """
    Wrapper around pexpect to automate interactive CLI tools.
    Supports "smart fill" where you define prompts and their responses.
    """
    def __init__(self, command: str, args: List[str] = None, timeout: int = 30, log_output: bool = True):
        self.command = command
        self.args = args or []
        self.timeout = timeout
        self.log_output = log_output
        self.child = None

    def start(self):
        cmd_line = f"{self.command} {' '.join(self.args)}"
        logger.info(f"Starting interactive session: {cmd_line}")
        # Spawn with encoding to handle modern CLI tools
        self.child = pexpect.spawn(self.command, self.args, encoding='utf-8', timeout=self.timeout)
        if self.log_output:
            self.child.logfile_read = sys.stdout

    def expect_and_send(self, pattern: str, response: str, exact: bool = False):
        """
        Wait for a pattern and send a response.
        
        Args:
            pattern: Regex or exact string to wait for
            response: String to send
            exact: If true, treats pattern as literal string instead of regex
        """
        if not self.child:
            raise RuntimeError("Session not started. Call start() first.")
        
        try:
            if exact:
                self.child.expect_exact(pattern)
            else:
                self.child.expect(pattern)
            
            logger.debug(f"Matched pattern '{pattern}', sending response.")
            self.child.sendline(response)
        except pexpect.TIMEOUT:
            logger.error(f"Timeout waiting for pattern '{pattern}'")
            raise TimeoutError(f"Timeout waiting for pattern '{pattern}'")
        except pexpect.EOF:
            logger.error("Process exited unexpectedly while waiting for input.")
            raise EOFError("Process exited unexpectedly")

    def wait_for_completion(self):
        if self.child:
            self.child.expect(pexpect.EOF)
            self.child.close()
            return self.child.exitstatus

    def auto_interact(self, interactions: List[Tuple[str, str]]):
        """
        Handle a sequence of interactions.
        interactions: List of (pattern, response) tuples.
        """
        if not self.child:
            self.start()

        for pattern, response in interactions:
            self.expect_and_send(pattern, response)
        
        self.wait_for_completion()
