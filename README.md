# adsyslib

A "10x better" systems library for Python, designed for robust system administration, cloud management, and automation.

## Features

- **Core Shell**: Robust command execution with output capturing and audit logging.
- **Package Management**: Unified interface for `apt` and `dnf` with idempotency.
- **Container Management**: High-level Docker wrapper.
- **Interactive Automation**: Smart wrappers around `pexpect`.
- **Cloud Integration**: Unified basic operations for AWS and Oracle Cloud.

## Installation

```bash
pip install .
```

## Basic Usage

```python
from adsyslib.core import run

# Run a command safely
result = run("ls -la", check=True)
print(result.stdout)
```
