#!/usr/bin/env python3
"""
Example Layout: "Web Server Setup"
Demostrates:
1. Installing system dependencies.
2. Generating a Dockerfile.
3. Building and running a container.
"""

import sys
from adsyslib.core import run, Shell
from adsyslib.packages.apt import Apt
from adsyslib.container.builder import PackageAwareBuilder
from adsyslib.container.manager import DockerManager

def main():
    print(">>> Step 1: Preparing Host System...")
    # In a real scenario, we might detect OS, but here we assume Apt for demo
    try:
        apt = Apt()
        # check if we are root or have sudo (simplified)
        # apt.install(["git", "curl"], update=True)
        print("    (Skipping actual install to avoid permission issues in demo)")
    except Exception as e:
        print(f"    Warning: {e}")

    print("\n>>> Step 2: Generating Dockerfile...")
    builder = PackageAwareBuilder("python:3.11-slim", distro_family="debian")
    builder.install(["gcc", "libpq-dev"]) # Common python deps
    builder.workdir("/app")
    builder.run("echo 'print(\"Hello from Adsyslib Container!\")' > main.py")
    builder.cmd(["python", "main.py"])
    
    dockerfile_path = "Dockerfile.example"
    builder.write(dockerfile_path)
    print(f"    Generated {dockerfile_path}")

    print("\n>>> Step 3: Building & Running Container...")
    dm = DockerManager()
    
    # We would build here using dm.client.images.build, but for now let's just run a stock image
    # to demonstrate the manager's capabilities
    try:
        container = dm.run_container(
            "alpine:3.18",
            name="adsys-demo-runner",
            command=["echo", "Adsyslib is running!"],
            wait_for_log="Adsyslib is running!",
            auto_remove=False
        )
        print(f"    Container ran successfully: {container.short_id}")
        print("    Logs:")
        print(container.logs().decode("utf-8"))
        
        container.remove(force=True)
    except Exception as e:
        print(f"    Error: {e}")

if __name__ == "__main__":
    main()
