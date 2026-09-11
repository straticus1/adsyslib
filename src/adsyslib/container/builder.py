"""Dockerfile construction with literal data fields and explicitly executable RUN steps."""

import json
import re
import shlex


def _single_line(value: str) -> str:
    if not value or any(char in value for char in "\r\n\x00"):
        raise ValueError("Dockerfile fields must be nonempty single-line strings")
    return value


class DockerfileBuilder:
    """
    Builder for Dockerfiles.
    Allows programmatic generation of Dockerfiles.
    """

    def __init__(self, base_image: str):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]*", base_image):
            raise ValueError("Invalid base image reference")
        self.lines: list[str] = [f"FROM {base_image}"]

    def run(self, command: str) -> "DockerfileBuilder":
        self.lines.append(f"RUN {command}")
        return self

    def copy(self, src: str, dest: str) -> "DockerfileBuilder":
        self.lines.append(f"COPY {json.dumps([_single_line(src), _single_line(dest)])}")
        return self

    def env(self, key: str, value: str) -> "DockerfileBuilder":
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ValueError("Invalid environment key")
        if value:
            _single_line(value)
        self.lines.append(f"ENV {key}={json.dumps(value)}")
        return self

    def workdir(self, path: str) -> "DockerfileBuilder":
        self.lines.append(f"WORKDIR {json.dumps(_single_line(path))}")
        return self

    def entrypoint(self, cmd: list[str]) -> "DockerfileBuilder":
        self.lines.append(f"ENTRYPOINT {json.dumps(cmd)}")
        return self

    def cmd(self, cmd: list[str]) -> "DockerfileBuilder":
        self.lines.append(f"CMD {json.dumps(cmd)}")
        return self

    def build(self) -> str:
        return "\n".join(self.lines) + "\n"

    def write(self, path: str = "Dockerfile") -> None:
        with open(path, "w") as f:
            f.write(self.build())


class PackageAwareBuilder(DockerfileBuilder):
    """
    Smart Dockerfile builder that abstracts package management.
    Automatically generates correct RUN commands for apt/dnf based on distro family.
    """

    def __init__(self, base_image: str, distro_family: str = "debian"):
        super().__init__(base_image)
        self.distro = distro_family.lower()

    def install(self, packages: list[str]) -> "PackageAwareBuilder":
        """
        Generates a highly optimized RUN instruction to install packages.
        Handles update, install, and cleanup in a single layer.
        """
        if not packages:
            return self

        for package in packages:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_:~=@%/-]*", package):
                raise ValueError(f"Invalid package name: {package!r}")
        pkgs_str = shlex.join(packages)

        if self.distro in ["debian", "ubuntu"]:
            # apt-get best practices: update, install, clean, rm lists
            cmd = (
                f"apt-get update && "
                f"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {pkgs_str} && "
                f"apt-get clean && "
                f"rm -rf /var/lib/apt/lists/*"
            )
        elif self.distro in ["rhel", "centos", "fedora", "oracle", "rocky", "almalinux"]:
            # dnf best practices
            cmd = f"dnf install -y {pkgs_str} && dnf clean all"
        elif self.distro in ["alpine"]:
            cmd = f"apk add --no-cache {pkgs_str}"
        else:
            # Fallback or error? For now fallback to simple run
            # assuming user handles it or it's a shell command
            raise ValueError(f"Unknown distro family: {self.distro}")

        self.run(cmd)
        return self
