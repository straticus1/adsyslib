from typing import List, Optional

class DockerfileBuilder:
    """
    Builder for Dockerfiles.
    Allows programmatic generation of Dockerfiles.
    """
    def __init__(self, base_image: str):
        self.lines: List[str] = [f"FROM {base_image}"]

    def run(self, command: str) -> 'DockerfileBuilder':
        self.lines.append(f"RUN {command}")
        return self

    def copy(self, src: str, dest: str) -> 'DockerfileBuilder':
        self.lines.append(f"COPY {src} {dest}")
        return self

    def env(self, key: str, value: str) -> 'DockerfileBuilder':
        self.lines.append(f"ENV {key}={value}")
        return self

    def workdir(self, path: str) -> 'DockerfileBuilder':
        self.lines.append(f"WORKDIR {path}")
        return self

    def entrypoint(self, cmd: List[str]) -> 'DockerfileBuilder':
        import json
        self.lines.append(f"ENTRYPOINT {json.dumps(cmd)}")
        return self

    def cmd(self, cmd: List[str]) -> 'DockerfileBuilder':
        import json
        self.lines.append(f"CMD {json.dumps(cmd)}")
        return self

    def build(self) -> str:
        return "\n".join(self.lines) + "\n"

    def write(self, path: str = "Dockerfile"):
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

    def install(self, packages: List[str]) -> 'PackageAwareBuilder':
        """
        Generates a highly optimized RUN instruction to install packages.
        Handles update, install, and cleanup in a single layer.
        """
        if not packages:
            return self

        pkgs_str = " ".join(packages)
        
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
            cmd = (
                f"dnf install -y {pkgs_str} && "
                f"dnf clean all"
            )
        elif self.distro in ["alpine"]:
            cmd = (
                f"apk add --no-cache {pkgs_str}"
            )
        else:
            # Fallback or error? For now fallback to simple run
            # assuming user handles it or it's a shell command
            cmd = f"echo 'Unknown distro family {self.distro}'; exit 1"

        self.run(cmd)
        return self
