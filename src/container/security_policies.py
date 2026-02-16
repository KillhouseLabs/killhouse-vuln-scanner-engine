"""Security policies for container execution"""

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class SecurityPolicy:
    """Security policy for container execution"""

    # Resource limits
    cpus: float = 0.5
    memory_limit: str = "512m"
    pids_limit: int = 100

    # Filesystem
    read_only: bool = True
    tmpfs: Dict[str, str] = None

    # Capabilities
    cap_drop: List[str] = None
    cap_add: List[str] = None

    # Security options
    security_opt: List[str] = None

    # Network
    network_mode: str = "none"  # Isolated by default

    def __post_init__(self):
        """Set default values"""
        if self.tmpfs is None:
            self.tmpfs = {"/tmp": "size=100m"}

        if self.cap_drop is None:
            self.cap_drop = ["ALL"]

        if self.cap_add is None:
            self.cap_add = ["NET_BIND_SERVICE"]

        if self.security_opt is None:
            self.security_opt = ["no-new-privileges:true", "label=type:container_t"]

    def to_podman_args(self) -> Dict:
        """Convert to Podman run arguments"""
        return {
            "cpus": self.cpus,
            "mem_limit": self.memory_limit,
            "pids_limit": self.pids_limit,
            "read_only": self.read_only,
            "tmpfs": self.tmpfs,
            "cap_drop": self.cap_drop,
            "cap_add": self.cap_add,
            "security_opt": self.security_opt,
        }

    def to_docker_args(self) -> Dict:
        """Convert to Docker run arguments"""
        # Docker and Podman have similar APIs
        return self.to_podman_args()


# Predefined security policies
DEFAULT_POLICY = SecurityPolicy()

STRICT_POLICY = SecurityPolicy(
    cpus=0.25,
    memory_limit="256m",
    pids_limit=50,
    read_only=True,
    cap_drop=["ALL"],
    cap_add=[],  # No capabilities
    network_mode="none",
)

SCANNER_POLICY = SecurityPolicy(
    cpus=1.0,
    memory_limit="1g",
    pids_limit=200,
    read_only=False,  # Scanner needs write access for temp files
    cap_drop=["ALL"],
    cap_add=["NET_BIND_SERVICE"],
    network_mode="bridge",  # Scanner needs network
)
