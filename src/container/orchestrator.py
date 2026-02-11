"""Container orchestrator for vulnerability scanning"""

import subprocess
import logging
import time
from typing import Optional, Dict, List
from contextlib import contextmanager

from .security_policies import SecurityPolicy, DEFAULT_POLICY, SCANNER_POLICY

logger = logging.getLogger(__name__)


class ContainerOrchestrator:
    """Orchestrates container lifecycle for vulnerability scanning"""

    def __init__(self, runtime: str = "podman"):
        """
        Initialize orchestrator

        Args:
            runtime: Container runtime (podman or docker)
        """
        self.runtime = runtime
        self._validate_runtime()

    def _validate_runtime(self):
        """Validate that container runtime is available"""
        try:
            result = subprocess.run(
                [self.runtime, "--version"],
                capture_output=True,
                text=True,
                check=True
            )
            logger.info(f"Using {self.runtime}: {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError(f"{self.runtime} is not installed or not in PATH")

    def create_pod(self, pod_name: str, network_isolated: bool = True) -> str:
        """
        Create a pod (Podman only)

        Args:
            pod_name: Name for the pod
            network_isolated: Isolate pod network

        Returns:
            Pod ID
        """
        if self.runtime != "podman":
            raise NotImplementedError("Pods are Podman-specific")

        cmd = ["podman", "pod", "create", "--name", pod_name]

        if network_isolated:
            cmd.extend(["--network", "none"])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            pod_id = result.stdout.strip()
            logger.info(f"Created pod: {pod_name} ({pod_id})")
            return pod_id
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create pod: {e.stderr}")
            raise

    def run_container(
        self,
        image: str,
        name: Optional[str] = None,
        command: Optional[List[str]] = None,
        pod: Optional[str] = None,
        security_policy: SecurityPolicy = None,
        detach: bool = True,
        env: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Run a container

        Args:
            image: Container image
            name: Container name
            command: Command to run
            pod: Pod ID (Podman only)
            security_policy: Security policy to apply
            detach: Run in detached mode
            env: Environment variables

        Returns:
            Container ID
        """
        if security_policy is None:
            security_policy = DEFAULT_POLICY

        cmd = [self.runtime, "run"]

        if detach:
            cmd.append("-d")

        if name:
            cmd.extend(["--name", name])

        if pod and self.runtime == "podman":
            cmd.extend(["--pod", pod])

        # Apply security policy
        policy_args = (
            security_policy.to_podman_args()
            if self.runtime == "podman"
            else security_policy.to_docker_args()
        )

        # Add resource limits
        cmd.extend(["--cpus", str(policy_args["cpus"])])
        cmd.extend(["--memory", policy_args["memory_limit"]])
        cmd.extend(["--pids-limit", str(policy_args["pids_limit"])])

        # Filesystem
        if policy_args["read_only"]:
            cmd.append("--read-only")

        for path, opts in policy_args["tmpfs"].items():
            cmd.extend(["--tmpfs", f"{path}:{opts}"])

        # Capabilities
        for cap in policy_args["cap_drop"]:
            cmd.extend(["--cap-drop", cap])

        for cap in policy_args["cap_add"]:
            cmd.extend(["--cap-add", cap])

        # Security options
        for opt in policy_args["security_opt"]:
            cmd.extend(["--security-opt", opt])

        # Environment variables
        if env:
            for key, value in env.items():
                cmd.extend(["-e", f"{key}={value}"])

        # Image
        cmd.append(image)

        # Command
        if command:
            cmd.extend(command)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            container_id = result.stdout.strip()
            logger.info(f"Started container: {name or container_id[:12]}")
            return container_id
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to run container: {e.stderr}")
            raise

    def run_app_container(
        self,
        image: str,
        pod: Optional[str] = None,
        security_policy: SecurityPolicy = None
    ) -> str:
        """Run user application container with strict security"""
        if security_policy is None:
            security_policy = DEFAULT_POLICY

        return self.run_container(
            image=image,
            name=f"app-{pod}" if pod else None,
            pod=pod,
            security_policy=security_policy,
            detach=True
        )

    def run_scanner_sidecar(
        self,
        pod: Optional[str] = None,
        scanner: str = "trivy"
    ) -> str:
        """Run vulnerability scanner as sidecar"""
        scanner_images = {
            "trivy": "aquasec/trivy:latest",
            "grype": "anchore/grype:latest"
        }

        image = scanner_images.get(scanner, "aquasec/trivy:latest")
        command = ["server", "--listen", "127.0.0.1:8081"] if scanner == "trivy" else None

        return self.run_container(
            image=image,
            name=f"scanner-{pod}" if pod else None,
            command=command,
            pod=pod,
            security_policy=SCANNER_POLICY,
            detach=True
        )

    def execute_command(
        self,
        container_id: str,
        cmd: List[str],
        tty: bool = False,
        demux: bool = True
    ) -> Dict:
        """
        Execute command in container

        Args:
            container_id: Container ID
            cmd: Command to execute
            tty: Allocate pseudo-TTY
            demux: Separate stdout/stderr

        Returns:
            Dict with exit_code, stdout, stderr
        """
        exec_cmd = [self.runtime, "exec"]

        if tty:
            exec_cmd.append("-t")

        exec_cmd.append(container_id)
        exec_cmd.extend(cmd)

        try:
            result = subprocess.run(
                exec_cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            return {
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out in container {container_id}")
            raise
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e.stderr}")
            raise

    def stop_container(self, container_id: str, timeout: int = 10):
        """Stop a container gracefully"""
        try:
            subprocess.run(
                [self.runtime, "stop", "-t", str(timeout), container_id],
                capture_output=True,
                text=True,
                check=True
            )
            logger.info(f"Stopped container: {container_id[:12]}")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to stop container: {e.stderr}")

    def remove_container(self, container_id: str, force: bool = True):
        """Remove a container"""
        cmd = [self.runtime, "rm"]
        if force:
            cmd.append("-f")
        cmd.append(container_id)

        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"Removed container: {container_id[:12]}")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to remove container: {e.stderr}")

    def cleanup_pod(self, pod_id: str, timeout: int = 10):
        """Stop and remove a pod with all containers"""
        if self.runtime != "podman":
            raise NotImplementedError("Pods are Podman-specific")

        try:
            # Stop pod
            subprocess.run(
                ["podman", "pod", "stop", "-t", str(timeout), pod_id],
                capture_output=True,
                text=True,
                check=True
            )

            # Remove pod (removes all containers in pod)
            subprocess.run(
                ["podman", "pod", "rm", "-f", pod_id],
                capture_output=True,
                text=True,
                check=True
            )

            logger.info(f"Cleaned up pod: {pod_id[:12]}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to cleanup pod: {e.stderr}")


@contextmanager
def container_environment(
    orchestrator: ContainerOrchestrator,
    user_image: str,
    use_pod: bool = True
):
    """Context manager for automatic container cleanup"""
    pod_id = None
    app_container = None
    scanner_container = None

    try:
        if use_pod and orchestrator.runtime == "podman":
            pod_id = orchestrator.create_pod("vuln-scan-pod")
            app_container = orchestrator.run_app_container(user_image, pod=pod_id)
            scanner_container = orchestrator.run_scanner_sidecar(pod=pod_id)
        else:
            app_container = orchestrator.run_app_container(user_image)
            scanner_container = orchestrator.run_scanner_sidecar()

        # Wait for containers to be ready
        time.sleep(2)

        yield {
            "pod_id": pod_id,
            "app_container": app_container,
            "scanner_container": scanner_container
        }

    finally:
        # Cleanup
        if pod_id:
            orchestrator.cleanup_pod(pod_id)
        else:
            if scanner_container:
                orchestrator.stop_container(scanner_container)
                orchestrator.remove_container(scanner_container)
            if app_container:
                orchestrator.stop_container(app_container)
                orchestrator.remove_container(app_container)
