"""Test container orchestrator"""

import subprocess

import pytest

from src.container.orchestrator import ContainerOrchestrator
from src.container.security_policies import DEFAULT_POLICY, STRICT_POLICY


def is_podman_available():
    """Check if podman is available"""
    try:
        subprocess.run(["podman", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def is_docker_available():
    """Check if docker is available"""
    try:
        subprocess.run(["docker", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


@pytest.fixture
def runtime():
    """Get available container runtime"""
    if is_podman_available():
        return "podman"
    elif is_docker_available():
        return "docker"
    else:
        pytest.skip("No container runtime available (podman or docker)")


@pytest.mark.integration
def test_orchestrator_init(runtime):
    """Test orchestrator initialization"""
    orch = ContainerOrchestrator(runtime=runtime)
    assert orch.runtime == runtime


@pytest.mark.integration
@pytest.mark.skipif(not is_podman_available(), reason="Podman not available")
def test_create_pod():
    """Test pod creation (Podman only)"""
    orch = ContainerOrchestrator(runtime="podman")

    pod_id = orch.create_pod("test-pod", network_isolated=True)
    assert pod_id

    # Cleanup
    orch.cleanup_pod(pod_id)


@pytest.mark.integration
def test_run_container(runtime):
    """Test running a container"""
    orch = ContainerOrchestrator(runtime=runtime)

    container_id = orch.run_container(
        image="alpine:latest",
        name="test-container",
        command=["sleep", "10"],
        security_policy=STRICT_POLICY,
        detach=True,
    )

    assert container_id

    # Cleanup
    orch.stop_container(container_id)
    orch.remove_container(container_id)


@pytest.mark.integration
def test_execute_command(runtime):
    """Test executing command in container"""
    orch = ContainerOrchestrator(runtime=runtime)

    # Start container
    container_id = orch.run_container(image="alpine:latest", command=["sleep", "30"], detach=True)

    # Wait a bit for container to start
    import time

    time.sleep(2)

    # Execute command
    result = orch.execute_command(container_id, ["echo", "hello"], tty=False)

    assert result["exit_code"] == 0
    assert "hello" in result["stdout"]

    # Cleanup
    orch.stop_container(container_id)
    orch.remove_container(container_id)


@pytest.mark.integration
def test_security_policy():
    """Test security policy conversion"""
    policy = DEFAULT_POLICY

    podman_args = policy.to_podman_args()
    assert podman_args["cpus"] == 0.5
    assert podman_args["mem_limit"] == "512m"
    assert "ALL" in podman_args["cap_drop"]

    docker_args = policy.to_docker_args()
    assert docker_args["cpus"] == 0.5


@pytest.mark.integration
@pytest.mark.skipif(not is_podman_available(), reason="Podman not available")
def test_container_environment_context():
    """Test container environment context manager"""
    from src.container.orchestrator import container_environment

    orch = ContainerOrchestrator(runtime="podman")

    with container_environment(orch, "alpine:latest", use_pod=True) as env:
        assert env["pod_id"]
        assert env["app_container"]
        assert env["scanner_container"]

    # Verify cleanup happened (containers should be gone)
    # This is implicit - if cleanup failed, we'd see errors


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
