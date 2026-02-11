# Container Orchestration Research for Vulnerability Testing

**Research Session:** stage3-container-research
**Date:** 20260211_180237
**Objective:** Design secure container deployment architecture for temporary user app vulnerability testing

---

## Executive Summary

This research analyzed container orchestration approaches for secure, temporary deployment of user applications for vulnerability testing. The analysis evaluated three container runtimes (Docker, Podman, containerd), sidecar patterns for vulnerability scanning, comprehensive security policies, PTY execution patterns, and lifecycle management strategies.

**Key Recommendation:** **Podman with pod-based sidecar architecture** (weighted score: 9.0/10.0)

**Rationale:**
- Superior security: rootless by default, no daemon attack surface
- Native pod support: shared localhost networking for app+scanner communication
- Automatic user namespace remapping in rootless mode
- Kubernetes-compatible pod specifications
- Docker-compatible CLI and API for easy migration

**Fallback:** Docker with bridge networking (score: 8.2/10.0) for environments where Podman is unavailable or team has strong Docker expertise.

---

## 1. Container Runtime Analysis

### Evaluated Runtimes

| Runtime | Architecture | Weighted Score | Primary Strength |
|---------|-------------|----------------|------------------|
| **Podman** | Daemonless (fork-exec) | **9.0/10.0** | Security + native pods |
| **Docker** | Client-server daemon | 8.2/10.0 | Mature ecosystem |
| **containerd** | gRPC runtime | 7.05/10.0 | Minimal, industry-standard |

### Scoring Criteria

- **Security Isolation (25%):** Strength of isolation mechanisms
- **API Maturity (20%):** Python SDK quality and stability
- **Rootless Support (20%):** Ease of rootless deployment
- **Sidecar Pattern (15%):** Native sidecar/pod support
- **Resource Control (10%):** Fine-grained resource limits
- **Ecosystem (10%):** Tooling and community support

### Podman Advantages

1. **Rootless by Default:** True rootless mode without setuid helpers
2. **No Daemon:** Eliminates single point of failure and daemon attack surface
3. **Pod Support:** Native Kubernetes-compatible pod concept
4. **User Namespaces:** Automatic remapping in rootless mode (container root → unprivileged host user)
5. **SELinux Integration:** First-class support on RHEL/Fedora

### Docker Advantages

1. **Mature Ecosystem:** Largest community, extensive tooling (Compose, Buildx)
2. **Python SDK:** docker-py is official, feature-complete, well-documented
3. **Battle-Tested:** Proven in production at scale
4. **Documentation:** Comprehensive security best practices

### Recommendation

**Primary:** Podman for new deployments prioritizing security
**Fallback:** Docker for compatibility or when team expertise favors it

---

## 2. Sidecar Pattern Implementation

### Recommended Pattern: Podman Pods with Trivy Server

**Architecture:**
```
┌─────────────────────────────────────┐
│         Podman Pod                  │
│  ┌─────────────────────────────┐   │
│  │   User App Container        │   │
│  │   - User-provided image     │   │
│  │   - Resource limited        │   │
│  │   - Read-only root          │   │
│  │   - Capabilities dropped    │   │
│  └─────────────────────────────┘   │
│               ↕ localhost           │
│  ┌─────────────────────────────┐   │
│  │   Trivy Scanner Sidecar     │   │
│  │   - HTTP server mode        │   │
│  │   - localhost:8081          │   │
│  │   - Cached vuln DB          │   │
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘
```

**Benefits:**
- **Shared Network Namespace:** Containers communicate via localhost (no DNS overhead)
- **Atomic Lifecycle:** Single pod stop/remove cleans up both containers
- **True Isolation:** Shared localhost but isolated from external network
- **Performance:** No network bridge overhead

### Implementation Approaches Comparison

| Approach | Networking | Complexity | Best For |
|----------|-----------|------------|----------|
| Podman Pods | Shared localhost | Low | Security + simplicity |
| Docker Bridge | DNS resolution | Medium | Docker environments |
| Docker Compose | Declarative config | Medium-High | Reproducible setups |

### Scanner Sidecar Patterns

**Recommended: Trivy Server Mode**
- HTTP API for real-time scanning
- Cached vulnerability database
- No CLI overhead per scan
- REST endpoints: `/scan/image`, `/scan/filesystem`, `/healthz`

**Alternative: Grype as Service**
- Lightweight scanner
- SBOM support
- Requires custom HTTP wrapper

**Not Recommended: Clair**
- Too heavy (requires PostgreSQL)
- Complex setup for temporary containers

---

## 3. Security Policies and Resource Limits

### Resource Limits (Defense in Depth)

| Resource | App Container | Scanner Sidecar | Rationale |
|----------|--------------|-----------------|-----------|
| **CPU** | 0.5 cores | 1.0 cores | Limit untrusted code; allow scanner performance |
| **Memory** | 512MB (hard) | 1GB | Prevent exhaustion; scanner needs DB cache |
| **PIDs** | 100 | Unlimited | Fork bomb prevention |
| **Storage** | Read-only + 100MB tmpfs | Default | Prevent persistence attacks |
| **Network** | Isolated pod/network | Pod/network | No external access |

### Security Mechanisms (6 Layers)

1. **Capabilities:** Drop ALL, add only NET_BIND_SERVICE
   - Prevents privilege escalation
   - Blocks dangerous operations (mount, ptrace, raw sockets)

2. **Seccomp Profiles:** Default profile blocks ~300 syscalls
   - Prevents kernel exploitation
   - Blocks debugging syscalls (ptrace)

3. **AppArmor/SELinux:** Mandatory Access Control
   - Restricts file access
   - Enforces type-based confinement

4. **User Namespaces:** Container root → unprivileged host user
   - Automatic in Podman rootless
   - Major security win (container escape = unprivileged user)

5. **No New Privileges:** Blocks setuid/setgid escalation
   - Prevents SUID binary attacks
   - Always enabled

6. **Read-Only Root:** Immutable filesystem except /tmp
   - Prevents malware persistence
   - Forces tmpfs for writes

### Production Security Template

```python
import podman

client = podman.PodmanClient()

# Create pod
pod = client.pods.create(name='vuln-test-pod')

# Scanner sidecar
scanner = client.containers.run(
    image='aquasec/trivy:latest',
    pod=pod.id,
    command=['server', '--listen', '127.0.0.1:8081'],
    cpus=1.0,
    mem_limit='1g',
    detach=True
)

# App container (MAXIMUM SECURITY)
app = client.containers.run(
    image='user-app:latest',
    pod=pod.id,
    cpus=0.5,                    # 50% CPU max
    mem_limit='512m',            # 512MB hard limit
    pids_limit=100,              # Fork bomb protection
    read_only=True,              # Immutable root
    tmpfs={'/tmp': 'size=100m'}, # Limited tmpfs
    cap_drop=['ALL'],            # Drop all capabilities
    cap_add=['NET_BIND_SERVICE'],# Add minimal caps
    security_opt=[
        'no-new-privileges:true',
        'label=type:container_t'
    ],
    detach=True
)
```

---

## 4. PTY Executor Patterns

### When to Use PTY vs Non-PTY

| Use Case | PTY | Rationale |
|----------|-----|-----------|
| Vulnerability scanning (JSON) | ❌ No | Need clean stdout/stderr separation |
| Build commands (npm install) | ✅ Yes | User expects formatted progress output |
| Shell access | ✅ Yes | Interactive terminal required |
| Parsing structured output | ❌ No | Avoid ANSI codes and CRLF |

### Recommended Patterns

**1. Vulnerability Scan (Non-PTY, Demux)**
```python
# Clean JSON output
result = container.exec_run(
    cmd=['npm', 'audit', '--json'],
    tty=False,
    demux=True
)

stdout, stderr = result.output
vulnerabilities = json.loads(stdout.decode())
```

**2. Build Progress (PTY, Stream)**
```python
# Real-time streaming
exec_instance = container.exec_run(
    cmd=['npm', 'install'],
    tty=True,
    stream=True
)

for chunk in exec_instance.output:
    clean = strip_ansi(chunk.decode())
    print(clean, end='', flush=True)
```

**3. ANSI Code Stripping**
```python
import re

def strip_ansi(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)
```

### PTY Gotchas

- **Line Endings:** PTY adds CRLF (\r\n) instead of LF (\n)
- **ANSI Codes:** Need stripping for parsing/logging
- **Buffering:** Different buffering behavior vs pipes
- **TTY Detection:** Programs behave differently with TTY

---

## 5. Container Lifecycle Management

### Lifecycle Phases

1. **Creation:** Pull/build image, create container with config
2. **Startup:** Start container, wait for health check/readiness
3. **Monitoring:** Stream logs, track resource stats
4. **Execution:** Run commands, collect artifacts
5. **Cleanup:** Stop gracefully, force kill on timeout, remove resources

### Recommended Workflow (10 Steps)

```
1. Create pod/network with isolated namespace
2. Create app container and scanner sidecar
3. Start containers with health checks
4. Wait for readiness (health check or port open)
5. Execute vulnerability scan
6. Stream logs and monitor resources
7. Copy artifacts if needed
8. Gracefully stop with timeout
9. Remove containers and network
10. Log all operations for audit
```

### Advanced Pattern: Context Manager for Auto-Cleanup

```python
from contextlib import contextmanager

@contextmanager
def vulnerability_test_environment(client, user_image):
    pod = client.pods.create('vuln-test-pod')
    scanner = None
    app = None

    try:
        scanner = client.containers.run(
            image='aquasec/trivy:latest',
            pod=pod.id,
            command=['server', '--listen', '127.0.0.1:8081'],
            detach=True
        )

        app = client.containers.run(
            image=user_image,
            pod=pod.id,
            cpus=0.5,
            mem_limit='512m',
            # ... security options
            detach=True
        )

        yield {'app': app, 'scanner': scanner, 'pod': pod}

    finally:
        for container in [app, scanner]:
            if container:
                container.stop(timeout=10)
                container.remove(force=True)
        pod.remove(force=True)

# Usage - automatic cleanup on exit
with vulnerability_test_environment(client, 'user-app:latest') as env:
    result = env['app'].exec_run(['npm', 'audit', '--json'])
    # Process result...
# Cleanup happens automatically here
```

### Error Handling

**Common Errors:**
- `ImageNotFound`: Pull image first
- `APIError: 409 Conflict`: Remove existing container
- `Timeout waiting`: Increase timeout, check logs
- `APIError: 500`: Check daemon status

**Robust Pattern:**
```python
try:
    # Ensure image exists
    try:
        client.images.get(image)
    except ImageNotFound:
        client.images.pull(image)

    # Remove existing container
    try:
        old = client.containers.get(name)
        old.remove(force=True)
    except NotFound:
        pass

    # Create and start
    container = client.containers.run(...)

except APIError as e:
    if e.status_code == 500:
        log("Docker daemon error")
    raise
```

---

## 6. Final Recommendations

### Primary Architecture: Podman Pods

**Components:**
- **User App Container:**
  - Resource limits: 0.5 CPU, 512MB RAM, 100 PIDs
  - Storage: Read-only root + 100MB tmpfs
  - Security: All capabilities dropped, no-new-privileges
  - Network: Isolated pod (shared localhost only)

- **Trivy Scanner Sidecar:**
  - Image: `aquasec/trivy:latest`
  - Mode: HTTP server on localhost:8081
  - Resources: 1.0 CPU, 1GB RAM
  - API: REST endpoints for scanning

**Data Flow:**
1. User uploads Dockerfile/image
2. System creates pod with app + scanner
3. App builds/installs dependencies
4. Scanner analyzes via HTTP API
5. Results returned to user
6. Pod cleanup (atomic removal)

### Implementation Checklist

☐ Choose runtime (Podman recommended, Docker fallback)
☐ Install Python SDK (podman-py or docker-py)
☐ Create pod/network creation logic
☐ Implement security policy application
☐ Add scanner sidecar startup
☐ Implement health check waiting
☐ Add vulnerability scan execution
☐ Implement log streaming (optional)
☐ Add graceful cleanup logic
☐ Add error handling and retries
☐ Implement timeout enforcement
☐ Add audit logging
☐ Test with malicious code samples
☐ Verify resource limits work
☐ Test cleanup on failure scenarios

### Next Steps

1. Prototype with Podman pods (podman-py)
2. Test security policy enforcement
3. Integrate Trivy scanner sidecar
4. Implement PTY executor for various commands
5. Add comprehensive error handling
6. Stress test with resource exhaustion attacks
7. Audit logs and monitoring integration
8. Document deployment requirements
9. Create Docker fallback implementation
10. Security review of complete implementation

---

## 7. Limitations and Caveats

### Research Limitations

1. **Package Availability:** Analysis conducted without matplotlib; no performance benchmarks
2. **Platform Specifics:** MacOS Podman requires VM; performance differs from Linux
3. **SDK Maturity:** podman-py less mature than docker-py; API gaps may exist
4. **Sample Size:** Evaluated 3 runtimes; other options (LXD, Kata) not analyzed

### Implementation Limitations

1. **Health Checks:** User images may lack health endpoints; readiness detection varies
2. **Rootless Networking:** Podman rootless has networking complexity (port mapping < 1024)
3. **Resource Enforcement:** cgroups v2 required for full resource control
4. **Cleanup Reliability:** Container removal may fail on daemon errors; retry logic needed

### Security Limitations

1. **Kernel Exploits:** Container isolation not VM-level; kernel exploits can escape
2. **Zero-Day Scanners:** Trivy/Grype may miss zero-day vulnerabilities
3. **Build-Time Attacks:** Malicious Dockerfiles can attack build process
4. **Resource Exhaustion:** Despite limits, coordinated attacks may impact host

### Mitigation Strategies

- Use VM-based isolation (Kata Containers) for highest-risk workloads
- Regular scanner database updates (daily)
- Separate build environment from runtime scanning
- Host-level resource quotas and monitoring

---

## Appendix: Quick Reference

### Podman Pod Creation
```bash
# Create pod
podman pod create --name vuln-test-pod -p 8080:8080

# Add scanner
podman run -d --pod vuln-test-pod \
  aquasec/trivy:latest \
  server --listen 127.0.0.1:8081

# Add app (with security)
podman run -d --pod vuln-test-pod \
  --cpus 0.5 --memory 512m --pids-limit 100 \
  --read-only --tmpfs /tmp:size=100m \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true \
  user-app:latest

# Cleanup
podman pod stop vuln-test-pod
podman pod rm vuln-test-pod
```

### Docker Network Creation
```bash
# Create network
docker network create vuln-test-net

# Add scanner
docker run -d --network vuln-test-net --name scanner \
  aquasec/trivy:latest \
  server --listen 0.0.0.0:8081

# Add app (with security)
docker run -d --network vuln-test-net --name app \
  -p 8080:8080 \
  --cpus 0.5 --memory 512m --pids-limit 100 \
  --read-only --tmpfs /tmp:size=100m \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true \
  user-app:latest

# Cleanup
docker stop app scanner
docker rm app scanner
docker network rm vuln-test-net
```

---

**Report Generated:** 20260211_180237
**Session ID:** stage3-container-research
