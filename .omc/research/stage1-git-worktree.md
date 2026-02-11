# Git Worktree Isolation Patterns for Vulnerability Assessment

**Research Date:** 2026-02-11
**Objective:** Investigate git worktree-based isolation for containerized vulnerability scanning

---

## Executive Summary

Git worktrees provide an effective isolation mechanism for parallel vulnerability scanning in containerized environments. The recommended architecture is a **hub-and-spoke pattern** where the main repository acts as a hub and ephemeral worktrees serve as isolated spokes for concurrent scanning operations.

**Key Findings:**
- Hub-and-spoke architecture optimal for parallel vulnerability scanning
- Dedicated worktree directory outside main repo prevents filesystem pollution
- Semaphore-based concurrency control (limit: 5-10 concurrent) prevents resource exhaustion
- Three-layer security model: worktree isolation + read-only mounts + network isolation
- Automated cleanup required to prevent disk exhaustion from orphaned worktrees

---

## 1. Recommended Architecture

### Hub-and-Spoke Pattern

```
Main Repository (Hub)
└── .git/
    ├── objects/ (shared)
    ├── refs/ (shared)
    └── worktrees/
        ├── vuln-scan-container-nginx-20260211-085900/
        ├── vuln-scan-sast-python-20260211-090000/
        └── vuln-scan-secrets-full-20260211-090100/

Worktree Base Directory (Spokes)
/tmp/vulner-worktrees/
├── vuln-scan-container-nginx-20260211-085900-a3f8b4c1/
├── vuln-scan-sast-python-20260211-090000-d7e2a9f5/
└── vuln-scan-secrets-full-20260211-090100-c1b6e3d8/
```

**Benefits:**
- Clear separation between main repo and scanning workspaces
- Easy cleanup (delete entire worktree directory)
- No .git directory pollution in main repo
- Concurrent scans don't interfere with each other

---

## 2. Best Practices

### Practice 1: Dedicated Worktree Directory

**Rationale:** Keep worktrees separate from main repo to avoid filesystem confusion

**Implementation:**
```python
worktree_base = Path("/tmp/vulner-worktrees")  # Outside main repo
worktree_base.mkdir(parents=True, exist_ok=True)
os.chmod(worktree_base, 0o700)  # Restricted permissions
```

**Benefits:**
- Clear separation
- Easier cleanup
- No .git directory pollution
- Can set filesystem quotas on dedicated partition

---

### Practice 2: Ephemeral Branches (Detached HEAD)

**Rationale:** Worktrees for scanning should be temporary and disposable

**Implementation:**
```bash
# Recommended: Detached HEAD (no branch pollution)
git worktree add --detach /tmp/worktrees/scan-12345 HEAD

# Alternative: Temporary branch (if branch history needed)
git worktree add -b vuln-scan/container/nginx/20260211 /tmp/worktrees/scan-12345 HEAD
```

**Benefits:**
- No branch pollution in main repo
- Automatic cleanup on worktree removal
- No need to track and delete temporary branches
- Simpler git history

---

### Practice 3: Atomic Worktree Operations

**Rationale:** Creation and cleanup must be atomic to prevent orphaned worktrees

**Implementation:**
```python
import fcntl
from contextlib import contextmanager

@contextmanager
def _lock(lock_file):
    """Atomic locking mechanism for git operations"""
    with open(lock_file, 'r') as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)

# Usage
with _lock("/tmp/worktrees/.lock"):
    subprocess.run(["git", "worktree", "add", ...])
```

**Benefits:**
- Reliable cleanup
- No resource leaks
- Prevents race conditions
- Safe concurrent operations

---

### Practice 4: Concurrent Worktree Limit

**Rationale:** Prevent resource exhaustion from too many parallel scans

**Implementation:**
```python
import asyncio

class VulnerabilityScanOrchestrator:
    def __init__(self, max_concurrent: int = 5):
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def run_scan(self, ...):
        async with self.semaphore:  # Limit concurrent scans
            # Create worktree and run scan
            pass
```

**Benefits:**
- Predictable resource usage
- Better performance (avoids thrashing)
- Prevents disk I/O saturation
- Configurable based on system resources

**Recommended Limits:**
- Small VMs (2-4 CPU): 3 concurrent worktrees
- Medium servers (8-16 CPU): 5 concurrent worktrees
- Large servers (32+ CPU): 10 concurrent worktrees

---

## 3. Branch Naming Conventions

### Pattern

```
vuln-scan/{scan_type}/{target}/{timestamp}
```

### Examples

```
vuln-scan/container/nginx/20260211-085900
vuln-scan/dependency/python/20260211-090000
vuln-scan/sast/auth-module/20260211-090100
vuln-scan/dast/api-gateway/20260211-090200
vuln-scan/secrets/full/20260211-090300
```

### Components

- **Prefix:** `vuln-scan/` (identifies all vulnerability scan branches)
- **Scan Type:** `container | dependency | sast | dast | secrets`
- **Target:** Component name or `full` for complete scan
- **Timestamp:** `YYYYMMdd-HHmmss` for uniqueness and chronological ordering

### Cleanup Strategy

**Retention:** 24-48 hours for debugging and result verification

**Automation:**
```bash
# Cron job: Daily cleanup
0 2 * * * cd /path/to/repo && git worktree prune && git branch -D vuln-scan/*

# Python script: Age-based cleanup
def cleanup_old_worktrees(max_age_hours: int = 24):
    cutoff = datetime.now() - timedelta(hours=max_age_hours)
    for worktree in list_worktrees():
        if worktree.created_at < cutoff:
            remove_worktree(worktree, force=True)
```

---

## 4. Container Integration Patterns

### Pattern 1: Worktree as Build Context

**Use Case:** Container image vulnerability scanning (Trivy, Grype, Clair)

```bash
worktree_path=/tmp/worktrees/scan-12345
docker build -t vuln-scan:${SCAN_ID} $worktree_path
trivy image vuln-scan:${SCAN_ID}
```

**Advantages:**
- Isolated build context
- No interference with main repo
- Can scan different commits in parallel

---

### Pattern 2: Volume Mount Worktree

**Use Case:** SAST tools (Semgrep, CodeQL, Bandit)

```bash
docker run --rm \
  -v $worktree_path:/scan:ro \
  returntocorp/semgrep:latest \
  semgrep --config auto /scan
```

**Advantages:**
- Direct filesystem access
- Faster than image build
- Read-only mount prevents modification

---

### Pattern 3: Bind Mount with Read-Only + Network Isolation

**Use Case:** Untrusted scanner tools, third-party security services

```bash
docker run --rm \
  --read-only \
  --network none \
  --security-opt no-new-privileges \
  -v $worktree_path:/code:ro \
  untrusted-scanner:latest \
  /code
```

**Advantages:**
- Maximum isolation
- Prevents scanner from modifying source code
- Prevents data exfiltration
- Defense-in-depth security

---

## 5. Parallel Scanning Strategy

### One Worktree Per Scanner Type

```
Worktree 1 → Trivy (container vulnerabilities)
Worktree 2 → Semgrep (code patterns)
Worktree 3 → Dependency-Check (CVE database)
Worktree 4 → Gitleaks (secrets detection)
Worktree 5 → Bandit (Python security)
```

### Concurrency Control

- **Semaphore limiting:** 5-10 concurrent worktree/container pairs
- **Resource isolation:** Each worktree can reference different commits
- **Comparison scanning:** Scan current commit vs. previous commits

### Example: Parallel Scan Orchestration

```python
async def parallel_scan(scans: list[dict]) -> list[dict]:
    """
    Run multiple scans in parallel with concurrency control.

    Args:
        scans: List of scan configs, each with scan_type, target, scanner_image

    Returns:
        List of scan results
    """
    tasks = [
        run_scan(
            scan["scan_type"],
            scan["target"],
            scan["scanner_image"],
            scan.get("commit", "HEAD")
        )
        for scan in scans
    ]

    # Run all scans concurrently (semaphore enforces max concurrent)
    return await asyncio.gather(*tasks)
```

---

## 6. Security Implications

### Isolation Benefits

| Threat | Mitigation | Implementation |
|--------|------------|----------------|
| **Scanner compromise** | Worktree isolation prevents compromised scanner from affecting main repo | Read-only mounts, separate filesystem namespace |
| **Malicious code execution** | Worktree created from trusted commit before untrusted changes | `git worktree add --detach HEAD~5` |
| **Secret leakage** | Worktrees don't include .env or secrets unless explicitly copied | Never copy .env, use separate secrets management |

### Security Risks

| Risk | Description | Impact | Mitigation |
|------|-------------|--------|------------|
| **Shared .git directory** | All worktrees share .git/objects and .git/refs | Compromised worktree can affect git metadata | Use `git clone --local` for true isolation if needed, or container-level isolation |
| **Filesystem race conditions** | Multiple worktrees modifying git state concurrently | Corrupted repository, lost scan results | Lock mechanism during git operations, atomic worktree creation |
| **Orphaned worktrees** | Failed cleanup leaves worktrees on disk indefinitely | Disk space exhaustion, resource leaks | Automated cleanup cron, monitoring, max age policy |

### Security Hardening Checklist

- [ ] Use read-only filesystem mounts for scanner containers
- [ ] Implement worktree registry/tracking to detect orphans
- [ ] Set max lifetime for worktrees (auto-cleanup after 24h)
- [ ] Use dedicated filesystem or partition for worktrees (quota enforcement)
- [ ] Audit log all worktree creation/deletion events
- [ ] Implement access controls on worktree directories (`chmod 700`)
- [ ] Use AppArmor/SELinux profiles for scanner containers
- [ ] Verify git integrity after scanner runs (`git fsck`)

---

## 7. Implementation Code Patterns

### WorktreeManager Class

Complete implementation with:
- Atomic locking mechanism (`fcntl.flock`)
- Worktree registry tracking (`.worktree-registry.json`)
- Automatic cleanup based on age
- Support for detached HEAD and branch-based worktrees
- Error handling and rollback

```python
class WorktreeManager:
    def __init__(self, repo_path: str, worktree_base: str = "/tmp/vulner-worktrees"):
        self.repo_path = Path(repo_path).resolve()
        self.worktree_base = Path(worktree_base)
        self.registry_file = self.worktree_base / ".worktree-registry.json"
        self.lock_file = self.worktree_base / ".worktree.lock"

        # Create base directory with restricted permissions
        self.worktree_base.mkdir(parents=True, exist_ok=True)
        os.chmod(self.worktree_base, 0o700)
```

**Key Features:**
- Atomic operations with file locking
- Registry-based tracking for orphan detection
- Configurable worktree base directory
- Secure permissions (700)

See full implementation in research data.

---

### VulnerabilityScanOrchestrator Class

Coordinates parallel scanning with:
- Semaphore-based concurrency control
- Automatic worktree lifecycle management
- Docker container integration
- Result aggregation

```python
class VulnerabilityScanOrchestrator:
    def __init__(self, repo_path: str, max_concurrent: int = 5):
        self.worktree_mgr = WorktreeManager(repo_path)
        self.semaphore = Semaphore(max_concurrent)
```

**Key Features:**
- Concurrent scan limit enforcement
- Automatic cleanup (even on failure)
- Read-only container mounts
- Network isolation for untrusted scanners

See full implementation in research data.

---

## 8. Cleanup Automation

### Cron Job Example

```bash
#!/bin/bash
# /etc/cron.daily/vulner-worktree-cleanup

python3 << 'EOF'
from worktree_manager import WorktreeManager

manager = WorktreeManager("/Users/edith/Projects/vulner")

# Remove worktrees older than 24 hours
manager.cleanup_old_worktrees(max_age_hours=24)

# Prune stale git worktree references
import subprocess
subprocess.run(["git", "worktree", "prune"], cwd=manager.repo_path)

# Verify git integrity
subprocess.run(["git", "fsck", "--full"], cwd=manager.repo_path)
EOF
```

### Monitoring

```python
def monitor_worktree_health():
    """Check for orphaned worktrees and disk usage"""
    manager = WorktreeManager("/path/to/repo")

    # Check registry vs. actual filesystem
    registered = set(manager.list_active_worktrees().keys())
    actual = set(p.name for p in manager.worktree_base.iterdir() if p.is_dir())

    orphaned = actual - registered
    if orphaned:
        print(f"WARNING: {len(orphaned)} orphaned worktrees detected")
        for name in orphaned:
            print(f"  - {name}")

    # Check disk usage
    import shutil
    total, used, free = shutil.disk_usage(manager.worktree_base)
    usage_pct = (used / total) * 100

    if usage_pct > 80:
        print(f"WARNING: Disk usage at {usage_pct:.1f}%")
```

---

## 9. Limitations

### All Worktrees Share .git Directory
**Impact:** Compromised worktree can affect git metadata (objects, refs)
**Mitigation:** For high-security scenarios, use `git clone --local` for true isolation, or rely on container-level isolation

### Filesystem Race Conditions
**Impact:** Concurrent git operations can corrupt repository
**Mitigation:** Implement locking mechanism (`fcntl.flock`) for all git operations

### Orphaned Worktrees Risk Disk Exhaustion
**Impact:** Failed cleanup leaves worktrees consuming disk space indefinitely
**Mitigation:** Automated cleanup cron, monitoring, max age policy, filesystem quotas

### Worktree Creation Overhead
**Impact:** Creating worktree takes ~100-500ms depending on repo size
**Mitigation:** For very frequent scans, consider worktree pooling (pre-create and reuse)

---

## 10. Recommendations

1. **Use hub-and-spoke architecture** with dedicated worktree base directory outside main repo
2. **Prefer detached HEAD** for ephemeral scanning (no branch pollution)
3. **Implement atomic operations** with file locking to prevent race conditions
4. **Enforce concurrency limits** using semaphores (5-10 concurrent recommended)
5. **Use three-layer security**: worktree isolation + read-only mounts + network isolation
6. **Automate cleanup** with daily cron jobs (24-48 hour retention)
7. **Monitor worktree health** to detect orphans and disk usage issues
8. **Track worktrees in registry** for audit trail and orphan detection
9. **Set filesystem quotas** on worktree partition to prevent disk exhaustion
10. **Verify git integrity** after scans with `git fsck`

---

## Conclusion

Git worktrees provide a robust foundation for isolated vulnerability scanning in containerized environments. The recommended architecture combines worktree isolation with Docker read-only mounts and network isolation to create a defense-in-depth security model. With proper automation for cleanup and monitoring, this approach enables scalable parallel vulnerability assessment while maintaining repository integrity.

**Statistical Summary:**
- **Architecture:** Hub-and-spoke pattern (1 hub + N spokes)
- **Concurrency:** 5-10 concurrent worktree/container pairs (configurable)
- **Security Layers:** 3 (worktree + read-only mount + network isolation)
- **Retention:** 24-48 hours (configurable)
- **Hardening Measures:** 8 security controls identified
- **Code Patterns:** 4 key components (WorktreeManager, Orchestrator, Parallel Execution, Cleanup)
