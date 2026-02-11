# Vulner Platform 테스트 가이드

이 문서는 Vulner 플랫폼을 테스트하는 방법을 설명합니다.

---

## 사전 요구사항

### 1. Python 환경 설정

```bash
# Python 3.10 이상 필요
python --version

# 의존성 설치
pip install -r requirements.txt
```

### 2. 컨테이너 런타임 설치

**Podman 설치 (권장):**
```bash
# macOS
brew install podman
podman machine init
podman machine start

# Linux (Fedora/RHEL)
sudo dnf install podman

# Linux (Ubuntu/Debian)
sudo apt install podman
```

**또는 Docker 설치:**
```bash
# macOS
brew install --cask docker

# Linux
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

### 3. Git 저장소 확인

```bash
# 현재 디렉토리가 git 저장소여야 함
git status

# git 저장소가 아니면 초기화
git init
git config user.email "test@example.com"
git config user.name "Test User"
echo "test" > test.txt
git add .
git commit -m "Initial commit"
```

---

## 테스트 방법

### 방법 1: 빠른 데모 테스트 (권장)

```bash
# 실행 권한 부여
chmod +x scripts/test_demo.py

# 데모 실행
python scripts/test_demo.py
```

**출력 예시:**
```
🚀 Vulner Platform Demo Tests

============================================================
Testing Git Worktree Manager
============================================================
Creating worktree...
✅ Created worktree: vuln-scan-demo-test-20260211-123456
   Path: /tmp/vulner-test-worktrees/vuln-scan-demo-test-20260211-123456
Listing active worktrees...
✅ Active worktrees: 1
Removing worktree...
✅ Worktree removed

============================================================
Testing Container Orchestrator
============================================================
✅ Using runtime: podman
Running test container...
✅ Container executed: abc123def456
Cleaning up...
✅ Cleanup complete

============================================================
Testing Main Platform Orchestration
============================================================
Initializing Vulner platform...
✅ Platform initialized
Running test scan...
✅ Scan completed: a1b2c3d4
   Status: completed
   URL: https://example.com
Running cleanup...
✅ Cleanup complete

============================================================
Test Summary
============================================================
✅ PASSED: Worktree Manager
✅ PASSED: Container Orchestrator
✅ PASSED: Main Platform

🎉 All tests passed!
```

### 방법 2: pytest로 단위 테스트

```bash
# 전체 테스트 실행
pytest tests/ -v

# 특정 테스트만 실행
pytest tests/test_worktree.py -v
pytest tests/test_container.py -v

# 커버리지 포함
pytest --cov=src tests/
```

### 방법 3: 개별 컴포넌트 테스트

#### Git Worktree Manager 테스트

```python
from src.worktree.manager import WorktreeManager

# 초기화
manager = WorktreeManager(
    repo_path=".",
    worktree_base="/tmp/vulner-worktrees"
)

# Worktree 생성
wt = manager.create_worktree(scan_id="test123")
print(f"Created: {wt['path']}")

# 목록 확인
worktrees = manager.list_active_worktrees()
print(f"Active: {len(worktrees)}")

# 삭제
manager.remove_worktree(wt['worktree_id'], force=True)
print("Cleaned up")
```

#### Container Orchestrator 테스트

```python
from src.container.orchestrator import ContainerOrchestrator

# 초기화 (podman 또는 docker)
orch = ContainerOrchestrator(runtime="podman")

# 컨테이너 실행
container_id = orch.run_container(
    image="alpine:latest",
    command=["echo", "hello"],
    detach=False
)

# 정리
orch.remove_container(container_id, force=True)
```

#### 전체 플랫폼 테스트

```python
import asyncio
from src.main import VulnerPlatform

async def test():
    platform = VulnerPlatform(
        repo_path=".",
        container_runtime="podman"
    )

    result = await platform.scan_target("https://example.com")

    print(f"Scan ID: {result.scan_id}")
    print(f"Status: {result.status}")

    platform.cleanup_old_worktrees()

asyncio.run(test())
```

---

## 문제 해결

### 1. Podman/Docker가 없는 경우

**오류:**
```
RuntimeError: podman is not installed or not in PATH
```

**해결:**
- Podman 또는 Docker를 설치하세요
- PATH에 추가되어 있는지 확인: `which podman` 또는 `which docker`

### 2. Git 저장소가 아닌 경우

**오류:**
```
fatal: not a git repository
```

**해결:**
```bash
git init
git config user.email "test@example.com"
git config user.name "Test User"
echo "test" > test.txt
git add .
git commit -m "Initial commit"
```

### 3. 권한 오류

**오류:**
```
PermissionError: [Errno 13] Permission denied
```

**해결:**
```bash
# Worktree 디렉토리 권한 확인
ls -la /tmp/vulner-worktrees

# 필요시 소유권 변경
sudo chown -R $USER /tmp/vulner-worktrees

# 또는 다른 디렉토리 사용
export WORKTREE_BASE_DIR=$HOME/vulner-worktrees
```

### 4. 컨테이너 이미지 풀 실패

**오류:**
```
Error: unable to pull image
```

**해결:**
```bash
# 이미지 미리 다운로드
podman pull alpine:latest
# 또는
docker pull alpine:latest

# 네트워크 확인
ping registry-1.docker.io
```

---

## 실제 사용 예시

### 기본 스캔

```python
from src.main import VulnerPlatform
import asyncio

async def scan():
    platform = VulnerPlatform(
        repo_path=".",
        container_runtime="podman"
    )

    # 스캔 실행
    result = await platform.scan_target(
        url="https://example.com",
        user_image="alpine:latest"
    )

    print(f"✅ Scan {result.scan_id} completed")
    print(f"   Status: {result.status}")
    print(f"   Tech Stack: {result.tech_stack}")
    print(f"   Vulnerabilities: {len(result.vulnerabilities)}")

    # 정리
    platform.cleanup_old_worktrees(max_age_hours=24)

asyncio.run(scan())
```

### Context Manager 사용

```python
from src.worktree.manager import WorktreeManager, worktree_context
from src.container.orchestrator import ContainerOrchestrator, container_environment

manager = WorktreeManager(".")
orch = ContainerOrchestrator("podman")

# 자동 정리되는 환경
with worktree_context(manager, "HEAD") as wt:
    print(f"Worktree created: {wt['path']}")

    with container_environment(orch, "alpine:latest") as env:
        print(f"Pod created: {env['pod_id']}")
        print(f"App container: {env['app_container']}")
        print(f"Scanner: {env['scanner_container']}")

        # 작업 수행
        result = orch.execute_command(
            env['app_container'],
            ["ls", "-la"]
        )
        print(result['stdout'])

# 자동으로 정리됨
print("All cleaned up!")
```

---

## 성능 테스트

### 병렬 스캔 테스트

```python
import asyncio
from src.main import VulnerPlatform

async def parallel_scans():
    platform = VulnerPlatform(".")

    urls = [
        "https://example1.com",
        "https://example2.com",
        "https://example3.com",
    ]

    # 병렬 실행
    tasks = [platform.scan_target(url) for url in urls]
    results = await asyncio.gather(*tasks)

    for result in results:
        print(f"Scan {result.scan_id}: {result.status}")

asyncio.run(parallel_scans())
```

### 메모리 사용량 확인

```bash
# 실행 중 메모리 모니터링
watch -n 1 'ps aux | grep -E "(python|podman|docker)" | grep -v grep'
```

---

## 다음 단계

현재 구현된 것은 **Phase 1 (Core Components)**입니다.

**테스트 가능:**
- ✅ Git Worktree 관리
- ✅ Container 오케스트레이션
- ✅ 기본 스캔 워크플로우

**아직 구현 안 됨 (Placeholder):**
- 📋 실제 기술 스택 탐지
- 📋 취약점 데이터베이스 쿼리
- 📋 LLM 기반 분석
- 📋 Exploit 검증

**전체 기능을 테스트하려면:**
1. `.env` 파일 설정 (OpenAI API 키, Supabase 등)
2. Phase 2-6 구현 완료 대기
3. 또는 직접 추가 컴포넌트 구현

---

**테스트 준비 완료!** 🚀

`python scripts/test_demo.py`를 실행하여 현재 구현된 기능을 테스트하세요.
