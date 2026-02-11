# Vulner: Automated Vulnerability Assessment Platform

A comprehensive, LLM-powered vulnerability assessment platform that combines git worktree isolation, containerized scanning, technology stack detection, and ethical exploit verification.

## Features

- **Git Worktree Isolation**: Hub-and-spoke architecture for parallel, isolated vulnerability scans
- **Container Orchestration**: Podman pod-based sidecar pattern with strict security policies
- **Tech Stack Detection**: Multi-method detection using Wappalyzer, HTTP headers, and HTML analysis
- **Vector Database**: Supabase pgvector for semantic vulnerability search with OpenAI embeddings
- **LLM-Driven Analysis**: GPT-4o powered vulnerability classification and attack planning
- **Feedback Loop**: OODA + Hypothesis-Driven 8-state machine for continuous improvement
- **SafeExploit Framework**: Authorized, ethical exploit verification with comprehensive safety controls

## Architecture

```
Git Worktree → Container Orchestrator → Tech Stack Detector → Vector DB (pgvector)
     ↓              ↓                                              ↓
  Podman Pods   Trivy Scanner                          OpenAI Embeddings
                                                              ↓
                                Policy Engine & Feedback Loop
                                              ↓
                                  SafeExploit Framework
```

## Installation

### Prerequisites

- Python 3.10+
- Podman or Docker
- Git
- OpenAI API key
- Supabase account

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd vulner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment:
```bash
cp .env.example .env
# Edit .env with your credentials
```

4. Initialize the database:
```bash
python scripts/init_db.py
```

## Usage

### Basic Scan

```python
from src.main import VulnerPlatform
from src.config import settings

platform = VulnerPlatform(
    repo_path=".",
    worktree_base=settings.worktree_base_dir
)

# Scan a target URL
result = await platform.scan_target("https://example.com")

print(f"Tech Stack: {result.tech_stack}")
print(f"Vulnerabilities: {len(result.vulnerabilities)}")
```

### With Authorization (Exploit Verification)

```python
# Requires written authorization
result = await platform.scan_target(
    "https://example.com",
    authorization_token="your-jwt-token"
)
```

## Components

### Git Worktree Manager
- Atomic worktree operations with file locking
- Registry-based tracking for orphan detection
- Automatic cleanup of old worktrees
- Detached HEAD for no branch pollution

### Container Orchestrator
- Podman pod-based architecture (Docker fallback)
- 6-layer security policy (capabilities, seccomp, AppArmor, user namespaces, read-only root)
- Resource limits: 0.5 CPU, 512MB RAM, 100 PIDs
- Context manager pattern for auto-cleanup

### Tech Stack Detector
- python-Wappalyzer (70K+ patterns)
- httpx (async HTTP/2)
- BeautifulSoup4 (HTML parsing)
- Confidence scoring by detection method

### Vector Database
- Supabase pgvector with HNSW indexing
- Hybrid search (vector + metadata filtering)
- Embedding cache (90% cost reduction)
- MITRE ATT&CK integration

### Policy Engine
- Python-based custom engine
- OODA + Hypothesis-Driven feedback loop
- 8-state machine (IDLE → OBSERVING → ORIENTING → HYPOTHESIZING → DECIDING → ACTING → VALIDATING → REPORTING)
- SQLite state persistence

### SafeExploit Framework
- JWT-based authorization verification
- LLM-driven exploit generation (GPT-4o)
- Safe execution runtime (sandboxed)
- Multi-method validation (differential testing, sandbox execution, OOB validation)

## Security

### Authorization Required
All exploit execution requires:
- Written authorization from system owner
- JWT token with scope validation
- Real-time revocation support
- Comprehensive audit logging

### Safety Controls
- Sandbox isolation (Docker/Podman)
- Resource limits enforced
- Rate limiting (10 requests/min default)
- Circuit breaker (anomaly detection)
- Automatic rollback on failure

### Compliance
- CFAA, GDPR, CCPA compliant
- PCI DSS, HIPAA, FISMA support
- Comprehensive audit trails
- Data retention policies

## Cost Analysis

### Infrastructure
- Supabase: $0 (free tier) → $25/mo (paid tier)
- Hosting: $5-10/mo
- **Total: $0-35/mo**

### API Costs
- **Baseline:** $1.54/1000 scans
- **Optimized:** $0.10-0.20/1000 scans (87-93% savings)

Optimizations:
- Embedding cache (90% hit rate)
- Batch API (50% discount)
- Prompt caching (50% discount)
- gpt-4o-mini for classification

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src tests/

# Run specific test module
pytest tests/test_worktree.py
```

## Development

### Project Structure

```
vulner/
├── src/
│   ├── worktree/          # Git worktree isolation
│   ├── container/         # Container orchestration
│   ├── detection/         # Tech stack detection
│   ├── database/          # Supabase integration
│   ├── policy/            # Policy engine & feedback loop
│   ├── exploit/           # SafeExploit framework
│   └── reporting/         # Report generation
├── tests/                 # Unit and integration tests
├── scripts/               # Utility scripts
├── .omc/research/         # Research documentation
└── requirements.txt
```

### Research Documentation

Comprehensive research findings available in `.omc/research/`:
- `stage1-git-worktree.md` - Git worktree isolation patterns
- `stage2-python-arch.md` - Python architecture and vector DB
- `stage3-container-orch.md` - Container orchestration patterns
- `stage4-policy-feedback.md` - Policy engine and feedback loops
- `stage5-exploit-framework.md` - Ethical exploit framework
- `IMPLEMENTATION_PLAN.md` - Complete 24-week implementation plan

## License

[Your License Here]

## Disclaimer

This tool is designed for **authorized security testing only**. Unauthorized access to computer systems is illegal. Users are solely responsible for:
- Obtaining proper authorization before testing
- Ensuring compliance with all applicable laws
- Any consequences of misuse

The developers assume no liability for unauthorized or illegal use of this software.

## Contributing

Contributions are welcome! Please read CONTRIBUTING.md for guidelines.

## Support

For issues, questions, or contributions, please open an issue on GitHub.
