"""Main orchestration module for Vulner platform"""

import asyncio
import logging
from typing import Optional, Dict, List
from dataclasses import dataclass
from pathlib import Path

from .config import settings
from .worktree.manager import WorktreeManager, worktree_context
from .container.orchestrator import ContainerOrchestrator, container_environment
from .container.security_policies import DEFAULT_POLICY

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of vulnerability scan"""
    scan_id: str
    url: str
    tech_stack: Dict
    vulnerabilities: List[Dict]
    exploit_results: Optional[List[Dict]] = None
    status: str = "completed"
    error: Optional[str] = None


class VulnerPlatform:
    """Main vulnerability assessment platform orchestrator"""

    def __init__(
        self,
        repo_path: str = ".",
        worktree_base: Optional[Path] = None,
        container_runtime: str = "podman"
    ):
        """
        Initialize Vulner platform

        Args:
            repo_path: Git repository path
            worktree_base: Base directory for worktrees
            container_runtime: Container runtime (podman or docker)
        """
        self.repo_path = Path(repo_path).resolve()
        self.worktree_base = worktree_base or settings.worktree_base_dir

        # Initialize managers
        self.worktree_mgr = WorktreeManager(
            repo_path=str(self.repo_path),
            worktree_base=str(self.worktree_base)
        )
        self.container_orch = ContainerOrchestrator(runtime=container_runtime)

        logger.info(f"Initialized Vulner platform at {self.repo_path}")

    async def scan_target(
        self,
        url: str,
        user_image: str = "alpine:latest",
        authorization_token: Optional[str] = None,
        commit_ref: str = "HEAD"
    ) -> ScanResult:
        """
        Execute complete vulnerability scan

        Args:
            url: Target URL to scan
            user_image: Container image to use
            authorization_token: JWT token for exploit execution
            commit_ref: Git commit reference

        Returns:
            ScanResult with findings
        """
        import uuid
        scan_id = str(uuid.uuid4())[:8]

        logger.info(f"Starting scan {scan_id} for {url}")

        try:
            # Phase 1: Create isolated worktree
            with worktree_context(self.worktree_mgr, commit_ref) as worktree_info:
                logger.info(f"Created worktree: {worktree_info['path']}")

                # Phase 2: Deploy containers with sidecar
                with container_environment(
                    self.container_orch,
                    user_image,
                    use_pod=True
                ) as env:
                    logger.info(f"Created pod: {env['pod_id']}")

                    # Phase 3: Detect tech stack
                    tech_stack = await self._detect_tech_stack(url)
                    logger.info(f"Detected tech stack: {tech_stack}")

                    # Phase 4: Query vulnerability database
                    vulnerabilities = await self._query_vulnerabilities(tech_stack)
                    logger.info(f"Found {len(vulnerabilities)} potential vulnerabilities")

                    # Phase 5: Execute feedback loop (validate findings)
                    validated_vulns = await self._run_feedback_loop(
                        vulnerabilities,
                        url,
                        env
                    )
                    logger.info(f"Validated {len(validated_vulns)} vulnerabilities")

                    # Phase 6: Generate exploits (if authorized)
                    exploit_results = None
                    if authorization_token:
                        exploit_results = await self._execute_exploits(
                            validated_vulns,
                            url,
                            authorization_token,
                            env
                        )
                        logger.info(f"Executed {len(exploit_results)} exploit verifications")

                    return ScanResult(
                        scan_id=scan_id,
                        url=url,
                        tech_stack=tech_stack,
                        vulnerabilities=validated_vulns,
                        exploit_results=exploit_results,
                        status="completed"
                    )

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            return ScanResult(
                scan_id=scan_id,
                url=url,
                tech_stack={},
                vulnerabilities=[],
                status="failed",
                error=str(e)
            )

    async def _detect_tech_stack(self, url: str) -> Dict:
        """Detect technology stack for target URL"""
        # Placeholder - will be implemented with actual tech stack detector
        logger.info(f"Detecting tech stack for {url}")
        return {
            "url": url,
            "technologies": {},
            "detection_methods": []
        }

    async def _query_vulnerabilities(self, tech_stack: Dict) -> List[Dict]:
        """Query vulnerability database for tech stack"""
        # Placeholder - will be implemented with vector DB integration
        logger.info("Querying vulnerability database")
        return []

    async def _run_feedback_loop(
        self,
        vulnerabilities: List[Dict],
        url: str,
        env: Dict
    ) -> List[Dict]:
        """Execute feedback loop to validate findings"""
        # Placeholder - will be implemented with feedback loop state machine
        logger.info("Running feedback loop validation")
        return vulnerabilities

    async def _execute_exploits(
        self,
        vulnerabilities: List[Dict],
        url: str,
        authorization_token: str,
        env: Dict
    ) -> List[Dict]:
        """Execute exploit verification (requires authorization)"""
        # Placeholder - will be implemented with SafeExploit framework
        logger.info("Executing authorized exploit verification")
        return []

    def cleanup_old_worktrees(self, max_age_hours: int = 24):
        """Cleanup worktrees older than specified age"""
        self.worktree_mgr.cleanup_old_worktrees(max_age_hours)

    def prune_worktrees(self):
        """Prune stale worktree references"""
        self.worktree_mgr.prune()


async def main():
    """Example usage"""
    platform = VulnerPlatform(
        repo_path=".",
        container_runtime=settings.container_runtime
    )

    # Run scan
    result = await platform.scan_target("https://example.com")

    print(f"Scan ID: {result.scan_id}")
    print(f"Status: {result.status}")
    print(f"Tech Stack: {result.tech_stack}")
    print(f"Vulnerabilities: {len(result.vulnerabilities)}")

    # Cleanup
    platform.cleanup_old_worktrees()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
