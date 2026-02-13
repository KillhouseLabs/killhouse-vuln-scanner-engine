"""Main orchestration module for Vulner platform"""

import asyncio
import logging
import json
from typing import Optional, Dict, List
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime

from .config import settings
from .worktree.manager import WorktreeManager, worktree_context
from .container.orchestrator import ContainerOrchestrator, container_environment
from .container.security_policies import DEFAULT_POLICY
from .detection.tech_stack_detector import TechStackDetector
from .vulnerability.vuln_database import VulnerabilityDatabase
from .database.vector_store import VectorStore
from .database.embedding_cache import EmbeddingCache
from .analysis.vulnerability_analyzer import VulnerabilityAnalyzer
from .feedback.state_machine import FeedbackLoopStateMachine, State
from .feedback.persistence import FeedbackLoopPersistence
from .feedback.llm_validator import LLMVulnerabilityValidator
from .policy.engine import PolicyEngine, ActionType, ExecutionContext

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of vulnerability scan"""
    scan_id: str
    url: str
    tech_stack: Dict
    vulnerabilities: List[Dict]
    exploit_results: Optional[List[Dict]] = None
    vulnerability_analyses: Optional[List[Dict]] = None
    executive_summary: Optional[Dict] = None
    feedback_loop_report: Optional[Dict] = None
    status: str = "completed"
    error: Optional[str] = None
    timestamp: str = None

    def __post_init__(self):
        """Set timestamp if not provided"""
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)

    def save_to_json(self, output_dir: Path = Path("scan_results")) -> Path:
        """
        Save scan result to JSON file

        Args:
            output_dir: Directory to save results

        Returns:
            Path to saved file
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate filename with timestamp
        filename = f"scan_{self.scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output_path = output_dir / filename

        # Save to JSON
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

        logger.info(f"Saved scan result to: {output_path}")
        return output_path

    def print_summary(self):
        """Print formatted summary to console"""
        print("\n" + "="*80)
        print(f"VULNERABILITY SCAN REPORT")
        print("="*80)
        print(f"\nScan ID: {self.scan_id}")
        print(f"Target URL: {self.url}")
        print(f"Status: {self.status}")
        print(f"Timestamp: {self.timestamp}")

        if self.error:
            print(f"\n❌ Error: {self.error}")
            return

        # Tech Stack
        print(f"\n{'='*80}")
        print("DETECTED TECHNOLOGIES")
        print("="*80)

        technologies = self.tech_stack.get('technologies', {})
        if technologies:
            for tech_name, tech_info in technologies.items():
                version = tech_info.get('version', 'N/A')
                confidence = tech_info.get('confidence', 0) * 100
                print(f"\n  • {tech_name}")
                if version:
                    print(f"    Version: {version}")
                print(f"    Confidence: {confidence:.0f}%")
                print(f"    Category: {tech_info.get('category', 'N/A')}")
                print(f"    Detection: {tech_info.get('detection_method', 'N/A')}")
        else:
            print("\n  No technologies detected")

        # Vulnerabilities
        total_found = len(self.vulnerabilities)
        validated_count = sum(1 for v in self.vulnerabilities if v.get('validated', False))

        print(f"\n{'='*80}")
        print(f"VULNERABILITIES")
        print("="*80)
        print(f"\n📊 검증 결과:")
        print(f"   총 발견: {total_found}개")
        print(f"   검증 완료: {validated_count}개")
        if validated_count < total_found:
            print(f"   필터링됨: {total_found - validated_count}개 (악용 불가능 또는 낮은 신뢰도)")

        if self.vulnerabilities:
            # Group by severity
            severity_groups = {}
            for vuln in self.vulnerabilities:
                severity = vuln.get('severity', 'UNKNOWN')
                if severity not in severity_groups:
                    severity_groups[severity] = []
                severity_groups[severity].append(vuln)

            # Print by severity (CRITICAL -> HIGH -> MEDIUM -> LOW)
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                if severity in severity_groups:
                    vulns = severity_groups[severity]
                    print(f"\n{severity} ({len(vulns)})")
                    print("-" * 80)

                    for vuln in vulns[:10]:  # Show first 10 per severity
                        print(f"\n  [{vuln.get('id', 'N/A')}] {vuln.get('title', 'No title')}")
                        print(f"  Technology: {vuln.get('tech_name', 'N/A')}")

                        cvss = vuln.get('cvss_score', 0)
                        if cvss > 0:
                            print(f"  CVSS Score: {cvss}")

                        desc = vuln.get('description', '')
                        if desc:
                            # Truncate long descriptions
                            desc_preview = desc[:200] + "..." if len(desc) > 200 else desc
                            print(f"  Description: {desc_preview}")

                        affected = vuln.get('affected_versions', [])
                        if affected:
                            print(f"  Affected Versions: {', '.join(affected[:3])}")

                        fixed = vuln.get('fixed_versions', [])
                        if fixed:
                            print(f"  Fixed In: {', '.join(fixed[:3])}")

                    if len(vulns) > 10:
                        print(f"\n  ... and {len(vulns) - 10} more {severity} vulnerabilities")
        else:
            print("\n  ✅ No vulnerabilities found")

        # Exploit Results
        if self.exploit_results:
            print(f"\n{'='*80}")
            print(f"EXPLOIT VERIFICATION ({len(self.exploit_results)} executed)")
            print("="*80)
            for result in self.exploit_results:
                print(f"\n  • {result}")

        # AI Analysis - Executive Summary
        if self.executive_summary:
            print(f"\n{'='*80}")
            print("🤖 AI 분석: 경영진 요약")
            print("="*80)

            summary = self.executive_summary.get('executive_summary', {})

            if summary.get('overview'):
                print(f"\n📋 개요:")
                print(f"  {summary['overview']}")

            if summary.get('key_findings'):
                print(f"\n🔍 주요 발견사항:")
                for finding in summary['key_findings']:
                    print(f"  • {finding}")

            if summary.get('critical_risks'):
                print(f"\n⚠️  중요 위험:")
                print(f"  {summary['critical_risks']}")

            if summary.get('recommendations'):
                print(f"\n✅ 권장 조치사항:")
                for i, rec in enumerate(summary['recommendations'], 1):
                    print(f"  {i}. {rec}")

            if summary.get('timeline'):
                print(f"\n⏱️  권장 일정:")
                print(f"  {summary['timeline']}")

        # AI Analysis - Detailed Vulnerability Analysis
        if self.vulnerability_analyses:
            print(f"\n{'='*80}")
            print(f"🤖 AI 분석: 상세 취약점 분석 ({len(self.vulnerability_analyses)}개)")
            print("="*80)

            for analysis in self.vulnerability_analyses[:5]:  # Show top 5
                if 'error' in analysis:
                    continue

                vuln_id = analysis.get('vulnerability_id')
                ai_analysis = analysis.get('analysis', {})

                print(f"\n[{vuln_id}]")
                print("-" * 80)

                if ai_analysis.get('summary'):
                    print(f"\n  📝 요약:")
                    print(f"     {ai_analysis['summary']}")

                if ai_analysis.get('risk'):
                    print(f"\n  ⚠️  위험성:")
                    print(f"     {ai_analysis['risk']}")

                if ai_analysis.get('affected'):
                    print(f"\n  🎯 영향 대상:")
                    print(f"     {ai_analysis['affected']}")

                if ai_analysis.get('action'):
                    print(f"\n  🔧 조치 방법:")
                    print(f"     {ai_analysis['action']}")

                if ai_analysis.get('severity_explanation'):
                    print(f"\n  📊 심각도 설명:")
                    print(f"     {ai_analysis['severity_explanation']}")

            if len(self.vulnerability_analyses) > 5:
                print(f"\n  ... 그 외 {len(self.vulnerability_analyses) - 5}개의 상세 분석이 JSON 파일에 저장되었습니다.")

        # Feedback Loop Report
        if self.feedback_loop_report:
            print(f"\n{'='*80}")
            print("🔄 피드백 루프 검증 리포트")
            print("="*80)

            metrics = self.feedback_loop_report.get('metrics', {})
            if metrics:
                print(f"\n  📊 검증 통계:")
                print(f"     총 루프 반복: {metrics.get('total_loops', 0)}")
                print(f"     관찰 수행: {metrics.get('observations_made', 0)}")
                print(f"     가설 생성: {metrics.get('hypotheses_generated', 0)}")
                print(f"     액션 실행: {metrics.get('actions_executed', 0)}")
                print(f"     검증 완료: {metrics.get('validations_completed', 0)}")
                print(f"     실제 취약점: {metrics.get('true_positives', 0)}")
                print(f"     오탐지: {metrics.get('false_positives', 0)}")

            validated = self.feedback_loop_report.get('validated_vulnerabilities', {})
            if validated:
                print(f"\n  ✅ 검증된 취약점: {len(validated)}개")
                for vuln_id in list(validated.keys())[:5]:
                    print(f"     • {vuln_id}")
                if len(validated) > 5:
                    print(f"     ... 외 {len(validated) - 5}개")

        print("\n" + "="*80 + "\n")


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

        # Phase 2 components (initialized lazily)
        self.tech_detector: Optional[TechStackDetector] = None
        self.vuln_db: Optional[VulnerabilityDatabase] = None
        self.vector_store: Optional[VectorStore] = None
        self.embedding_cache: Optional[EmbeddingCache] = None
        self.vuln_analyzer: Optional[VulnerabilityAnalyzer] = None

        # Phase 3 components (initialized lazily)
        self.policy_engine: Optional[PolicyEngine] = None
        self.feedback_persistence: Optional[FeedbackLoopPersistence] = None
        self.llm_validator: Optional[LLMVulnerabilityValidator] = None

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
                    validated_vulns, feedback_report = await self._run_feedback_loop(
                        vulnerabilities,
                        tech_stack,
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

                    # Phase 7: AI Analysis (if OpenAI key available)
                    vulnerability_analyses = None
                    executive_summary = None
                    if settings.openai_api_key:
                        vulnerability_analyses, executive_summary = await self._analyze_vulnerabilities(
                            validated_vulns,
                            tech_stack,
                            scan_id,
                            url,
                            total_vulnerabilities_found=len(vulnerabilities)  # Pass original count
                        )
                        logger.info(f"Generated AI analysis for {len(vulnerability_analyses)} vulnerabilities")

                    return ScanResult(
                        scan_id=scan_id,
                        url=url,
                        tech_stack=tech_stack,
                        vulnerabilities=validated_vulns,
                        exploit_results=exploit_results,
                        vulnerability_analyses=vulnerability_analyses,
                        executive_summary=executive_summary,
                        feedback_loop_report=feedback_report,
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
        logger.info(f"Detecting tech stack for {url}")

        # Initialize tech detector lazily
        if not self.tech_detector:
            self.tech_detector = TechStackDetector()

        try:
            technologies = await self.tech_detector.detect(url)

            tech_dict = {
                tech.name: {
                    "version": tech.version,
                    "category": tech.category,
                    "confidence": tech.confidence,
                    "detection_method": tech.detection_method
                }
                for tech in technologies
            }

            return {
                "url": url,
                "technologies": tech_dict,
                "detection_methods": list(set(tech.detection_method for tech in technologies))
            }
        except Exception as e:
            logger.error(f"Tech stack detection failed: {e}")
            return {
                "url": url,
                "technologies": {},
                "detection_methods": [],
                "error": str(e)
            }

    async def _query_vulnerabilities(self, tech_stack: Dict) -> List[Dict]:
        """Query vulnerability database for tech stack"""
        logger.info("Querying vulnerability database")

        # Initialize vuln database lazily
        if not self.vuln_db:
            self.vuln_db = VulnerabilityDatabase()

        # Initialize vector store if Supabase is configured
        if settings.supabase_url and settings.supabase_key and not self.vector_store:
            self.vector_store = VectorStore(
                supabase_url=settings.supabase_url,
                supabase_key=settings.supabase_key,
                openai_api_key=settings.openai_api_key
            )

        vulnerabilities = []
        technologies = tech_stack.get("technologies", {})

        for tech_name, tech_info in technologies.items():
            try:
                # Query OSV.dev and NVD
                vulns = await self.vuln_db.query_vulnerabilities(
                    package_name=tech_name,
                    version=tech_info.get("version"),
                    ecosystem="npm"  # TODO: detect ecosystem from tech category
                )

                # Convert to dict format
                for vuln in vulns:
                    vulnerabilities.append({
                        "id": vuln.id,
                        "tech_name": tech_name,
                        "title": vuln.title,
                        "description": vuln.description,
                        "severity": vuln.severity,
                        "cvss_score": vuln.cvss_score,
                        "affected_versions": vuln.affected_versions,
                        "fixed_versions": vuln.fixed_versions,
                        "published_date": vuln.published_date,
                        "references": vuln.references,
                        "source": vuln.source
                    })

                # Also query vector store if available
                if self.vector_store:
                    similar_vulns = await self.vector_store.search_similar(
                        query=f"{tech_name} vulnerabilities",
                        tech_name=tech_name,
                        limit=5
                    )
                    # Merge results (deduplicate by ID)
                    existing_ids = {v["id"] for v in vulnerabilities}
                    for sv in similar_vulns:
                        if sv["vulnerability_id"] not in existing_ids:
                            vulnerabilities.append({
                                "id": sv["vulnerability_id"],
                                "tech_name": sv["tech_name"],
                                "title": sv["title"],
                                "description": sv["description"],
                                "severity": sv["severity"],
                                "cvss_score": sv["cvss_score"],
                                "source": "vector_db",
                                "similarity": sv.get("similarity", 0)
                            })

            except Exception as e:
                logger.warning(f"Failed to query vulnerabilities for {tech_name}: {e}")
                continue

        logger.info(f"Found {len(vulnerabilities)} total vulnerabilities")
        return vulnerabilities

    async def _run_feedback_loop(
        self,
        vulnerabilities: List[Dict],
        tech_stack: Dict,
        url: str,
        env: Dict
    ) -> tuple[List[Dict], Dict]:
        """
        Execute feedback loop to validate findings

        Implements 8-state OODA loop:
        IDLE -> OBSERVING -> ORIENTING -> HYPOTHESIZING ->
        DECIDING -> ACTING -> VALIDATING -> REPORTING

        Args:
            vulnerabilities: List of potential vulnerabilities
            url: Target URL
            env: Container environment context

        Returns:
            List of validated vulnerabilities
        """
        import uuid
        scan_id = str(uuid.uuid4())[:8]

        logger.info(f"Starting feedback loop {scan_id} for {len(vulnerabilities)} vulnerabilities")

        try:
            # Initialize components lazily
            if not self.policy_engine:
                self.policy_engine = PolicyEngine(
                    jwt_secret=settings.jwt_secret if hasattr(settings, 'jwt_secret') else None,
                    require_authorization=False  # Scanning doesn't require auth
                )

            if not self.feedback_persistence:
                self.feedback_persistence = FeedbackLoopPersistence()

            if not self.llm_validator and settings.openai_api_key:
                self.llm_validator = LLMVulnerabilityValidator(
                    openai_api_key=settings.openai_api_key,
                    model="gpt-4o-mini"
                )

            # Create feedback loop state machine
            state_machine = FeedbackLoopStateMachine(
                scan_id=scan_id,
                persistence_path=Path(f".feedback/{scan_id}")
            )

            # Create persistence session
            tech_stack = {"url": url, "technologies": {}}
            self.feedback_persistence.create_session(
                scan_id=scan_id,
                target_url=url,
                metadata={"container_env": env.get("pod_id", "unknown")}
            )

            # Phase 1: OBSERVING - Collect data
            state_machine.observe(
                vulnerabilities=vulnerabilities,
                tech_stack=tech_stack,
                target_url=url
            )

            # Persist observation
            self.feedback_persistence.add_observation(
                scan_id=scan_id,
                observation_data={
                    "vulnerability_count": len(vulnerabilities),
                    "url": url
                }
            )

            # Phase 2: ORIENTING - Analyze data
            orientation = state_machine.orient()
            logger.info(f"Orientation complete: {orientation.get('high_priority_count', 0)} high-priority vulnerabilities")

            # Phase 3: HYPOTHESIZING - Form hypotheses
            hypotheses = state_machine.hypothesize(llm_engine=None)
            logger.info(f"Generated {len(hypotheses)} hypotheses")

            # Persist hypotheses
            for hypothesis in hypotheses:
                self.feedback_persistence.add_hypothesis(
                    scan_id=scan_id,
                    vulnerability_id=hypothesis.vulnerability_id,
                    hypothesis=hypothesis.hypothesis,
                    confidence=hypothesis.confidence,
                    evidence=hypothesis.evidence,
                    validation_plan=hypothesis.validation_plan
                )

            # Phase 4: DECIDING - Plan validation actions
            actions = state_machine.decide()
            logger.info(f"Planned {len(actions)} validation actions")

            # Persist actions
            for action in actions:
                self.feedback_persistence.add_action(
                    scan_id=scan_id,
                    action_id=action.action_id,
                    action_type=action.action_type,
                    target=action.target,
                    parameters=action.parameters,
                    expected_result=action.expected_result
                )

            # Phase 5: ACTING - Execute validation actions (simulated)
            executed_actions = await state_machine.act(action_executor=None)
            logger.info(f"Executed {len(executed_actions)} actions")

            # Update action results in persistence
            for action in executed_actions:
                if action.executed_at:
                    self.feedback_persistence.update_action_result(
                        action_id=action.action_id,
                        actual_result=action.actual_result or "No result",
                        success=action.success or False
                    )

            # Phase 6: VALIDATING - Use LLM to validate hypotheses
            validations = {}

            if self.llm_validator and hypotheses:
                logger.info("Running LLM-based hypothesis validation")

                validation_results = await self.llm_validator.validate_hypotheses(
                    hypotheses=hypotheses,
                    tech_stack=tech_stack,
                    target_url=url,
                    max_concurrent=3
                )

                # Update validations based on LLM results
                for result in validation_results:
                    vuln_id = result["vulnerability_id"]
                    is_exploitable = result["is_exploitable"]
                    confidence = result["confidence"]

                    # Consider valid if exploitable and high confidence
                    is_valid = is_exploitable and confidence >= 0.6
                    validations[vuln_id] = is_valid

                    # Persist validation
                    self.feedback_persistence.add_validation(
                        scan_id=scan_id,
                        vulnerability_id=vuln_id,
                        is_valid=is_valid,
                        details={
                            "llm_reasoning": result["reasoning"],
                            "confidence": confidence,
                            "attack_vectors": result["attack_vectors"],
                            "impact": result["impact_assessment"]
                        }
                    )

                    logger.info(f"Validated {vuln_id}: valid={is_valid}, confidence={confidence:.2f}")

                # Update state machine's validations with LLM results
                state_machine.validations.update(validations)

                # Transition state machine to REPORTING state
                from .feedback.state_machine import State
                state_machine.transition_to(
                    State.REPORTING,
                    "LLM validation complete, generating report"
                )

            else:
                # Fallback: use state machine validation (simpler logic)
                validations = state_machine.validate()

                for vuln_id, is_valid in validations.items():
                    self.feedback_persistence.add_validation(
                        scan_id=scan_id,
                        vulnerability_id=vuln_id,
                        is_valid=is_valid,
                        details={"method": "state_machine"}
                    )

            # Phase 7: REPORTING - Generate report
            report = state_machine.report()
            logger.info(f"Feedback loop complete: {len(validations)} validations")

            # Complete session in persistence
            self.feedback_persistence.complete_session(scan_id)

            # Filter vulnerabilities to only validated ones
            validated_vulnerabilities = []
            for vuln in vulnerabilities:
                vuln_id = vuln.get("id")
                if vuln_id in validations and validations[vuln_id]:
                    # Mark as validated
                    vuln["validated"] = True
                    vuln["validation_confidence"] = validations.get(vuln_id, 0.0)
                    validated_vulnerabilities.append(vuln)

            logger.info(f"Feedback loop validated {len(validated_vulnerabilities)}/{len(vulnerabilities)} vulnerabilities")

            return validated_vulnerabilities, report

        except Exception as e:
            logger.error(f"Feedback loop failed: {e}")
            # On error, return original vulnerabilities (no validation)
            return vulnerabilities, {}

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

    async def _analyze_vulnerabilities(
        self,
        vulnerabilities: List[Dict],
        tech_stack: Dict,
        scan_id: str,
        url: str,
        total_vulnerabilities_found: int = None
    ) -> tuple[List[Dict], Dict]:
        """
        Analyze vulnerabilities using AI

        Args:
            vulnerabilities: List of vulnerabilities
            tech_stack: Detected tech stack
            scan_id: Scan ID
            url: Target URL

        Returns:
            Tuple of (vulnerability analyses, executive summary)
        """
        logger.info("Analyzing vulnerabilities with AI")

        # Initialize analyzer lazily
        if not self.vuln_analyzer:
            self.vuln_analyzer = VulnerabilityAnalyzer(
                openai_api_key=settings.openai_api_key,
                model="gpt-4o-mini"  # Fast and cost-effective
            )

        try:
            # Analyze critical and high severity vulnerabilities in detail
            critical_high = [
                v for v in vulnerabilities
                if v.get("severity") in ["CRITICAL", "HIGH"]
            ]

            # Limit to top 10 most severe for detailed analysis
            to_analyze = critical_high[:10] if len(critical_high) > 10 else critical_high

            # Add a few medium severity for context (if we have room)
            if len(to_analyze) < 10:
                medium = [v for v in vulnerabilities if v.get("severity") == "MEDIUM"]
                to_analyze.extend(medium[:10 - len(to_analyze)])

            # Analyze vulnerabilities
            analyses = []
            if to_analyze:
                analyses = await self.vuln_analyzer.analyze_vulnerabilities(
                    to_analyze,
                    language="Korean"
                )
                logger.info(f"Analyzed {len(analyses)} vulnerabilities in detail")

            # Generate executive summary
            scan_result = {
                "scan_id": scan_id,
                "url": url,
                "tech_stack": tech_stack,
                "vulnerabilities": vulnerabilities,
                "timestamp": datetime.now().isoformat(),
                "total_found": total_vulnerabilities_found if total_vulnerabilities_found else len(vulnerabilities),
                "validated_count": len(vulnerabilities)
            }

            executive_summary = await self.vuln_analyzer.generate_executive_summary(
                scan_result,
                language="Korean"
            )
            logger.info("Generated executive summary")

            # Log stats
            stats = self.vuln_analyzer.get_stats()
            logger.info(f"AI Analysis Stats: {stats}")

            return analyses, executive_summary

        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return [], {}

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
    result = await platform.scan_target("https://hamalab.io")

    # Print detailed summary to console
    result.print_summary()

    # Save to JSON file
    output_path = result.save_to_json()
    print(f"\n💾 Full report saved to: {output_path}")

    # Cleanup
    platform.cleanup_old_worktrees()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
