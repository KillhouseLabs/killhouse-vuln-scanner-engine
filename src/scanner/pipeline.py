"""Scan pipeline orchestrating SAST, DAST, aggregation, and callback"""

import asyncio
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx

from .aggregator import AggregatedResult, ResultAggregator
from .config import PipelineConfig
from .dast import NucleiScanner
from .domain import LogMessage, PipelinePhase, StepKey, StepResult, StepStatus
from .exploit_client import ExploitAgentClient
from .mappers import build_failure_payload, build_result_payload, log_to_webhook_payload
from .sast import SemgrepScanner

logger = logging.getLogger(__name__)

CONFIG = PipelineConfig()


class ScanPipeline:
    """Orchestrates the full scan pipeline with per-step state tracking"""

    def __init__(self):
        self.sast_scanner = SemgrepScanner()
        self.dast_scanner = NucleiScanner()
        self.aggregator = ResultAggregator(openai_api_key=os.getenv("OPENAI_API_KEY"))
        self._exploit_client = ExploitAgentClient(config=CONFIG)

    # ── HTTP helpers ───────────────────────────────────────────────

    async def _post_webhook(self, url: str, payload: dict, timeout: int) -> httpx.Response:
        """Send an authenticated POST to a webhook endpoint."""
        api_key = os.getenv("SCANNER_API_KEY", "")
        async with httpx.AsyncClient(timeout=timeout) as client:
            return await client.post(
                url,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                },
            )

    async def _notify(
        self,
        callback_url: Optional[str],
        analysis_id: str,
        phase: PipelinePhase,
        scan_id: str,
        log: LogMessage,
    ):
        """Send a phase notification if callback_url is configured (no-op otherwise)."""
        if not callback_url:
            return
        await self._send_status_callback(callback_url, analysis_id, phase, scan_id, log=log)

    # ── Step executors ─────────────────────────────────────────────

    def _clone_repository(
        self,
        scan_id: str,
        repo_url: Optional[str],
        branch: str,
        local_path: Optional[str],
    ) -> Tuple[Optional[Path], StepResult, Optional[str]]:
        """Clone the target repository. Returns (repo_path, result, clone_output)."""
        if local_path:
            return Path(local_path), StepResult(status=StepStatus.SUCCESS), None

        if not repo_url:
            return None, StepResult(status=StepStatus.SKIPPED, error="No repo URL provided"), None

        try:
            repo_path, clone_output = self.sast_scanner.clone_repo(repo_url, branch)
            return repo_path, StepResult(status=StepStatus.SUCCESS), clone_output
        except Exception as e:
            logger.error(f"[{scan_id}] Clone failed: {e}")
            return None, StepResult(status=StepStatus.FAILED, error=str(e)), None

    def _run_sast(
        self,
        scan_id: str,
        repo_path: Optional[Path],
        clone_succeeded: bool,
    ) -> Tuple[List, StepResult, Optional[str]]:
        """Run static analysis on the cloned repository. Returns (findings, result, raw_output)."""
        if not repo_path or not clone_succeeded:
            return (
                [],
                StepResult(status=StepStatus.SKIPPED, error="Clone was skipped or failed"),
                None,
            )

        try:
            findings, raw_output = self.sast_scanner.run(repo_path)
            logger.info(f"[{scan_id}] SAST found {len(findings)} issues")
            return (
                findings,
                StepResult(status=StepStatus.SUCCESS, findings_count=len(findings)),
                raw_output,
            )
        except Exception as e:
            logger.error(f"[{scan_id}] SAST failed: {e}")
            return [], StepResult(status=StepStatus.FAILED, error=str(e)), None

    async def _run_dast(
        self,
        scan_id: str,
        target_url: Optional[str],
        network_name: Optional[str],
    ) -> Tuple[List, StepResult, Optional[str]]:
        """Run dynamic analysis against the target. Returns (findings, result, raw_output)."""
        if not target_url:
            return [], StepResult(status=StepStatus.SKIPPED, error="No target URL provided"), None

        network_connected = False
        if network_name:
            network_connected = self.dast_scanner._connect_to_network(network_name)
            if not network_connected:
                error = f"Failed to connect to Docker network '{network_name}'"
                logger.error(f"[{scan_id}] DAST: cannot connect to network {network_name}")
                return [], StepResult(status=StepStatus.FAILED, error=error), None

        try:
            return await self._execute_dast_scan(scan_id, target_url)
        except Exception as e:
            logger.error(f"[{scan_id}] DAST failed: {e}")
            return [], StepResult(status=StepStatus.FAILED, error=str(e)), None
        finally:
            if network_connected and network_name:
                self.dast_scanner._disconnect_from_network(network_name)

    async def _execute_dast_scan(
        self,
        scan_id: str,
        target_url: str,
    ) -> Tuple[List, StepResult, Optional[str]]:
        """Execute the DAST scan with healthcheck and reachability verification."""
        target_ready = await self._wait_for_target(target_url, scan_id)
        if not target_ready:
            error = "Target not reachable after 120s healthcheck timeout"
            logger.error(f"[{scan_id}] DAST skipped: target not reachable")
            return [], StepResult(status=StepStatus.FAILED, error=error), None

        findings, raw_output = self.dast_scanner.run(target_url, network_name=None)

        if not findings:
            return await self._verify_empty_dast_result(scan_id, target_url, raw_output)

        logger.info(f"[{scan_id}] DAST found {len(findings)} issues")
        return (
            findings,
            StepResult(status=StepStatus.SUCCESS, findings_count=len(findings)),
            raw_output,
        )

    async def _verify_empty_dast_result(
        self,
        scan_id: str,
        target_url: str,
        raw_output: Optional[str],
    ) -> Tuple[List, StepResult, Optional[str]]:
        """When DAST finds 0 issues, verify the target was reachable during the scan."""
        still_reachable = await self._wait_for_target(
            target_url,
            scan_id,
            timeout=CONFIG.reachability_check_timeout,
            interval=CONFIG.reachability_check_interval,
        )
        if not still_reachable:
            logger.error(f"[{scan_id}] DAST: 0 findings and target unreachable")
            return (
                [],
                StepResult(status=StepStatus.FAILED, error="Target became unreachable during scan"),
                raw_output,
            )

        logger.info(f"[{scan_id}] DAST found 0 issues (target OK)")
        return [], StepResult(status=StepStatus.SUCCESS, findings_count=0), raw_output

    async def _wait_for_target(
        self,
        target_url: str,
        scan_id: str,
        timeout: int = CONFIG.healthcheck_timeout,
        interval: int = CONFIG.healthcheck_interval,
    ) -> bool:
        """Wait for target to become reachable before DAST scan."""
        logger.info(f"[{scan_id}] Waiting for target {target_url} to become reachable")
        elapsed = 0
        async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
            while elapsed < timeout:
                try:
                    response = await client.get(target_url)
                    logger.info(f"[{scan_id}] Target reachable: HTTP {response.status_code}")
                    return True
                except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
                    pass
                await asyncio.sleep(interval)
                elapsed += interval
        logger.error(f"[{scan_id}] Target not reachable after {timeout}s")
        return False

    # ── Pipeline orchestrator ──────────────────────────────────────

    async def run(
        self,
        scan_id: str,
        analysis_id: str,
        repo_url: Optional[str],
        branch: str,
        target_url: Optional[str],
        callback_url: Optional[str],
        scan_store: dict,
        local_path: Optional[str] = None,
        network_name: Optional[str] = None,
    ):
        """Execute full scan pipeline with per-step state tracking"""
        from src.api.schemas import ScanStatus

        logger.info(f"[{scan_id}] Starting pipeline for analysis {analysis_id}")
        scan_store[scan_id]["status"] = ScanStatus.SCANNING

        sast_findings: List = []
        dast_findings: List = []
        step_results: Dict[str, StepResult] = {
            StepKey.CLONING: StepResult(),
            StepKey.SAST: StepResult(),
            StepKey.BUILDING: StepResult(status=StepStatus.SKIPPED),
            StepKey.DAST: StepResult(),
        }

        try:
            # Step 1: Clone repository
            await self._notify(
                callback_url,
                analysis_id,
                PipelinePhase.CLONING,
                scan_id,
                LogMessage.info("Repository cloning started"),
            )
            repo_path, clone_result, clone_output = self._clone_repository(
                scan_id,
                repo_url,
                branch,
                local_path,
            )
            step_results[StepKey.CLONING] = clone_result

            if clone_result.is_success and clone_output:
                await self._notify(
                    callback_url,
                    analysis_id,
                    PipelinePhase.CLONING,
                    scan_id,
                    LogMessage.info(
                        f"Repository cloned: {repo_url} (branch: {branch})",
                        raw_output=clone_output,
                    ),
                )
            elif clone_result.is_failed:
                await self._notify(
                    callback_url,
                    analysis_id,
                    PipelinePhase.CLONING,
                    scan_id,
                    LogMessage.error(f"Clone failed: {clone_result.error}"),
                )

            # Step 2: Static analysis
            await self._notify(
                callback_url,
                analysis_id,
                PipelinePhase.STATIC_ANALYSIS,
                scan_id,
                LogMessage.info("Starting static analysis"),
            )
            sast_findings, sast_result, sast_output = self._run_sast(
                scan_id,
                repo_path,
                clone_result.is_success,
            )
            step_results[StepKey.SAST] = sast_result

            if sast_result.is_success:
                await self._notify(
                    callback_url,
                    analysis_id,
                    PipelinePhase.STATIC_ANALYSIS,
                    scan_id,
                    LogMessage.info(
                        f"SAST completed: {len(sast_findings)} findings",
                        raw_output=sast_output,
                    ),
                )
            elif sast_result.is_failed:
                await self._notify(
                    callback_url,
                    analysis_id,
                    PipelinePhase.STATIC_ANALYSIS,
                    scan_id,
                    LogMessage.error(f"SAST failed: {sast_result.error}"),
                )

            # Step 3: Building (handled by sandbox, scanner sends status only)
            await self._notify(
                callback_url,
                analysis_id,
                PipelinePhase.BUILDING,
                scan_id,
                LogMessage.info("Building sandbox environment"),
            )

            # Step 4: Dynamic analysis (DAST)
            await self._notify(
                callback_url,
                analysis_id,
                PipelinePhase.PENETRATION_TEST,
                scan_id,
                LogMessage.info("Starting penetration test"),
            )
            dast_findings, dast_result, dast_output = await self._run_dast(
                scan_id,
                target_url,
                network_name,
            )
            step_results[StepKey.DAST] = dast_result

            if dast_result.is_success:
                await self._notify(
                    callback_url,
                    analysis_id,
                    PipelinePhase.PENETRATION_TEST,
                    scan_id,
                    LogMessage.info(
                        f"DAST completed: {len(dast_findings)} findings",
                        raw_output=dast_output,
                    ),
                )
            elif dast_result.is_failed:
                await self._notify(
                    callback_url,
                    analysis_id,
                    PipelinePhase.PENETRATION_TEST,
                    scan_id,
                    LogMessage.error(f"DAST failed: {dast_result.error}"),
                )

            # Cleanup cloned repo if we cloned it (not local_path)
            if repo_path and not local_path:
                import shutil

                shutil.rmtree(repo_path, ignore_errors=True)

            # Step 5: Aggregate results
            result = self.aggregator.aggregate(sast_findings, dast_findings)

            # Step 6: Generate AI summaries
            try:
                result = await self.aggregator.generate_summaries(result)
            except Exception as e:
                logger.error(f"[{scan_id}] AI summary generation failed: {e}")

            # Step 7: Exploit verification (if findings exist and target is available)
            exploit_session_id = None
            if target_url and result.total > 0:
                await self._notify(
                    callback_url,
                    analysis_id,
                    PipelinePhase.EXPLOIT_VERIFICATION,
                    scan_id,
                    LogMessage.info("Starting exploit verification"),
                )
                exploit_session_id = await self._call_exploit_agent(
                    scan_id,
                    analysis_id,
                    target_url,
                    result,
                    network_name,
                )

            # Step 8: Send final callback with step_results
            if callback_url:
                await self._send_callback(
                    callback_url,
                    analysis_id,
                    result,
                    scan_id,
                    step_results,
                    exploit_session_id,
                )

            # Update scan store
            scan_store[scan_id]["status"] = ScanStatus.COMPLETED
            scan_store[scan_id]["completed_at"] = datetime.now()
            logger.info(f"[{scan_id}] Pipeline completed: {result.total} findings")

        except Exception as e:
            logger.error(f"[{scan_id}] Pipeline failed: {e}")
            scan_store[scan_id]["status"] = ScanStatus.FAILED
            scan_store[scan_id]["error"] = str(e)
            scan_store[scan_id]["completed_at"] = datetime.now()

            if callback_url:
                await self._send_failure_callback(
                    callback_url,
                    analysis_id,
                    str(e),
                    step_results,
                )

    # ── Webhook callbacks ──────────────────────────────────────────

    async def _send_status_callback(
        self,
        callback_url: str,
        analysis_id: str,
        status: PipelinePhase,
        scan_id: str,
        log: LogMessage,
    ):
        """Send status update with log message to callback URL (non-fatal on failure)."""
        payload = {
            "analysis_id": analysis_id,
            "status": status,
            **log_to_webhook_payload(log, CONFIG.raw_output_max_length),
        }
        try:
            await self._post_webhook(callback_url, payload, CONFIG.callback_timeout)
            logger.info(f"[{scan_id}] Status callback sent: {status}")
        except Exception as e:
            logger.warning(f"[{scan_id}] Status callback failed (non-fatal): {e}")

    async def _call_exploit_agent(
        self,
        scan_id: str,
        analysis_id: str,
        target_url: str,
        result: AggregatedResult,
        network_name: Optional[str] = None,
    ) -> Optional[str]:
        """Call exploit-agent to start a penetration test session. Returns session_id or None."""
        return await self._exploit_client.start_session(
            scan_id, analysis_id, target_url, result, network_name
        )

    async def _send_callback(
        self,
        callback_url: str,
        analysis_id: str,
        result: AggregatedResult,
        scan_id: str,
        step_results: Dict[str, StepResult],
        exploit_session_id: Optional[str] = None,
    ):
        """Send scan results to the callback URL"""
        payload = build_result_payload(analysis_id, result, step_results, exploit_session_id)

        logger.info(f"[{scan_id}] Sending callback to {callback_url}")
        try:
            response = await self._post_webhook(
                callback_url,
                payload,
                CONFIG.result_callback_timeout,
            )
            if response.status_code == 200:
                logger.info(f"[{scan_id}] Callback sent successfully")
            else:
                logger.warning(
                    f"[{scan_id}] Callback returned {response.status_code}: {response.text}"
                )
        except Exception as e:
            logger.error(f"[{scan_id}] Failed to send callback: {e}")

    async def _send_failure_callback(
        self,
        callback_url: str,
        analysis_id: str,
        error: str,
        step_results: Dict[str, StepResult],
    ):
        """Send failure notification to callback URL"""
        payload = build_failure_payload(analysis_id, error, step_results)
        try:
            await self._post_webhook(callback_url, payload, CONFIG.result_callback_timeout)
        except Exception as e:
            logger.error(f"Failed to send failure callback: {e}")
