"""Scan pipeline orchestrating SAST, DAST, aggregation, and callback"""

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional

import httpx

from .aggregator import AggregatedResult, ResultAggregator
from .dast import NucleiScanner
from .exceptions import ScannerNotFoundError, ScannerTimeoutError
from .sast import SemgrepScanner

logger = logging.getLogger(__name__)


@dataclass
class StepResult:
    """Result of a single pipeline step"""

    status: str = "pending"  # "success" | "failed" | "skipped"
    findings_count: int = 0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        result = {"status": self.status}
        if self.findings_count > 0:
            result["findings_count"] = self.findings_count
        if self.error:
            result["error"] = self.error
        return result


class ScanPipeline:
    """Orchestrates the full scan pipeline with per-step state tracking"""

    def __init__(self):
        self.sast_scanner = SemgrepScanner()
        self.dast_scanner = NucleiScanner()
        self.aggregator = ResultAggregator(openai_api_key=os.getenv("OPENAI_API_KEY"))

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
    ):
        """Execute full scan pipeline with per-step state tracking"""
        from pathlib import Path

        from src.api.schemas import ScanStatus

        logger.info(f"[{scan_id}] Starting pipeline for analysis {analysis_id}")
        scan_store[scan_id]["status"] = ScanStatus.SCANNING

        sast_findings = []
        dast_findings = []
        step_results: Dict[str, StepResult] = {
            "cloning": StepResult(),
            "sast": StepResult(),
            "building": StepResult(status="skipped"),
            "dast": StepResult(),
        }

        try:
            # Step 1: Clone repository
            repo_path = None
            if callback_url:
                await self._send_status_callback(callback_url, analysis_id, "CLONING", scan_id)

            if local_path:
                step_results["cloning"] = StepResult(status="success")
                repo_path = Path(local_path)
            elif repo_url:
                try:
                    repo_path = self.sast_scanner.clone_repo(repo_url, branch)
                    step_results["cloning"] = StepResult(status="success")
                except Exception as e:
                    step_results["cloning"] = StepResult(status="failed", error=str(e))
                    logger.error(f"[{scan_id}] Clone failed: {e}")
            else:
                step_results["cloning"] = StepResult(status="skipped", error="No repo URL provided")

            # Step 2: SAST scan
            if repo_path and step_results["cloning"].status == "success":
                if callback_url:
                    await self._send_status_callback(
                        callback_url, analysis_id, "STATIC_ANALYSIS", scan_id
                    )
                try:
                    sast_findings = self.sast_scanner.run(repo_path)
                    step_results["sast"] = StepResult(
                        status="success", findings_count=len(sast_findings)
                    )
                    logger.info(f"[{scan_id}] SAST found {len(sast_findings)} issues")
                except (ScannerNotFoundError, ScannerTimeoutError) as e:
                    step_results["sast"] = StepResult(status="failed", error=str(e))
                    logger.error(f"[{scan_id}] SAST failed: {e}")
                except Exception as e:
                    step_results["sast"] = StepResult(status="failed", error=str(e))
                    logger.error(f"[{scan_id}] SAST failed: {e}")
            else:
                reason = "Clone was skipped or failed"
                step_results["sast"] = StepResult(status="skipped", error=reason)

            # Step 3: Building (handled by sandbox, scanner sends status only)
            if callback_url:
                await self._send_status_callback(callback_url, analysis_id, "BUILDING", scan_id)

            # Step 4: DAST scan
            if target_url:
                if callback_url:
                    await self._send_status_callback(
                        callback_url, analysis_id, "PENETRATION_TEST", scan_id
                    )
                try:
                    dast_findings = self.dast_scanner.run(target_url)
                    step_results["dast"] = StepResult(
                        status="success", findings_count=len(dast_findings)
                    )
                    logger.info(f"[{scan_id}] DAST found {len(dast_findings)} issues")
                except (ScannerNotFoundError, ScannerTimeoutError) as e:
                    step_results["dast"] = StepResult(status="failed", error=str(e))
                    logger.error(f"[{scan_id}] DAST failed: {e}")
                except Exception as e:
                    step_results["dast"] = StepResult(status="failed", error=str(e))
                    logger.error(f"[{scan_id}] DAST failed: {e}")
            else:
                step_results["dast"] = StepResult(status="skipped", error="No target URL provided")

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

            # Step 7: Send callback with step_results
            if callback_url:
                await self._send_callback(callback_url, analysis_id, result, scan_id, step_results)

            # Update scan store
            scan_store[scan_id]["status"] = ScanStatus.COMPLETED
            scan_store[scan_id]["completed_at"] = datetime.now()
            logger.info(f"[{scan_id}] Pipeline completed: {result.total} findings")

        except Exception as e:
            logger.error(f"[{scan_id}] Pipeline failed: {e}")
            scan_store[scan_id]["status"] = ScanStatus.FAILED
            scan_store[scan_id]["error"] = str(e)
            scan_store[scan_id]["completed_at"] = datetime.now()

            # Send failure callback
            if callback_url:
                await self._send_failure_callback(callback_url, analysis_id, str(e), step_results)

    async def _send_status_callback(
        self, callback_url: str, analysis_id: str, status: str, scan_id: str
    ):
        """Send lightweight status update to callback URL (non-fatal on failure)"""
        payload = {"analysis_id": analysis_id, "status": status}
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                api_key = os.getenv("SCANNER_API_KEY", "")
                await client.post(
                    callback_url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": api_key,
                    },
                )
                logger.info(f"[{scan_id}] Status callback sent: {status}")
        except Exception as e:
            logger.warning(f"[{scan_id}] Status callback failed (non-fatal): {e}")

    async def _send_callback(
        self,
        callback_url: str,
        analysis_id: str,
        result: AggregatedResult,
        scan_id: str,
        step_results: Dict[str, StepResult],
    ):
        """Send scan results to the callback URL"""
        # Build static analysis report from SAST findings
        sast_findings = [f for f in result.findings if f.type == "sast"]
        dast_findings = [f for f in result.findings if f.type == "dast"]

        static_report = {
            "tool": "semgrep",
            "findings": [f.to_dict() for f in sast_findings],
            "total": len(sast_findings),
            "summary": result.sast_summary,
            "step_result": step_results["sast"].to_dict(),
        }

        pentest_report = {
            "tool": "nuclei",
            "findings": [f.to_dict() for f in dast_findings],
            "total": len(dast_findings),
            "summary": result.dast_summary,
            "step_result": step_results["dast"].to_dict(),
        }

        payload = {
            "analysis_id": analysis_id,
            "status": "COMPLETED",
            "static_analysis_report": static_report,
            "penetration_test_report": pentest_report,
            "vulnerabilities_found": result.total,
            "critical_count": result.critical_count,
            "high_count": result.high_count,
            "medium_count": result.medium_count,
            "low_count": result.low_count,
            "step_results": {k: v.to_dict() for k, v in step_results.items()},
        }

        logger.info(f"[{scan_id}] Sending callback to {callback_url}")
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                api_key = os.getenv("SCANNER_API_KEY", "")
                response = await client.post(
                    callback_url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": api_key,
                    },
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
        payload = {
            "analysis_id": analysis_id,
            "status": "FAILED",
            "error": error,
            "step_results": {k: v.to_dict() for k, v in step_results.items()},
        }
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                api_key = os.getenv("SCANNER_API_KEY", "")
                await client.post(
                    callback_url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": api_key,
                    },
                )
        except Exception as e:
            logger.error(f"Failed to send failure callback: {e}")
