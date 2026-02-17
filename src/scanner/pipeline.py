"""Scan pipeline orchestrating SAST, DAST, aggregation, and callback"""

import logging
import os
from datetime import datetime
from typing import Optional

import httpx

from .aggregator import AggregatedResult, ResultAggregator
from .dast import NucleiScanner
from .sast import SemgrepScanner

logger = logging.getLogger(__name__)


class ScanPipeline:
    """Orchestrates the full scan pipeline"""

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
        """Execute full scan pipeline"""
        from pathlib import Path

        from src.api.schemas import ScanStatus

        logger.info(f"[{scan_id}] Starting pipeline for analysis {analysis_id}")
        scan_store[scan_id]["status"] = ScanStatus.SCANNING

        sast_findings = []
        dast_findings = []

        try:
            # Step 1: Clone / SAST scan
            if callback_url:
                await self._send_status_callback(callback_url, analysis_id, "CLONING", scan_id)

            if local_path:
                # Direct local path scan (no git clone needed)
                logger.info(f"[{scan_id}] Running SAST scan on local path {local_path}")
                try:
                    if callback_url:
                        await self._send_status_callback(
                            callback_url, analysis_id, "STATIC_ANALYSIS", scan_id
                        )
                    sast_findings = self.sast_scanner.run(Path(local_path))
                    logger.info(f"[{scan_id}] SAST found {len(sast_findings)} issues")
                except Exception as e:
                    logger.error(f"[{scan_id}] SAST local scan failed: {e}")
            elif repo_url:
                logger.info(f"[{scan_id}] Running SAST scan on {repo_url}")
                try:
                    if callback_url:
                        await self._send_status_callback(
                            callback_url, analysis_id, "STATIC_ANALYSIS", scan_id
                        )
                    sast_findings = self.sast_scanner.scan_repo(repo_url, branch)
                    logger.info(f"[{scan_id}] SAST found {len(sast_findings)} issues")
                except Exception as e:
                    logger.error(f"[{scan_id}] SAST scan failed: {e}")

            # Step 2: DAST scan (if target_url provided)
            if target_url:
                if callback_url:
                    await self._send_status_callback(
                        callback_url, analysis_id, "PENETRATION_TEST", scan_id
                    )
                logger.info(f"[{scan_id}] Running DAST scan on {target_url}")
                try:
                    dast_findings = self.dast_scanner.run(target_url)
                    logger.info(f"[{scan_id}] DAST found {len(dast_findings)} issues")
                except Exception as e:
                    logger.error(f"[{scan_id}] DAST scan failed: {e}")

            # Step 3: Aggregate results
            result = self.aggregator.aggregate(sast_findings, dast_findings)

            # Step 4: Generate AI summaries
            try:
                result = await self.aggregator.generate_summaries(result)
            except Exception as e:
                logger.error(f"[{scan_id}] AI summary generation failed: {e}")

            # Step 5: Send callback
            if callback_url:
                await self._send_callback(callback_url, analysis_id, result, scan_id)

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
                await self._send_failure_callback(callback_url, analysis_id, str(e))

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
        }

        pentest_report = {
            "tool": "nuclei",
            "findings": [f.to_dict() for f in dast_findings],
            "total": len(dast_findings),
            "summary": result.dast_summary,
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

    async def _send_failure_callback(self, callback_url: str, analysis_id: str, error: str):
        """Send failure notification to callback URL"""
        payload = {
            "analysis_id": analysis_id,
            "status": "FAILED",
            "error": error,
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
