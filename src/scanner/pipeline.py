"""Scan pipeline orchestrating SAST, DAST, aggregation, and callback"""

import asyncio
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

    async def _wait_for_target(
        self, target_url: str, scan_id: str, timeout: int = 120, interval: int = 3
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

                # Join target network BEFORE healthcheck so internal hostnames resolve
                network_connected = False
                if network_name:
                    network_connected = self.dast_scanner._connect_to_network(network_name)
                    if not network_connected:
                        step_results["dast"] = StepResult(
                            status="failed",
                            error=f"Failed to connect to Docker network '{network_name}'",
                        )
                        logger.error(f"[{scan_id}] DAST: cannot connect to network {network_name}")

                if not network_name or network_connected:
                    # Healthcheck: wait for target to become reachable
                    target_ready = await self._wait_for_target(target_url, scan_id)
                    if not target_ready:
                        step_results["dast"] = StepResult(
                            status="failed",
                            error="Target not reachable after 120s healthcheck timeout",
                        )
                        logger.error(f"[{scan_id}] DAST skipped: target not reachable")
                    else:
                        try:
                            # Pass network_name=None since we already connected
                            dast_findings = self.dast_scanner.run(target_url, network_name=None)

                            # Verify: if 0 findings, check target is still reachable
                            if len(dast_findings) == 0:
                                still_reachable = await self._wait_for_target(
                                    target_url, scan_id, timeout=10, interval=2
                                )
                                if not still_reachable:
                                    step_results["dast"] = StepResult(
                                        status="failed",
                                        error="Target became unreachable during scan",
                                    )
                                    logger.error(f"[{scan_id}] DAST: 0 findings and target unreachable")
                                else:
                                    step_results["dast"] = StepResult(
                                        status="success", findings_count=0
                                    )
                                    logger.info(f"[{scan_id}] DAST found 0 issues (target OK)")
                            else:
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

                # Disconnect from network after all DAST work
                if network_connected and network_name:
                    self.dast_scanner._disconnect_from_network(network_name)
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

            # Step 7: Exploit verification (if findings exist and target is available)
            exploit_session_id = None
            if target_url and result.total > 0:
                if callback_url:
                    await self._send_status_callback(
                        callback_url, analysis_id, "EXPLOIT_VERIFICATION", scan_id
                    )
                exploit_session_id = await self._call_exploit_agent(
                    scan_id, analysis_id, target_url, result, network_name
                )

            # Step 8: Send callback with step_results
            if callback_url:
                await self._send_callback(
                    callback_url, analysis_id, result, scan_id, step_results, exploit_session_id
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

    async def _call_exploit_agent(
        self,
        scan_id: str,
        analysis_id: str,
        target_url: str,
        result: AggregatedResult,
        network_name: Optional[str] = None,
    ) -> Optional[str]:
        """Call exploit-agent to start a penetration test session. Returns session_id or None."""
        exploit_agent_url = os.getenv("EXPLOIT_AGENT_URL")
        if not exploit_agent_url:
            logger.info(f"[{scan_id}] EXPLOIT_AGENT_URL not set, skipping exploit verification")
            return None

        # Translate findings to exploit-agent Vulnerability format
        vulnerabilities = []
        for f in result.findings:
            vuln = {
                "type": "rce",  # default, will be overridden by translator on agent side
                "location": f.url or f.file_path or "/",
                "method": "GET",
                "analysis_context": {
                    "source": f.type,
                    "tool": f.tool,
                    "severity": f.severity,
                    "cwe_id": f.cwe,
                    "title": f.title,
                    "matched_url": f.url,
                    "description": f.description,
                    "reference": f.reference,
                },
            }

            # Map CWE to vulnerability type
            cwe_mapping = {
                "CWE-89": "sql_injection",
                "CWE-79": "xss",
                "CWE-78": "command_injection",
                "CWE-77": "command_injection",
                "CWE-22": "path_traversal",
                "CWE-918": "ssrf",
                "CWE-287": "auth_bypass",
                "CWE-306": "auth_bypass",
                "CWE-502": "deserialization",
                "CWE-611": "xxe",
                "CWE-94": "rce",
                "CWE-96": "rce",
            }
            if f.cwe and f.cwe in cwe_mapping:
                vuln["type"] = cwe_mapping[f.cwe]

            vulnerabilities.append(vuln)

        if not vulnerabilities:
            return None

        payload = {
            "analysis_id": analysis_id,
            "target_url": target_url,
            "vulnerabilities": vulnerabilities,
            "max_attempts": 10,
        }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{exploit_agent_url}/api/sessions",
                    json=payload,
                )
                if response.status_code == 200:
                    data = response.json()
                    session_id = data.get("session_id")
                    logger.info(f"[{scan_id}] Exploit session started: {session_id}")
                    return session_id
                else:
                    logger.warning(
                        f"[{scan_id}] Exploit agent returned {response.status_code}: "
                        f"{response.text[:200]}"
                    )
        except Exception as e:
            logger.error(f"[{scan_id}] Failed to call exploit agent: {e}")

        return None

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

        has_failure = any(sr.status == "failed" for sr in step_results.values())
        final_status = "COMPLETED_WITH_ERRORS" if has_failure else "COMPLETED"

        payload = {
            "analysis_id": analysis_id,
            "status": final_status,
            "static_analysis_report": static_report,
            "penetration_test_report": pentest_report,
            "executive_summary": result.executive_summary,
            "exploit_session_id": exploit_session_id,
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
