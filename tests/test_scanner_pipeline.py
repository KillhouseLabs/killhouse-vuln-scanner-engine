"""Tests for ScanPipeline status decision logic and log callback"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.scanner.constants import FinalStatus, LogLevel, StepStatus
from src.scanner.pipeline import ScanPipeline, StepResult


class TestPipelineStatusDecision:
    """Tests for determining final pipeline status based on step results"""

    def _determine_status(self, step_results):
        """Replicate the status decision logic from _send_callback"""
        has_failure = any(sr.status == StepStatus.FAILED for sr in step_results.values())
        return FinalStatus.COMPLETED_WITH_ERRORS if has_failure else FinalStatus.COMPLETED

    def test_all_success_returns_completed(self):
        """All steps successful -> COMPLETED"""
        step_results = {
            "cloning": StepResult(status=StepStatus.SUCCESS),
            "sast": StepResult(status=StepStatus.SUCCESS, findings_count=3),
            "building": StepResult(status=StepStatus.SKIPPED),
            "dast": StepResult(status=StepStatus.SUCCESS, findings_count=5),
        }
        assert self._determine_status(step_results) == FinalStatus.COMPLETED

    def test_dast_failed_returns_completed_with_errors(self):
        """DAST failed -> COMPLETED_WITH_ERRORS"""
        step_results = {
            "cloning": StepResult(status=StepStatus.SUCCESS),
            "sast": StepResult(status=StepStatus.SUCCESS, findings_count=3),
            "building": StepResult(status=StepStatus.SKIPPED),
            "dast": StepResult(status=StepStatus.FAILED, error="nuclei timeout"),
        }
        assert self._determine_status(step_results) == FinalStatus.COMPLETED_WITH_ERRORS

    def test_sast_failed_returns_completed_with_errors(self):
        """SAST failed -> COMPLETED_WITH_ERRORS"""
        step_results = {
            "cloning": StepResult(status=StepStatus.SUCCESS),
            "sast": StepResult(status=StepStatus.FAILED, error="semgrep not found"),
            "building": StepResult(status=StepStatus.SKIPPED),
            "dast": StepResult(status=StepStatus.SUCCESS, findings_count=5),
        }
        assert self._determine_status(step_results) == FinalStatus.COMPLETED_WITH_ERRORS

    def test_all_failed_returns_completed_with_errors(self):
        """All steps failed -> COMPLETED_WITH_ERRORS"""
        step_results = {
            "cloning": StepResult(status=StepStatus.FAILED, error="clone failed"),
            "sast": StepResult(status=StepStatus.FAILED, error="semgrep not found"),
            "building": StepResult(status=StepStatus.SKIPPED),
            "dast": StepResult(status=StepStatus.FAILED, error="nuclei timeout"),
        }
        assert self._determine_status(step_results) == FinalStatus.COMPLETED_WITH_ERRORS

    def test_skipped_steps_not_treated_as_failure(self):
        """Skipped steps should not be treated as failures"""
        step_results = {
            "cloning": StepResult(status=StepStatus.SUCCESS),
            "sast": StepResult(status=StepStatus.SUCCESS, findings_count=1),
            "building": StepResult(status=StepStatus.SKIPPED),
            "dast": StepResult(status=StepStatus.SKIPPED, error="No target URL"),
        }
        assert self._determine_status(step_results) == FinalStatus.COMPLETED


class TestSendStatusCallback:
    """Tests for ScanPipeline._send_status_callback (unified status + log callback)"""

    def setup_method(self):
        self.pipeline = ScanPipeline()

    @pytest.mark.asyncio
    @patch("src.scanner.pipeline.httpx.AsyncClient")
    async def test_sends_log_with_message_and_raw_output(self, mock_client_cls):
        """_send_status_callback() sends log_message and raw_output in payload"""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        await self.pipeline._send_status_callback(
            callback_url="http://web/api/analyses/webhook",
            analysis_id="analysis-123",
            status="STATIC_ANALYSIS",
            scan_id="scan-456",
            log_message="SAST completed: 5 findings",
            raw_output="Running 500 rules...\nFinished in 2.5s\n",
        )

        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["analysis_id"] == "analysis-123"
        assert payload["log_message"] == "SAST completed: 5 findings"
        assert "Running 500 rules" in payload["raw_output"]

    @pytest.mark.asyncio
    @patch("src.scanner.pipeline.httpx.AsyncClient")
    async def test_sends_log_without_raw_output(self, mock_client_cls):
        """_send_status_callback() omits raw_output when None"""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        await self.pipeline._send_status_callback(
            callback_url="http://web/api/analyses/webhook",
            analysis_id="analysis-123",
            status="CLONING",
            scan_id="scan-456",
            log_message="Waiting for target...",
        )

        payload = mock_client.post.call_args.kwargs.get("json") or mock_client.post.call_args[
            1
        ].get("json")
        assert "raw_output" not in payload
        assert payload["log_message"] == "Waiting for target..."

    @pytest.mark.asyncio
    @patch("src.scanner.pipeline.httpx.AsyncClient")
    async def test_truncates_raw_output_over_50kb(self, mock_client_cls):
        """_send_status_callback() truncates raw_output exceeding 50KB"""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        large_output = "x" * 60_000  # 60KB, exceeds 50KB limit

        await self.pipeline._send_status_callback(
            callback_url="http://web/api/analyses/webhook",
            analysis_id="analysis-123",
            status="STATIC_ANALYSIS",
            scan_id="scan-456",
            log_message="Large output",
            raw_output=large_output,
        )

        payload = mock_client.post.call_args.kwargs.get("json") or mock_client.post.call_args[
            1
        ].get("json")
        assert len(payload["raw_output"]) < 60_000
        assert payload["raw_output"].endswith("... (truncated)")

    @pytest.mark.asyncio
    @patch("src.scanner.pipeline.httpx.AsyncClient")
    async def test_includes_log_level_in_payload(self, mock_client_cls):
        """_send_status_callback() includes log_level field (default: info)"""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        await self.pipeline._send_status_callback(
            callback_url="http://web/api/analyses/webhook",
            analysis_id="analysis-123",
            status="CLONING",
            scan_id="scan-456",
            log_message="Clone failed: auth error",
            log_level=LogLevel.ERROR,
        )

        payload = mock_client.post.call_args.kwargs.get("json") or mock_client.post.call_args[
            1
        ].get("json")
        assert payload["log_level"] == "error"

    @pytest.mark.asyncio
    @patch("src.scanner.pipeline.httpx.AsyncClient")
    async def test_callback_failure_is_non_fatal(self, mock_client_cls):
        """_send_status_callback() does not raise on HTTP failure"""
        mock_client = AsyncMock()
        mock_client.post.side_effect = Exception("connection refused")
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        # Should not raise
        await self.pipeline._send_status_callback(
            callback_url="http://unreachable/webhook",
            analysis_id="analysis-123",
            status="CLONING",
            scan_id="scan-456",
            log_message="test",
        )

    @pytest.mark.asyncio
    @patch("src.scanner.pipeline.httpx.AsyncClient")
    async def test_includes_api_key_header(self, mock_client_cls):
        """_send_status_callback() sends x-api-key header"""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        await self.pipeline._send_status_callback(
            callback_url="http://web/api/analyses/webhook",
            analysis_id="analysis-123",
            status="CLONING",
            scan_id="scan-456",
            log_message="test",
        )

        call_kwargs = mock_client.post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        assert "x-api-key" in headers


class TestPipelineSendsLogCallbacks:
    """Tests for pipeline.run() sending log callbacks at each step"""

    def setup_method(self):
        self.pipeline = ScanPipeline()

    @pytest.mark.asyncio
    @patch.object(ScanPipeline, "_send_status_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_send_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_wait_for_target", new_callable=AsyncMock)
    async def test_sends_clone_log_callback(
        self, mock_wait, mock_send_cb, mock_status_cb
    ):
        """Pipeline sends log callback with clone output after cloning"""
        clone_output = "Cloning into '/tmp/repo'...\nReceiving objects: 100%\n"
        self.pipeline.sast_scanner = MagicMock()
        self.pipeline.sast_scanner.clone_repo.return_value = (
            MagicMock(),  # Path
            clone_output,
        )
        self.pipeline.sast_scanner.run.return_value = ([], "")
        self.pipeline.dast_scanner = MagicMock()
        self.pipeline.aggregator = MagicMock()
        self.pipeline.aggregator.aggregate.return_value = MagicMock(
            total=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            findings=[],
            sast_summary=None,
            dast_summary=None,
            executive_summary=None,
        )
        self.pipeline.aggregator.generate_summaries = AsyncMock(
            return_value=self.pipeline.aggregator.aggregate.return_value
        )
        mock_wait.return_value = True

        scan_store = {"scan-1": {"status": None}}
        await self.pipeline.run(
            scan_id="scan-1",
            analysis_id="analysis-1",
            repo_url="https://github.com/test/repo.git",
            branch="main",
            target_url=None,
            callback_url="http://web/api/webhook",
            scan_store=scan_store,
        )

        # Verify _send_status_callback was called with clone-related log
        status_calls = mock_status_cb.call_args_list
        clone_log_call = [
            c for c in status_calls if "cloned" in str(c).lower() or "clone" in str(c).lower()
        ]
        assert len(clone_log_call) >= 1

    @pytest.mark.asyncio
    @patch.object(ScanPipeline, "_send_status_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_send_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_wait_for_target", new_callable=AsyncMock)
    async def test_sends_sast_log_callback(
        self, mock_wait, mock_send_cb, mock_status_cb
    ):
        """Pipeline sends log callback with SAST output after scanning"""
        sast_output = "Running 500 rules...\nFinished in 2.5s\n"
        self.pipeline.sast_scanner = MagicMock()
        self.pipeline.sast_scanner.clone_repo.return_value = (MagicMock(), "")
        self.pipeline.sast_scanner.run.return_value = ([], sast_output)
        self.pipeline.dast_scanner = MagicMock()
        self.pipeline.aggregator = MagicMock()
        self.pipeline.aggregator.aggregate.return_value = MagicMock(
            total=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            findings=[],
            sast_summary=None,
            dast_summary=None,
            executive_summary=None,
        )
        self.pipeline.aggregator.generate_summaries = AsyncMock(
            return_value=self.pipeline.aggregator.aggregate.return_value
        )

        scan_store = {"scan-1": {"status": None}}
        await self.pipeline.run(
            scan_id="scan-1",
            analysis_id="analysis-1",
            repo_url="https://github.com/test/repo.git",
            branch="main",
            target_url=None,
            callback_url="http://web/api/webhook",
            scan_store=scan_store,
        )

        status_calls = mock_status_cb.call_args_list
        sast_log_call = [c for c in status_calls if "sast" in str(c).lower()]
        assert len(sast_log_call) >= 1

    @pytest.mark.asyncio
    @patch.object(ScanPipeline, "_send_status_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_send_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_wait_for_target", new_callable=AsyncMock)
    async def test_sends_dast_log_callback(
        self, mock_wait, mock_send_cb, mock_status_cb
    ):
        """Pipeline sends log callback with DAST output after scanning"""
        dast_output = "[INF] Templates loaded: 500\n[INF] Found 2 results\n"
        self.pipeline.sast_scanner = MagicMock()
        self.pipeline.sast_scanner.clone_repo.return_value = (MagicMock(), "")
        self.pipeline.sast_scanner.run.return_value = ([], "")
        self.pipeline.dast_scanner = MagicMock()
        self.pipeline.dast_scanner.run.return_value = ([], dast_output)
        self.pipeline.dast_scanner._connect_to_network.return_value = False
        self.pipeline.aggregator = MagicMock()
        self.pipeline.aggregator.aggregate.return_value = MagicMock(
            total=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            findings=[],
            sast_summary=None,
            dast_summary=None,
            executive_summary=None,
        )
        self.pipeline.aggregator.generate_summaries = AsyncMock(
            return_value=self.pipeline.aggregator.aggregate.return_value
        )
        mock_wait.return_value = True

        scan_store = {"scan-1": {"status": None}}
        await self.pipeline.run(
            scan_id="scan-1",
            analysis_id="analysis-1",
            repo_url="https://github.com/test/repo.git",
            branch="main",
            target_url="http://target:8080",
            callback_url="http://web/api/webhook",
            scan_store=scan_store,
        )

        status_calls = mock_status_cb.call_args_list
        dast_log_call = [c for c in status_calls if "dast" in str(c).lower()]
        assert len(dast_log_call) >= 1

    @pytest.mark.asyncio
    @patch.object(ScanPipeline, "_send_status_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_send_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_wait_for_target", new_callable=AsyncMock)
    async def test_sends_error_log_on_clone_failure(
        self, mock_wait, mock_send_cb, mock_status_cb
    ):
        """Pipeline sends error log callback when clone fails"""
        self.pipeline.sast_scanner = MagicMock()
        self.pipeline.sast_scanner.clone_repo.side_effect = RuntimeError("auth failed")
        self.pipeline.dast_scanner = MagicMock()
        self.pipeline.aggregator = MagicMock()
        self.pipeline.aggregator.aggregate.return_value = MagicMock(
            total=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            findings=[],
            sast_summary=None,
            dast_summary=None,
            executive_summary=None,
        )
        self.pipeline.aggregator.generate_summaries = AsyncMock(
            return_value=self.pipeline.aggregator.aggregate.return_value
        )

        scan_store = {"scan-1": {"status": None}}
        await self.pipeline.run(
            scan_id="scan-1",
            analysis_id="analysis-1",
            repo_url="https://github.com/test/repo.git",
            branch="main",
            target_url=None,
            callback_url="http://web/api/webhook",
            scan_store=scan_store,
        )

        status_calls = mock_status_cb.call_args_list
        error_calls = [c for c in status_calls if "error" in str(c).lower()]
        assert len(error_calls) >= 1


class TestSendCallbackReportExclusion:
    """Tests for _send_callback excluding skipped step reports from payload"""

    def setup_method(self):
        self.pipeline = ScanPipeline()

    @pytest.mark.asyncio
    @patch("src.scanner.pipeline.httpx.AsyncClient")
    async def test_sast_only_scan_excludes_dast_report(self, mock_client_cls):
        """When DAST step is skipped, penetration_test_report should NOT be in payload"""
        from src.scanner.aggregator import AggregatedResult
        from src.scanner.models import Finding

        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        # Build test data: SAST ran (success), DAST skipped
        step_results = {
            "cloning": StepResult(status=StepStatus.SUCCESS),
            "sast": StepResult(status=StepStatus.SUCCESS, findings_count=2),
            "building": StepResult(status=StepStatus.SKIPPED),
            "dast": StepResult(status=StepStatus.SKIPPED, error="No target URL provided"),
        }

        sast_finding = Finding(
            tool="semgrep",
            type="sast",
            severity="HIGH",
            title="SQL Injection",
            description="Potential SQL injection vulnerability",
            file_path="/app/user.py",
            line=42,
            cwe="CWE-89",
        )

        result = AggregatedResult(
            findings=[sast_finding],
            total=1,
            critical_count=0,
            high_count=1,
            medium_count=0,
            low_count=0,
            info_count=0,
            sast_summary="SAST found SQL injection",
            dast_summary=None,
            executive_summary="Security issues detected",
        )

        await self.pipeline._send_callback(
            callback_url="http://web/api/analyses/webhook",
            analysis_id="analysis-123",
            result=result,
            scan_id="scan-456",
            step_results=step_results,
        )

        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")

        # Assert: SAST report included, DAST report excluded
        assert "static_analysis_report" in payload
        assert "penetration_test_report" not in payload
        assert payload["static_analysis_report"]["total"] == 1
        assert payload["static_analysis_report"]["step_result"]["status"] == "success"

    @pytest.mark.asyncio
    @patch("src.scanner.pipeline.httpx.AsyncClient")
    async def test_dast_only_scan_excludes_sast_report(self, mock_client_cls):
        """When SAST step is skipped, static_analysis_report should NOT be in payload"""
        from src.scanner.aggregator import AggregatedResult
        from src.scanner.models import Finding

        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        # Build test data: SAST skipped, DAST ran (success)
        step_results = {
            "cloning": StepResult(status=StepStatus.SKIPPED),
            "sast": StepResult(status=StepStatus.SKIPPED, error="Clone was skipped or failed"),
            "building": StepResult(status=StepStatus.SKIPPED),
            "dast": StepResult(status=StepStatus.SUCCESS, findings_count=3),
        }

        dast_finding = Finding(
            tool="nuclei",
            type="dast",
            severity="CRITICAL",
            title="XSS Vulnerability",
            description="Reflected XSS detected",
            url="http://target:8080/search?q=<script>",
            cwe="CWE-79",
        )

        result = AggregatedResult(
            findings=[dast_finding],
            total=1,
            critical_count=1,
            high_count=0,
            medium_count=0,
            low_count=0,
            info_count=0,
            sast_summary=None,
            dast_summary="DAST found XSS",
            executive_summary="Critical issues detected",
        )

        await self.pipeline._send_callback(
            callback_url="http://web/api/analyses/webhook",
            analysis_id="analysis-456",
            result=result,
            scan_id="scan-789",
            step_results=step_results,
        )

        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")

        # Assert: DAST report included, SAST report excluded
        assert "penetration_test_report" in payload
        assert "static_analysis_report" not in payload
        assert payload["penetration_test_report"]["total"] == 1
        assert payload["penetration_test_report"]["step_result"]["status"] == "success"

    @pytest.mark.asyncio
    @patch("src.scanner.pipeline.httpx.AsyncClient")
    async def test_both_steps_ran_includes_both_reports(self, mock_client_cls):
        """When both steps ran, both reports should be in payload"""
        from src.scanner.aggregator import AggregatedResult
        from src.scanner.models import Finding

        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        # Build test data: Both SAST and DAST ran successfully
        step_results = {
            "cloning": StepResult(status=StepStatus.SUCCESS),
            "sast": StepResult(status=StepStatus.SUCCESS, findings_count=2),
            "building": StepResult(status=StepStatus.SKIPPED),
            "dast": StepResult(status=StepStatus.SUCCESS, findings_count=1),
        }

        sast_finding = Finding(
            tool="semgrep",
            type="sast",
            severity="HIGH",
            title="SQL Injection",
            description="SQL injection",
            file_path="/app/user.py",
            line=42,
        )

        dast_finding = Finding(
            tool="nuclei",
            type="dast",
            severity="MEDIUM",
            title="Open Redirect",
            description="Open redirect",
            url="http://target:8080/redirect",
        )

        result = AggregatedResult(
            findings=[sast_finding, dast_finding],
            total=2,
            critical_count=0,
            high_count=1,
            medium_count=1,
            low_count=0,
            info_count=0,
            sast_summary="SAST summary",
            dast_summary="DAST summary",
            executive_summary="Both scans completed",
        )

        await self.pipeline._send_callback(
            callback_url="http://web/api/analyses/webhook",
            analysis_id="analysis-789",
            result=result,
            scan_id="scan-101",
            step_results=step_results,
        )

        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")

        # Assert: Both reports included
        assert "static_analysis_report" in payload
        assert "penetration_test_report" in payload
        assert payload["static_analysis_report"]["total"] == 1
        assert payload["penetration_test_report"]["total"] == 1
        assert payload["static_analysis_report"]["step_result"]["status"] == "success"
        assert payload["penetration_test_report"]["step_result"]["status"] == "success"
