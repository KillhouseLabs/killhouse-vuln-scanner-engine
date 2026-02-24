"""Tests for ScanPipeline status decision logic and log callback"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.scanner.pipeline import ScanPipeline, StepResult


class TestPipelineStatusDecision:
    """Tests for determining final pipeline status based on step results"""

    def _determine_status(self, step_results):
        """Replicate the status decision logic from _send_callback"""
        has_failure = any(sr.status == "failed" for sr in step_results.values())
        return "COMPLETED_WITH_ERRORS" if has_failure else "COMPLETED"

    def test_all_success_returns_completed(self):
        """All steps successful -> COMPLETED"""
        step_results = {
            "cloning": StepResult(status="success"),
            "sast": StepResult(status="success", findings_count=3),
            "building": StepResult(status="skipped"),
            "dast": StepResult(status="success", findings_count=5),
        }
        assert self._determine_status(step_results) == "COMPLETED"

    def test_dast_failed_returns_completed_with_errors(self):
        """DAST failed -> COMPLETED_WITH_ERRORS"""
        step_results = {
            "cloning": StepResult(status="success"),
            "sast": StepResult(status="success", findings_count=3),
            "building": StepResult(status="skipped"),
            "dast": StepResult(status="failed", error="nuclei timeout"),
        }
        assert self._determine_status(step_results) == "COMPLETED_WITH_ERRORS"

    def test_sast_failed_returns_completed_with_errors(self):
        """SAST failed -> COMPLETED_WITH_ERRORS"""
        step_results = {
            "cloning": StepResult(status="success"),
            "sast": StepResult(status="failed", error="semgrep not found"),
            "building": StepResult(status="skipped"),
            "dast": StepResult(status="success", findings_count=5),
        }
        assert self._determine_status(step_results) == "COMPLETED_WITH_ERRORS"

    def test_all_failed_returns_completed_with_errors(self):
        """All steps failed -> COMPLETED_WITH_ERRORS"""
        step_results = {
            "cloning": StepResult(status="failed", error="clone failed"),
            "sast": StepResult(status="failed", error="semgrep not found"),
            "building": StepResult(status="skipped"),
            "dast": StepResult(status="failed", error="nuclei timeout"),
        }
        assert self._determine_status(step_results) == "COMPLETED_WITH_ERRORS"

    def test_skipped_steps_not_treated_as_failure(self):
        """Skipped steps should not be treated as failures"""
        step_results = {
            "cloning": StepResult(status="success"),
            "sast": StepResult(status="success", findings_count=1),
            "building": StepResult(status="skipped"),
            "dast": StepResult(status="skipped", error="No target URL"),
        }
        assert self._determine_status(step_results) == "COMPLETED"


class TestSendLogCallback:
    """Tests for ScanPipeline._send_log_callback"""

    def setup_method(self):
        self.pipeline = ScanPipeline()

    @pytest.mark.asyncio
    @patch("src.scanner.pipeline.httpx.AsyncClient")
    async def test_sends_log_with_message_and_raw_output(self, mock_client_cls):
        """_send_log_callback() sends log_message and raw_output in payload"""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        await self.pipeline._send_log_callback(
            callback_url="http://web/api/analyses/webhook",
            analysis_id="analysis-123",
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
        """_send_log_callback() omits raw_output when None"""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        await self.pipeline._send_log_callback(
            callback_url="http://web/api/analyses/webhook",
            analysis_id="analysis-123",
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
        """_send_log_callback() truncates raw_output exceeding 50KB"""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        large_output = "x" * 60_000  # 60KB, exceeds 50KB limit

        await self.pipeline._send_log_callback(
            callback_url="http://web/api/analyses/webhook",
            analysis_id="analysis-123",
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
        """_send_log_callback() includes log_level field (default: info)"""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        await self.pipeline._send_log_callback(
            callback_url="http://web/api/analyses/webhook",
            analysis_id="analysis-123",
            scan_id="scan-456",
            log_message="Clone failed: auth error",
            log_level="error",
        )

        payload = mock_client.post.call_args.kwargs.get("json") or mock_client.post.call_args[
            1
        ].get("json")
        assert payload["log_level"] == "error"

    @pytest.mark.asyncio
    @patch("src.scanner.pipeline.httpx.AsyncClient")
    async def test_log_callback_failure_is_non_fatal(self, mock_client_cls):
        """_send_log_callback() does not raise on HTTP failure"""
        mock_client = AsyncMock()
        mock_client.post.side_effect = Exception("connection refused")
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        # Should not raise
        await self.pipeline._send_log_callback(
            callback_url="http://unreachable/webhook",
            analysis_id="analysis-123",
            scan_id="scan-456",
            log_message="test",
        )

    @pytest.mark.asyncio
    @patch("src.scanner.pipeline.httpx.AsyncClient")
    async def test_includes_api_key_header(self, mock_client_cls):
        """_send_log_callback() sends x-api-key header"""
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        await self.pipeline._send_log_callback(
            callback_url="http://web/api/analyses/webhook",
            analysis_id="analysis-123",
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
    @patch.object(ScanPipeline, "_send_log_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_send_status_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_send_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_wait_for_target", new_callable=AsyncMock)
    async def test_sends_clone_log_callback(
        self, mock_wait, mock_send_cb, mock_status_cb, mock_log_cb
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

        # Verify _send_log_callback was called with clone output
        log_calls = mock_log_cb.call_args_list
        clone_log_call = [
            c for c in log_calls if "cloned" in str(c).lower() or "clone" in str(c).lower()
        ]
        assert len(clone_log_call) >= 1

    @pytest.mark.asyncio
    @patch.object(ScanPipeline, "_send_log_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_send_status_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_send_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_wait_for_target", new_callable=AsyncMock)
    async def test_sends_sast_log_callback(
        self, mock_wait, mock_send_cb, mock_status_cb, mock_log_cb
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

        log_calls = mock_log_cb.call_args_list
        sast_log_call = [c for c in log_calls if "sast" in str(c).lower()]
        assert len(sast_log_call) >= 1

    @pytest.mark.asyncio
    @patch.object(ScanPipeline, "_send_log_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_send_status_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_send_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_wait_for_target", new_callable=AsyncMock)
    async def test_sends_dast_log_callback(
        self, mock_wait, mock_send_cb, mock_status_cb, mock_log_cb
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

        log_calls = mock_log_cb.call_args_list
        dast_log_call = [c for c in log_calls if "dast" in str(c).lower()]
        assert len(dast_log_call) >= 1

    @pytest.mark.asyncio
    @patch.object(ScanPipeline, "_send_log_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_send_status_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_send_callback", new_callable=AsyncMock)
    @patch.object(ScanPipeline, "_wait_for_target", new_callable=AsyncMock)
    async def test_sends_error_log_on_clone_failure(
        self, mock_wait, mock_send_cb, mock_status_cb, mock_log_cb
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

        log_calls = mock_log_cb.call_args_list
        error_calls = [c for c in log_calls if "error" in str(c).lower()]
        assert len(error_calls) >= 1
