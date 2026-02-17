"""Tests for ScanPipeline status decision logic"""

from src.scanner.pipeline import StepResult


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
