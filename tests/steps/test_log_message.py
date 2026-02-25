"""Step definitions for pipeline log message feature."""

import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pytest_bdd import given, parsers, scenario, then, when

# Stub heavy dependencies that _send_status_callback doesn't need
for mod_name in ("openai", "docker", "podman"):
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()

from src.scanner.constants import LogLevel, PipelinePhase  # noqa: E402
from src.scanner.pipeline import ScanPipeline  # noqa: E402


@scenario(
    "../features/pipeline/log_message.feature",
    "CLONING 단계에서 로그 메시지를 전송한다",
)
def test_cloning_sends_log_message():
    pass


@scenario(
    "../features/pipeline/log_message.feature",
    "STATIC_ANALYSIS 완료 시 결과 로그를 전송한다",
)
def test_sast_result_log_message():
    pass


@scenario(
    "../features/pipeline/log_message.feature",
    "BUILDING 단계에서 로그 메시지를 전송한다",
)
def test_building_sends_log_message():
    pass


@scenario(
    "../features/pipeline/log_message.feature",
    "PENETRATION_TEST 완료 시 결과 로그를 전송한다",
)
def test_dast_result_log_message():
    pass


@scenario(
    "../features/pipeline/log_message.feature",
    "EXPLOIT_VERIFICATION 시작 시 로그를 전송한다",
)
def test_exploit_verification_sends_log_message():
    pass


@scenario(
    "../features/pipeline/log_message.feature",
    "단계 실패 시 에러 로그를 전송한다",
)
def test_step_failure_sends_error_log():
    pass


@pytest.fixture
def callback_context():
    return {
        "callback_url": "http://test-callback/api/analyses/webhook",
        "last_payload": None,
        "sast_findings_count": 0,
        "dast_findings_count": 0,
        "sast_error": None,
    }


def _run_async(coro):
    """Run async coroutine in sync context."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _call_and_capture(callback_url, status, log_message, log_level=None):
    """Call _send_status_callback with mocked httpx and return the payload."""
    pipeline = ScanPipeline.__new__(ScanPipeline)
    mock_client = AsyncMock()

    with patch("src.scanner.pipeline.httpx.AsyncClient") as mock_cls:
        mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        kwargs = {"log_message": log_message}
        if log_level is not None:
            kwargs["log_level"] = log_level

        await pipeline._send_status_callback(callback_url, "analysis-1", status, "scan-1", **kwargs)

    return mock_client.post.call_args.kwargs.get("json")


# --- Given ---


@given("콜백 URL이 설정되어 있다")
def callback_url_set(callback_context):
    assert callback_context["callback_url"] is not None


@given(parsers.parse("SAST 스캔이 {count:d}건을 발견했다"))
def sast_findings(callback_context, count):
    callback_context["sast_findings_count"] = count


@given(parsers.parse("DAST 스캔이 {count:d}건을 발견했다"))
def dast_findings(callback_context, count):
    callback_context["dast_findings_count"] = count


@given(parsers.parse('SAST 스캔이 "{error}" 에러로 실패했다'))
def sast_error(callback_context, error):
    callback_context["sast_error"] = error


# --- When ---


@when("파이프라인이 CLONING 상태 콜백을 전송한다")
def send_cloning_callback(callback_context):
    callback_context["last_payload"] = _run_async(
        _call_and_capture(
            callback_context["callback_url"],
            PipelinePhase.CLONING,
            log_message="Repository cloning started",
        )
    )


@when("파이프라인이 SAST 결과 콜백을 전송한다")
def send_sast_result_callback(callback_context):
    count = callback_context["sast_findings_count"]
    callback_context["last_payload"] = _run_async(
        _call_and_capture(
            callback_context["callback_url"],
            PipelinePhase.STATIC_ANALYSIS,
            log_message=f"SAST completed: {count} findings",
        )
    )


@when("파이프라인이 BUILDING 상태 콜백을 전송한다")
def send_building_callback(callback_context):
    callback_context["last_payload"] = _run_async(
        _call_and_capture(
            callback_context["callback_url"],
            PipelinePhase.BUILDING,
            log_message="Building sandbox environment",
        )
    )


@when("파이프라인이 DAST 결과 콜백을 전송한다")
def send_dast_result_callback(callback_context):
    count = callback_context["dast_findings_count"]
    callback_context["last_payload"] = _run_async(
        _call_and_capture(
            callback_context["callback_url"],
            PipelinePhase.PENETRATION_TEST,
            log_message=f"DAST completed: {count} findings",
        )
    )


@when("파이프라인이 EXPLOIT_VERIFICATION 상태 콜백을 전송한다")
def send_exploit_verification_callback(callback_context):
    callback_context["last_payload"] = _run_async(
        _call_and_capture(
            callback_context["callback_url"],
            PipelinePhase.EXPLOIT_VERIFICATION,
            log_message="Starting exploit verification",
        )
    )


@when("파이프라인이 SAST 에러 콜백을 전송한다")
def send_sast_error_callback(callback_context):
    error = callback_context["sast_error"]
    callback_context["last_payload"] = _run_async(
        _call_and_capture(
            callback_context["callback_url"],
            PipelinePhase.STATIC_ANALYSIS,
            log_message=f"SAST failed: {error}",
            log_level=LogLevel.ERROR,
        )
    )


# --- Then ---


@then(parsers.parse('웹훅 콜백에 status "{expected_status}"이 포함된다'))
def verify_status(callback_context, expected_status):
    payload = callback_context["last_payload"]
    assert payload is not None, "Payload was not captured"
    assert payload["status"] == expected_status


@then("웹훅 콜백에 log_message가 포함된다")
def verify_log_message_exists(callback_context):
    payload = callback_context["last_payload"]
    assert payload is not None, "Payload was not captured"
    assert "log_message" in payload
    assert payload["log_message"] is not None
    assert len(payload["log_message"]) > 0


@then(parsers.parse('웹훅 콜백에 log_message에 "{expected_text}"가 포함된다'))
def verify_log_message_content(callback_context, expected_text):
    payload = callback_context["last_payload"]
    assert payload is not None, "Payload was not captured"
    assert "log_message" in payload
    assert expected_text in payload["log_message"]


@then(parsers.parse('웹훅 콜백에 log_level "{expected_level}"가 포함된다'))
def verify_log_level(callback_context, expected_level):
    payload = callback_context["last_payload"]
    assert payload is not None, "Payload was not captured"
    assert "log_level" in payload
    assert payload["log_level"] == expected_level
