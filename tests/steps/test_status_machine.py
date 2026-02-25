"""Step definitions for pipeline status machine feature."""

import pytest
from pytest_bdd import given, parsers, scenario, then, when

from src.scanner.domain import FinalStatus, StepResult, StepStatus


@scenario(
    "../features/pipeline/status_machine.feature",
    "모든 스텝 성공 시 COMPLETED",
)
def test_all_success_completed():
    pass


@scenario(
    "../features/pipeline/status_machine.feature",
    "DAST 실패 시 COMPLETED_WITH_ERRORS",
)
def test_dast_failed_completed_with_errors():
    pass


@scenario(
    "../features/pipeline/status_machine.feature",
    "SAST 실패 시 COMPLETED_WITH_ERRORS",
)
def test_sast_failed_completed_with_errors():
    pass


@pytest.fixture
def context():
    return {
        "step_results": {
            "cloning": StepResult(status=StepStatus.SUCCESS),
            "sast": StepResult(),
            "building": StepResult(status=StepStatus.SKIPPED),
            "dast": StepResult(),
        }
    }


@given("SAST가 성공한다")
def sast_success(context):
    context["step_results"]["sast"] = StepResult(status=StepStatus.SUCCESS, findings_count=3)


@given("DAST가 성공한다")
def dast_success(context):
    context["step_results"]["dast"] = StepResult(status=StepStatus.SUCCESS, findings_count=5)


@given("SAST가 실패한다")
def sast_failed(context):
    context["step_results"]["sast"] = StepResult(
        status=StepStatus.FAILED, error="semgrep not found"
    )


@given("DAST가 실패한다")
def dast_failed(context):
    context["step_results"]["dast"] = StepResult(status=StepStatus.FAILED, error="nuclei timeout")


@when("파이프라인이 완료된다")
def pipeline_completes(context):
    context["final_status"] = FinalStatus.from_step_results(context["step_results"])


@then(parsers.parse('최종 상태는 "{expected_status}"이다'))
def verify_final_status(context, expected_status):
    assert context["final_status"] == expected_status
