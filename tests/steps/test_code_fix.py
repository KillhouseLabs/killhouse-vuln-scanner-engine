"""BDD step definitions for code fix suggestion feature"""

import json
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from pytest_bdd import given, parsers, scenario, then, when

from src.api.app import app

# --- Scenarios ---


@scenario("../features/fix/code_fix.feature", "소스코드와 취약점 정보로 수정 코드 생성")
def test_generate_fix_from_source():
    pass


@scenario("../features/fix/code_fix.feature", "OpenAI API 키가 없을 때")
def test_fix_without_api_key():
    pass


# --- Context ---


class FixContext:
    def __init__(self):
        self.client = TestClient(app)
        self.payload = {}
        self.response = None
        self.mock_patcher = None


import pytest


@pytest.fixture
def fix_context():
    return FixContext()


# --- Given ---


@given("취약점이 있는 소스코드가 있다", target_fixture="fix_context")
def vulnerable_source_code(fix_context):
    fix_context.payload["source_code"] = (
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    )
    fix_context.payload["file_path"] = "app/db.py"
    fix_context.payload["line"] = 25
    fix_context.payload["severity"] = "HIGH"
    return fix_context


@given("SAST 취약점 정보가 있다")
def sast_vulnerability_info(fix_context):
    fix_context.payload["rule"] = "python.flask.security.injection.sql-injection"
    fix_context.payload["cwe"] = "CWE-89"
    fix_context.payload["description"] = "SQL injection detected in query construction."


@given("OpenAI API 키가 설정되지 않았다", target_fixture="fix_context")
def no_api_key(fix_context):
    fix_context.payload = {
        "source_code": "code",
        "file_path": "test.py",
        "line": 1,
        "severity": "LOW",
    }
    return fix_context


# --- When ---


@when("코드 수정 제안을 요청한다")
def request_fix_suggestion(fix_context):
    if fix_context.payload.get("severity") == "LOW" and "rule" not in fix_context.payload:
        # No API key scenario
        with patch("src.api.routes.FixGenerator") as MockGenerator:
            mock_instance = MockGenerator.return_value
            mock_instance.generate_fix = AsyncMock(
                side_effect=RuntimeError("OpenAI API key is not configured")
            )
            fix_context.response = fix_context.client.post(
                "/api/fix-suggestion", json=fix_context.payload
            )
    else:
        # Success scenario
        with patch("src.api.routes.FixGenerator") as MockGenerator:
            mock_instance = MockGenerator.return_value
            mock_instance.generate_fix = AsyncMock(
                return_value={
                    "explanation": "SQL 인젝션 취약점을 파라미터화된 쿼리로 수정했습니다.",
                    "fixed_code": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                }
            )
            fix_context.response = fix_context.client.post(
                "/api/fix-suggestion", json=fix_context.payload
            )


# --- Then ---


@then("수정된 코드와 설명이 반환된다")
def fix_returned(fix_context):
    assert fix_context.response.status_code == 200
    data = fix_context.response.json()
    assert "explanation" in data
    assert "fixed_code" in data
    assert len(data["explanation"]) > 0
    assert len(data["fixed_code"]) > 0


@then("503 에러가 반환된다")
def service_unavailable_error(fix_context):
    assert fix_context.response.status_code == 503
