"""Tests for FixGenerator module"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.scanner.fix_generator import FixGenerator


class TestFixGenerator:
    """Unit tests for FixGenerator"""

    def setup_method(self):
        self.generator = FixGenerator(openai_api_key="test-key")

    @pytest.mark.asyncio
    async def test_generate_fix_returns_explanation_and_fixed_code(self):
        """OpenAI 응답에서 explanation과 fixed_code를 올바르게 파싱한다"""
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(
                message=MagicMock(
                    content=json.dumps(
                        {
                            "explanation": "SQL 인젝션 취약점입니다.",
                            "fixed_code": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                        }
                    )
                )
            )
        ]

        with patch.object(
            self.generator.client.chat.completions,
            "create",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            result = await self.generator.generate_fix(
                source_code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                file_path="app/db.py",
                line=25,
                severity="HIGH",
                rule="python.flask.security.injection.sql-injection",
                cwe="CWE-89",
                description="SQL injection detected",
            )

        assert result["explanation"] == "SQL 인젝션 취약점입니다."
        assert "?" in result["fixed_code"]

    @pytest.mark.asyncio
    async def test_generate_fix_calls_openai_with_correct_model(self):
        """OpenAI를 gpt-4o-mini 모델과 json_object 형식으로 호출한다"""
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(
                message=MagicMock(
                    content=json.dumps(
                        {"explanation": "fix applied", "fixed_code": "safe_code()"}
                    )
                )
            )
        ]

        mock_create = AsyncMock(return_value=mock_response)

        with patch.object(
            self.generator.client.chat.completions,
            "create",
            mock_create,
        ):
            await self.generator.generate_fix(
                source_code="unsafe()",
                file_path="test.py",
                line=1,
                severity="MEDIUM",
                rule="test-rule",
                cwe="",
                description="test",
            )

        mock_create.assert_called_once()
        call_kwargs = mock_create.call_args.kwargs
        assert call_kwargs["model"] == "gpt-4o-mini"
        assert call_kwargs["response_format"] == {"type": "json_object"}

    @pytest.mark.asyncio
    async def test_generate_fix_without_api_key_raises_error(self):
        """API 키가 없으면 RuntimeError를 발생시킨다"""
        generator = FixGenerator(openai_api_key=None)
        # Ensure env fallback is also None
        with patch.dict("os.environ", {}, clear=True):
            generator_no_key = FixGenerator(openai_api_key=None)

        with pytest.raises(RuntimeError, match="not configured"):
            await generator_no_key.generate_fix(
                source_code="code",
                file_path="test.py",
                line=1,
                severity="LOW",
                rule="",
                cwe="",
                description="",
            )

    @pytest.mark.asyncio
    async def test_generate_fix_handles_missing_fields(self):
        """OpenAI 응답에 필드가 누락되어도 빈 문자열로 처리한다"""
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(message=MagicMock(content=json.dumps({})))
        ]

        with patch.object(
            self.generator.client.chat.completions,
            "create",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            result = await self.generator.generate_fix(
                source_code="code",
                file_path="test.py",
                line=1,
                severity="LOW",
                rule="",
                cwe="",
                description="",
            )

        assert result["explanation"] == ""
        assert result["fixed_code"] == ""


class TestFixSuggestionAPI:
    """Tests for POST /api/fix-suggestion endpoint"""

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient

        from src.api.app import app

        return TestClient(app)

    @patch("src.api.routes.FixGenerator")
    def test_fix_suggestion_success(self, MockGenerator, client):
        """POST /api/fix-suggestion returns explanation and fixed_code"""
        mock_instance = MockGenerator.return_value
        mock_instance.generate_fix = AsyncMock(
            return_value={
                "explanation": "취약점 수정됨",
                "fixed_code": "safe_code()",
            }
        )

        payload = {
            "source_code": "unsafe_code()",
            "file_path": "app.py",
            "line": 10,
            "severity": "HIGH",
            "rule": "test-rule",
            "cwe": "CWE-79",
            "description": "XSS detected",
        }

        response = client.post("/api/fix-suggestion", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["explanation"] == "취약점 수정됨"
        assert data["fixed_code"] == "safe_code()"

    @patch("src.api.routes.FixGenerator")
    def test_fix_suggestion_no_api_key(self, MockGenerator, client):
        """POST /api/fix-suggestion returns 503 when API key is missing"""
        mock_instance = MockGenerator.return_value
        mock_instance.generate_fix = AsyncMock(
            side_effect=RuntimeError("OpenAI API key is not configured")
        )

        payload = {
            "source_code": "code",
            "file_path": "test.py",
            "line": 1,
            "severity": "LOW",
        }

        response = client.post("/api/fix-suggestion", json=payload)
        assert response.status_code == 503

    def test_fix_suggestion_missing_required_fields(self, client):
        """POST /api/fix-suggestion returns 422 without required fields"""
        payload = {"source_code": "code"}
        response = client.post("/api/fix-suggestion", json=payload)
        assert response.status_code == 422
