"""Tests for executive summary prompt neutrality (Phase 1-B)"""

from unittest.mock import AsyncMock, MagicMock
import pytest
from src.scanner.aggregator import ResultAggregator, AggregatedResult


class TestExecutiveSummaryPrompt:
    """Test that _generate_executive uses neutral language"""

    @pytest.mark.asyncio
    async def test_executive_prompt_is_neutral(self):
        """_generate_executive should use neutral terms, not '경영진'"""

        # Arrange: Create aggregator with mock OpenAI client
        aggregator = ResultAggregator(openai_api_key="test-key")

        # Mock the OpenAI API response
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Mock summary"

        # Create AsyncMock for the create method
        aggregator.client.chat.completions.create = AsyncMock(return_value=mock_response)

        # Create test data
        result = AggregatedResult(
            total=5,
            critical_count=1,
            high_count=2,
            medium_count=1,
            low_count=1,
            sast_summary="SAST test summary",
            dast_summary="DAST test summary",
        )

        # Act: Call _generate_executive
        await aggregator._generate_executive(result)

        # Assert: Get the call arguments
        call_args = aggregator.client.chat.completions.create.call_args
        messages = call_args.kwargs["messages"]

        # Extract system message and user prompt
        system_message = messages[0]["content"]
        user_prompt = messages[1]["content"]

        # Verify NO occurrence of "경영진" in either message
        assert "경영진" not in system_message, "System message should not contain '경영진'"
        assert "경영진" not in user_prompt, "User prompt should not contain '경영진'"

        # Verify neutral terms are used
        assert "요약" in user_prompt, "User prompt should contain '요약'"
        assert "보안 스캔 요약" in user_prompt, "User prompt should contain '보안 스캔 요약'"
