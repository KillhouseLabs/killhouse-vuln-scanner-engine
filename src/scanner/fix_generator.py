"""OpenAI-based code fix suggestion generator"""

import json
import logging
import os
from typing import Optional

from openai import AsyncOpenAI

logger = logging.getLogger(__name__)


class FixGenerator:
    """Generates code fix suggestions using OpenAI"""

    def __init__(self, openai_api_key: Optional[str] = None):
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        self.client: Optional[AsyncOpenAI] = None
        if self.openai_api_key:
            self.client = AsyncOpenAI(api_key=self.openai_api_key)

    async def generate_fix(
        self,
        source_code: str,
        file_path: str,
        line: int,
        severity: str,
        rule: str,
        cwe: str,
        description: str,
    ) -> dict:
        """Generate a fix suggestion for vulnerable code.

        Args:
            source_code: The original source code containing the vulnerability
            file_path: Path to the file
            line: Line number of the vulnerability
            severity: Severity level (CRITICAL/HIGH/MEDIUM/LOW)
            rule: Rule or check name that detected the vulnerability
            cwe: CWE identifier
            description: Description of the vulnerability

        Returns:
            dict with 'explanation' and 'fixed_code' keys

        Raises:
            RuntimeError: If OpenAI client is not configured
        """
        if not self.client:
            raise RuntimeError("OpenAI API key is not configured")

        prompt = f"""당신은 보안 코드 리뷰 전문가입니다. 아래 소스코드에서 발견된 취약점을 수정해주세요.

## 취약점 정보
- 파일: {file_path}:{line}
- 심각도: {severity}
- 규칙: {rule}
- CWE: {cwe or "N/A"}
- 설명: {description}

## 원본 코드
```
{source_code}
```

## 지시사항
1. 취약점이 있는 부분만 최소한으로 수정하세요
2. 원본 코드의 스타일과 들여쓰기를 유지하세요
3. 수정하지 않는 줄은 그대로 유지하세요

다음 JSON 형식으로만 답변해주세요 (마크다운 코드 펜스 없이):
{{
  "explanation": "취약점에 대한 설명과 수정 이유 (한국어)",
  "fixed_code": "수정된 전체 코드 (원본과 동일한 줄 수를 유지)"
}}"""

        response = await self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "보안 전문가로서 취약점이 있는 코드를 수정합니다. JSON 형식으로만 응답합니다.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content
        parsed = json.loads(content)

        return {
            "explanation": parsed.get("explanation", ""),
            "fixed_code": parsed.get("fixed_code", ""),
        }
