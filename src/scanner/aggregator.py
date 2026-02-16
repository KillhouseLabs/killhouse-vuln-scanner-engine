"""Result aggregation and AI summary generation for scan findings"""

import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

from openai import AsyncOpenAI

from .models import Finding

logger = logging.getLogger(__name__)


@dataclass
class AggregatedResult:
    """Aggregated scan results from all scanners"""

    findings: List[Finding] = field(default_factory=list)
    total: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    sast_summary: Optional[str] = None
    dast_summary: Optional[str] = None
    executive_summary: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "total": self.total,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "sast_summary": self.sast_summary,
            "dast_summary": self.dast_summary,
            "executive_summary": self.executive_summary,
        }


class ResultAggregator:
    """Aggregates SAST + DAST findings and generates AI summaries"""

    def __init__(self, openai_api_key: Optional[str] = None):
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        self.client: Optional[AsyncOpenAI] = None
        if self.openai_api_key:
            self.client = AsyncOpenAI(api_key=self.openai_api_key)

    def aggregate(
        self,
        sast_findings: List[Finding],
        dast_findings: List[Finding],
    ) -> AggregatedResult:
        """Merge SAST and DAST findings, deduplicate, count severities"""
        merged = self._deduplicate(sast_findings + dast_findings)

        result = AggregatedResult(findings=merged, total=len(merged))
        for f in merged:
            sev = f.severity.upper()
            if sev == "CRITICAL":
                result.critical_count += 1
            elif sev == "HIGH":
                result.high_count += 1
            elif sev == "MEDIUM":
                result.medium_count += 1
            elif sev == "LOW":
                result.low_count += 1
            else:
                result.info_count += 1

        logger.info(
            f"Aggregated {result.total} findings: "
            f"C={result.critical_count} H={result.high_count} "
            f"M={result.medium_count} L={result.low_count}"
        )
        return result

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings based on CWE + location"""
        seen = set()
        unique = []
        for f in findings:
            # Build a dedup key: same CWE in same file/line or same URL
            key = (
                ((f.cwe, f.file_path, f.line) if f.type == "sast" else (f.cwe, f.url))
                if f.cwe
                else ((f.title, f.file_path, f.line) if f.type == "sast" else (f.title, f.url))
            )

            if key not in seen:
                seen.add(key)
                unique.append(f)

        dedup_count = len(findings) - len(unique)
        if dedup_count > 0:
            logger.info(f"Deduplicated {dedup_count} findings")
        return unique

    async def generate_summaries(self, result: AggregatedResult) -> AggregatedResult:
        """Generate AI summaries for the aggregated results"""
        if not self.client:
            logger.warning("OpenAI client not configured, skipping AI summaries")
            return result

        sast_findings = [f for f in result.findings if f.type == "sast"]
        dast_findings = [f for f in result.findings if f.type == "dast"]

        if sast_findings:
            result.sast_summary = await self._summarize_findings(sast_findings, "SAST (정적 분석)")

        if dast_findings:
            result.dast_summary = await self._summarize_findings(dast_findings, "DAST (동적 분석)")

        result.executive_summary = await self._generate_executive(result)
        return result

    async def _summarize_findings(self, findings: List[Finding], scan_type: str) -> str:
        """Generate a summary for a set of findings"""
        # Prepare findings text (limit to top 20 for token efficiency)
        findings_text = ""
        for i, f in enumerate(findings[:20]):
            findings_text += f"\n{i + 1}. [{f.severity}] {f.title}\n   {f.description[:200]}\n"
            if f.file_path:
                findings_text += f"   File: {f.file_path}:{f.line}\n"
            if f.url:
                findings_text += f"   URL: {f.url}\n"

        prompt = f"""다음은 {scan_type} 스캔 결과입니다. 3-5문장으로 요약해주세요.
총 {len(findings)}개 발견사항 중 상위 {min(len(findings), 20)}개:
{findings_text}

요약에 포함할 내용:
1. 전체적인 보안 상태 평가
2. 가장 심각한 발견사항
3. 주요 권장 조치"""

        try:
            response = await self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "보안 전문가로서 취약점 스캔 결과를 한국어로 간결하게 요약합니다.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                max_tokens=500,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"AI summary failed for {scan_type}: {e}")
            return None

    async def _generate_executive(self, result: AggregatedResult) -> str:
        """Generate executive summary"""
        prompt = f"""보안 스캔 경영진 요약을 작성해주세요.

스캔 결과:
- 총 발견사항: {result.total}개
- Critical: {result.critical_count}개
- High: {result.high_count}개
- Medium: {result.medium_count}개
- Low: {result.low_count}개

SAST 요약: {result.sast_summary or "해당 없음"}
DAST 요약: {result.dast_summary or "해당 없음"}

경영진 요약에 포함할 내용:
1. 전반적인 보안 위험 수준 (상/중/하)
2. 즉시 조치가 필요한 사항
3. 단기/중기 보안 개선 권고"""

        try:
            response = await self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "보안 CISO로서 경영진에게 보안 스캔 결과를 보고합니다. 한국어로 작성하며, 비기술적 용어를 사용합니다.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                max_tokens=800,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            return None
