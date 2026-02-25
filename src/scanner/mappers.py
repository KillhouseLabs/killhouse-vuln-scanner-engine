"""Anti-corruption layer: translates scanner domain models to external API formats."""

from __future__ import annotations

from typing import Dict, List, Optional

from .aggregator import AggregatedResult
from .domain import FinalStatus, StepKey, StepResult
from .domain.cwe import classify_exploit_type
from .domain.log import DEFAULT_RAW_OUTPUT_MAX_LENGTH, LogMessage
from .models import Finding

# ── LogMessage → Webhook ───────────────────────────────────────────


def log_to_webhook_payload(
    log: LogMessage,
    max_length: int = DEFAULT_RAW_OUTPUT_MAX_LENGTH,
) -> dict:
    """Translate LogMessage VO to webhook callback payload format."""
    payload: dict = {
        "log_message": log.message,
        "log_level": log.level,
    }
    truncated = log.truncated_raw_output(max_length)
    if truncated:
        payload["raw_output"] = truncated
    return payload


# ── Finding → Exploit Agent Vulnerability ──────────────────────────


def finding_to_exploit_vulnerability(finding: Finding) -> dict:
    """Translate a scanner Finding into exploit-agent Vulnerability format."""
    return {
        "type": classify_exploit_type(finding.cwe),
        "location": finding.url or finding.file_path or "/",
        "method": "GET",
        "analysis_context": {
            "source": finding.type,
            "tool": finding.tool,
            "severity": finding.severity,
            "cwe_id": finding.cwe,
            "title": finding.title,
            "matched_url": finding.url,
            "description": finding.description,
            "reference": finding.reference,
        },
    }


def findings_to_exploit_vulnerabilities(findings: List[Finding]) -> List[dict]:
    """Translate a list of Findings for the exploit-agent API."""
    return [finding_to_exploit_vulnerability(f) for f in findings]


# ── Scan Result → Webhook Payload ──────────────────────────────────


def build_result_payload(
    analysis_id: str,
    result: AggregatedResult,
    step_results: Dict[str, StepResult],
    exploit_session_id: Optional[str] = None,
) -> dict:
    """Build the webhook payload for successful scan completion."""
    sast_findings = [f for f in result.findings if f.type == "sast"]
    dast_findings = [f for f in result.findings if f.type == "dast"]

    static_report = {
        "tool": "semgrep",
        "findings": [f.to_dict() for f in sast_findings],
        "total": len(sast_findings),
        "summary": result.sast_summary,
        "step_result": step_results[StepKey.SAST].to_dict(),
    }

    pentest_report = {
        "tool": "nuclei",
        "findings": [f.to_dict() for f in dast_findings],
        "total": len(dast_findings),
        "summary": result.dast_summary,
        "step_result": step_results[StepKey.DAST].to_dict(),
    }

    final_status = FinalStatus.from_step_results(step_results)

    payload = {
        "analysis_id": analysis_id,
        "status": final_status,
        "executive_summary": result.executive_summary,
        "exploit_session_id": exploit_session_id,
        "vulnerabilities_found": result.total,
        "critical_count": result.critical_count,
        "high_count": result.high_count,
        "medium_count": result.medium_count,
        "low_count": result.low_count,
        "info_count": result.info_count,
        "step_results": {k: v.to_dict() for k, v in step_results.items()},
    }

    if not step_results[StepKey.SAST].is_skipped:
        payload["static_analysis_report"] = static_report
    if not step_results[StepKey.DAST].is_skipped:
        payload["penetration_test_report"] = pentest_report

    return payload


def build_failure_payload(
    analysis_id: str,
    error: str,
    step_results: Dict[str, StepResult],
) -> dict:
    """Build the webhook payload for pipeline failure."""
    return {
        "analysis_id": analysis_id,
        "status": FinalStatus.FAILED,
        "error": error,
        "step_results": {k: v.to_dict() for k, v in step_results.items()},
    }
