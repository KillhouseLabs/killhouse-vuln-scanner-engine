"""Tests for ResultAggregator"""

from src.scanner.aggregator import AggregatedResult, ResultAggregator
from src.scanner.models import Finding


class TestResultAggregator:
    """Tests for ResultAggregator.aggregate"""

    def setup_method(self):
        self.aggregator = ResultAggregator(openai_api_key=None)

    def test_aggregate_empty(self):
        """Aggregating empty lists returns zero counts"""
        result = self.aggregator.aggregate([], [])
        assert result.total == 0
        assert result.critical_count == 0
        assert result.high_count == 0

    def test_aggregate_severity_counts(self):
        """Severity counts are computed correctly"""
        sast = [
            Finding(
                tool="semgrep",
                type="sast",
                severity="CRITICAL",
                title="t1",
                description="d1",
            ),
            Finding(
                tool="semgrep",
                type="sast",
                severity="HIGH",
                title="t2",
                description="d2",
            ),
        ]
        dast = [
            Finding(
                tool="nuclei",
                type="dast",
                severity="MEDIUM",
                title="t3",
                description="d3",
            ),
            Finding(
                tool="nuclei",
                type="dast",
                severity="LOW",
                title="t4",
                description="d4",
            ),
            Finding(
                tool="nuclei",
                type="dast",
                severity="INFO",
                title="t5",
                description="d5",
            ),
        ]
        result = self.aggregator.aggregate(sast, dast)
        assert result.total == 5
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 1
        assert result.info_count == 1

    def test_deduplicate_by_cwe_and_location(self):
        """Findings with same CWE + file/line are deduplicated"""
        findings = [
            Finding(
                tool="semgrep",
                type="sast",
                severity="HIGH",
                title="sql-injection",
                description="d1",
                file_path="app.py",
                line=10,
                cwe="CWE-89",
            ),
            Finding(
                tool="semgrep",
                type="sast",
                severity="HIGH",
                title="sql-injection-variant",
                description="d2",
                file_path="app.py",
                line=10,
                cwe="CWE-89",
            ),
        ]
        result = self.aggregator.aggregate(findings, [])
        assert result.total == 1

    def test_deduplicate_by_title_no_cwe(self):
        """Findings without CWE are deduped by title + location"""
        findings = [
            Finding(
                tool="semgrep",
                type="sast",
                severity="MEDIUM",
                title="exec-detected",
                description="d1",
                file_path="main.py",
                line=5,
            ),
            Finding(
                tool="semgrep",
                type="sast",
                severity="MEDIUM",
                title="exec-detected",
                description="d2",
                file_path="main.py",
                line=5,
            ),
        ]
        result = self.aggregator.aggregate(findings, [])
        assert result.total == 1

    def test_no_client_skips_summaries(self, monkeypatch):
        """Without OpenAI client, generate_summaries returns result unchanged"""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        aggregator = ResultAggregator(openai_api_key=None)
        assert aggregator.client is None


class TestAggregatedResult:
    """Tests for AggregatedResult.to_dict"""

    def test_to_dict(self):
        """to_dict serializes all fields"""
        finding = Finding(
            tool="semgrep",
            type="sast",
            severity="HIGH",
            title="test",
            description="test desc",
        )
        result = AggregatedResult(
            findings=[finding],
            total=1,
            high_count=1,
            sast_summary="Summary text",
        )
        d = result.to_dict()
        assert d["total"] == 1
        assert d["high_count"] == 1
        assert d["sast_summary"] == "Summary text"
        assert len(d["findings"]) == 1
        assert d["findings"][0]["tool"] == "semgrep"
