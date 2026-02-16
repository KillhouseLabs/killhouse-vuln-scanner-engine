"""Tests for scanner Finding model"""

from src.scanner.models import Finding


class TestFinding:
    """Tests for Finding dataclass"""

    def test_create_sast_finding(self):
        """Finding can be created with SAST fields"""
        finding = Finding(
            tool="semgrep",
            type="sast",
            severity="HIGH",
            title="sql-injection",
            description="SQL injection detected",
            file_path="app.py",
            line=25,
            cwe="CWE-89",
        )
        assert finding.tool == "semgrep"
        assert finding.type == "sast"
        assert finding.severity == "HIGH"
        assert finding.file_path == "app.py"
        assert finding.line == 25
        assert finding.url is None

    def test_create_dast_finding(self):
        """Finding can be created with DAST fields"""
        finding = Finding(
            tool="nuclei",
            type="dast",
            severity="CRITICAL",
            title="log4j-rce",
            description="Log4j RCE vulnerability",
            url="http://target:8080/api",
            cwe="CWE-502",
        )
        assert finding.tool == "nuclei"
        assert finding.type == "dast"
        assert finding.url == "http://target:8080/api"
        assert finding.file_path is None

    def test_to_dict(self):
        """to_dict returns all fields as a dictionary"""
        finding = Finding(
            tool="semgrep",
            type="sast",
            severity="MEDIUM",
            title="exec-detected",
            description="Use of exec()",
            file_path="main.py",
            line=10,
        )
        d = finding.to_dict()
        assert isinstance(d, dict)
        assert d["tool"] == "semgrep"
        assert d["severity"] == "MEDIUM"
        assert d["file_path"] == "main.py"
        assert d["line"] == 10
        assert d["url"] is None
        assert d["cwe"] is None

    def test_normalize_severity_mapping(self):
        """normalize_severity maps known strings correctly"""
        assert Finding.normalize_severity("error") == "HIGH"
        assert Finding.normalize_severity("warning") == "MEDIUM"
        assert Finding.normalize_severity("info") == "INFO"
        assert Finding.normalize_severity("note") == "INFO"
        assert Finding.normalize_severity("critical") == "CRITICAL"
        assert Finding.normalize_severity("high") == "HIGH"
        assert Finding.normalize_severity("medium") == "MEDIUM"
        assert Finding.normalize_severity("low") == "LOW"

    def test_normalize_severity_unknown(self):
        """normalize_severity uppercases unknown values"""
        assert Finding.normalize_severity("unknown") == "UNKNOWN"
        assert Finding.normalize_severity("CRITICAL") == "CRITICAL"
