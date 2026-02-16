"""Tests for SemgrepScanner (SAST)"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.scanner.sast import SemgrepScanner


class TestSemgrepParseOutput:
    """Tests for SemgrepScanner._parse_output"""

    def setup_method(self):
        self.scanner = SemgrepScanner(timeout=60)

    def test_parse_valid_output(self, sample_semgrep_output):
        """Parses valid Semgrep JSON into Finding objects"""
        findings = self.scanner._parse_output(sample_semgrep_output, Path("/tmp/scan"))
        assert len(findings) == 2

        f0 = findings[0]
        assert f0.tool == "semgrep"
        assert f0.type == "sast"
        assert f0.severity == "MEDIUM"  # "WARNING" -> "MEDIUM"
        assert f0.title == "python.lang.security.audit.exec-detected"
        assert f0.line == 10
        assert "CWE-95" in f0.cwe

        f1 = findings[1]
        assert f1.severity == "HIGH"  # "ERROR" -> "HIGH"
        assert "CWE-89" in f1.cwe

    def test_parse_empty_output(self):
        """Returns empty list for empty input"""
        assert self.scanner._parse_output("", Path("/tmp")) == []
        assert self.scanner._parse_output("  ", Path("/tmp")) == []

    def test_parse_invalid_json(self):
        """Returns empty list for invalid JSON"""
        assert self.scanner._parse_output("not json", Path("/tmp")) == []

    def test_parse_no_results(self):
        """Returns empty list when results array is empty"""
        data = json.dumps({"results": [], "errors": []})
        assert self.scanner._parse_output(data, Path("/tmp")) == []

    def test_parse_relative_path(self, sample_semgrep_output):
        """File paths are made relative to repo path"""
        findings = self.scanner._parse_output(sample_semgrep_output, Path("/tmp/scan"))
        assert findings[0].file_path == "app.py"
        assert findings[1].file_path == "db.py"


class TestSemgrepRun:
    """Tests for SemgrepScanner.run with subprocess mocking"""

    def setup_method(self):
        self.scanner = SemgrepScanner(timeout=60)

    @patch("src.scanner.sast.subprocess.run")
    @patch("src.scanner.sast.shutil.copytree")
    @patch("src.scanner.sast.shutil.rmtree")
    @patch("src.scanner.sast.tempfile.mkdtemp")
    def test_run_success(self, mock_mkdtemp, mock_rmtree, mock_copytree, mock_run):
        """run() invokes semgrep and parses output"""
        mock_mkdtemp.return_value = "/tmp/killhouse-scan-test"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"results": [], "errors": []}),
            stderr="",
        )

        findings = self.scanner.run(Path("/tmp/repo"))
        assert findings == []
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "semgrep"

    @patch("src.scanner.sast.subprocess.run")
    @patch("src.scanner.sast.shutil.copytree")
    @patch("src.scanner.sast.shutil.rmtree")
    @patch("src.scanner.sast.tempfile.mkdtemp")
    def test_run_timeout(self, mock_mkdtemp, mock_rmtree, mock_copytree, mock_run):
        """run() returns empty list on timeout"""
        import subprocess

        mock_mkdtemp.return_value = "/tmp/killhouse-scan-test"
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="semgrep", timeout=60)

        findings = self.scanner.run(Path("/tmp/repo"))
        assert findings == []

    @patch("src.scanner.sast.subprocess.run")
    @patch("src.scanner.sast.shutil.copytree")
    @patch("src.scanner.sast.shutil.rmtree")
    @patch("src.scanner.sast.tempfile.mkdtemp")
    def test_run_not_found(self, mock_mkdtemp, mock_rmtree, mock_copytree, mock_run):
        """run() returns empty list when semgrep is not installed"""
        mock_mkdtemp.return_value = "/tmp/killhouse-scan-test"
        mock_run.side_effect = FileNotFoundError("semgrep")

        findings = self.scanner.run(Path("/tmp/repo"))
        assert findings == []
