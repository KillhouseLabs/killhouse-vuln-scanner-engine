"""Tests for NucleiScanner (DAST)"""

import json
import subprocess
from unittest.mock import MagicMock, patch

from src.scanner.dast import NucleiScanner


class TestNucleiParseOutput:
    """Tests for NucleiScanner._parse_output"""

    def setup_method(self):
        self.scanner = NucleiScanner(timeout=60)

    def test_parse_valid_output(self, sample_nuclei_output):
        """Parses valid Nuclei JSONL into Finding objects"""
        findings = self.scanner._parse_output(sample_nuclei_output)
        assert len(findings) == 2

        f0 = findings[0]
        assert f0.tool == "nuclei"
        assert f0.type == "dast"
        assert f0.severity == "CRITICAL"
        assert f0.title == "cve-2021-44228-log4j"
        assert f0.url == "http://target:8080/api/login"
        assert f0.cwe == "CWE-502"
        assert "nvd.nist.gov" in f0.reference

        f1 = findings[1]
        assert f1.severity == "INFO"
        assert f1.cwe is None

    def test_parse_empty_output(self):
        """Returns empty list for empty input"""
        assert self.scanner._parse_output("") == []
        assert self.scanner._parse_output("  \n  ") == []

    def test_parse_invalid_json_line(self):
        """Skips non-JSON lines gracefully"""
        output = "not json\n" + json.dumps(
            {
                "template-id": "test",
                "host": "http://target",
                "info": {
                    "name": "Test",
                    "severity": "low",
                    "description": "Test finding",
                    "classification": {"cwe-id": []},
                    "reference": [],
                },
            }
        )
        findings = self.scanner._parse_output(output)
        assert len(findings) == 1
        assert findings[0].severity == "LOW"

    def test_parse_reference_as_string(self):
        """Handles reference as a string instead of list"""
        output = json.dumps(
            {
                "template-id": "test",
                "host": "http://target",
                "info": {
                    "name": "Test",
                    "severity": "medium",
                    "description": "desc",
                    "classification": {"cwe-id": []},
                    "reference": "https://example.com",
                },
            }
        )
        findings = self.scanner._parse_output(output)
        assert findings[0].reference == "https://example.com"


class TestNucleiRun:
    """Tests for NucleiScanner.run with subprocess mocking"""

    def setup_method(self):
        self.scanner = NucleiScanner(timeout=60)

    @patch("src.scanner.dast.subprocess.run")
    def test_run_success(self, mock_run):
        """run() invokes nuclei and parses output"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="",
        )
        findings = self.scanner.run("http://target:8080")
        assert findings == []
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "nuclei"
        assert "http://target:8080" in args

    @patch("src.scanner.dast.subprocess.run")
    def test_run_timeout(self, mock_run):
        """run() returns empty list on timeout"""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nuclei", timeout=60)
        findings = self.scanner.run("http://target:8080")
        assert findings == []

    @patch("src.scanner.dast.subprocess.run")
    def test_run_not_found(self, mock_run):
        """run() returns empty list when nuclei is not installed"""
        mock_run.side_effect = FileNotFoundError("nuclei")
        findings = self.scanner.run("http://target:8080")
        assert findings == []
