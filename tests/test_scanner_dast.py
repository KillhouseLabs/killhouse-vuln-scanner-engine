"""Tests for NucleiScanner (DAST)"""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from src.scanner.dast import NucleiScanner
from src.scanner.exceptions import ScannerNotFoundError, ScannerTimeoutError


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


class TestNucleiRunRawOutput:
    """Tests for NucleiScanner.run returning raw output alongside findings"""

    def setup_method(self):
        self.scanner = NucleiScanner(timeout=60)

    @patch("src.scanner.dast.subprocess.run")
    def test_run_returns_tuple_with_findings_and_output(self, mock_run):
        """run() returns (findings, raw_output) tuple"""
        nuclei_stderr = (
            "[INF] nuclei-engine v3.1.0\n[INF] Templates loaded: 500\n[INF] Targets loaded: 1\n"
        )
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr=nuclei_stderr,
        )

        result = self.scanner.run("http://target:8080")

        assert isinstance(result, tuple)
        assert len(result) == 2
        findings, raw_output = result
        assert findings == []
        assert "Templates loaded" in raw_output

    @patch("src.scanner.dast.subprocess.run")
    def test_run_does_not_use_silent_flag(self, mock_run):
        """run() does not pass -silent flag to nuclei (allows raw output)"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="",
        )

        self.scanner.run("http://target:8080")

        args = mock_run.call_args[0][0]
        assert "-silent" not in args

    @patch("src.scanner.dast.subprocess.run")
    def test_run_captures_nuclei_progress_from_stderr(self, mock_run):
        """run() captures nuclei scan progress from stderr"""
        nuclei_stderr = "[INF] Running httpx on input host\n[INF] Found 3 results in 5.2s\n"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr=nuclei_stderr,
        )

        _, raw_output = self.scanner.run("http://target:8080")

        assert "Running httpx" in raw_output
        assert "Found 3 results" in raw_output


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
        findings, _ = self.scanner.run("http://target:8080")
        assert findings == []
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "nuclei"
        assert "http://target:8080" in args

    @patch("src.scanner.dast.subprocess.run")
    def test_run_timeout(self, mock_run):
        """run() raises ScannerTimeoutError on timeout"""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nuclei", timeout=60)
        with pytest.raises(ScannerTimeoutError, match="nuclei"):
            self.scanner.run("http://target:8080")

    @patch("src.scanner.dast.subprocess.run")
    def test_run_not_found(self, mock_run):
        """run() raises ScannerNotFoundError when nuclei is not installed"""
        mock_run.side_effect = FileNotFoundError("nuclei")
        with pytest.raises(ScannerNotFoundError, match="nuclei"):
            self.scanner.run("http://target:8080")


class TestNucleiNetworkConnect:
    """Tests for NucleiScanner Docker network connect/disconnect"""

    def setup_method(self):
        self.scanner = NucleiScanner(timeout=60)

    @patch("src.scanner.dast.docker.from_env")
    @patch("src.scanner.dast.subprocess.run")
    def test_connects_to_network_before_scan(self, mock_run, mock_docker):
        """Scanner connects to Docker network before running nuclei"""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        mock_network = MagicMock()
        mock_docker.return_value.networks.get.return_value = mock_network

        self.scanner.run("http://target:8080", network_name="killhouse-test-123")

        mock_docker.return_value.networks.get.assert_called_with("killhouse-test-123")
        mock_network.connect.assert_called_once()

    @patch("src.scanner.dast.docker.from_env")
    @patch("src.scanner.dast.subprocess.run")
    def test_disconnects_from_network_after_scan(self, mock_run, mock_docker):
        """Scanner disconnects from Docker network after scan completes"""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        mock_network = MagicMock()
        mock_docker.return_value.networks.get.return_value = mock_network

        self.scanner.run("http://target:8080", network_name="killhouse-test-123")

        mock_network.disconnect.assert_called_once()

    @patch("src.scanner.dast.subprocess.run")
    def test_runs_without_network_when_none(self, mock_run):
        """Scanner runs without network connect when network_name is None"""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        self.scanner.run("http://target:8080", network_name=None)

        mock_run.assert_called_once()

    @patch("src.scanner.dast.docker.from_env")
    @patch("src.scanner.dast.subprocess.run")
    def test_disconnects_even_on_scan_failure(self, mock_run, mock_docker):
        """Network disconnect runs even if scan raises an exception"""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nuclei", timeout=60)
        mock_network = MagicMock()
        mock_docker.return_value.networks.get.return_value = mock_network

        with pytest.raises(ScannerTimeoutError):
            self.scanner.run("http://target:8080", network_name="killhouse-test-123")

        mock_network.disconnect.assert_called_once()
