"""Tests for SemgrepScanner (SAST)"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.scanner.exceptions import ScannerNotFoundError, ScannerTimeoutError
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


class TestSemgrepCloneRepoRawOutput:
    """Tests for SemgrepScanner.clone_repo returning raw output"""

    def setup_method(self):
        self.scanner = SemgrepScanner(timeout=60)

    @patch("src.scanner.sast.subprocess.run")
    @patch("src.scanner.sast.tempfile.mkdtemp")
    def test_clone_returns_tuple_with_path_and_output(self, mock_mkdtemp, mock_run):
        """clone_repo() returns (repo_path, raw_output) tuple"""
        mock_mkdtemp.return_value = "/tmp/killhouse-sast-test"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="Cloning into '/tmp/killhouse-sast-test'...\nremote: Enumerating objects: 42\n",
        )

        result = self.scanner.clone_repo("https://github.com/test/repo.git", "main")

        assert isinstance(result, tuple)
        assert len(result) == 2
        repo_path, raw_output = result
        assert isinstance(repo_path, Path)
        assert str(repo_path) == "/tmp/killhouse-sast-test"
        assert "Cloning into" in raw_output

    @patch("src.scanner.sast.subprocess.run")
    @patch("src.scanner.sast.tempfile.mkdtemp")
    def test_clone_captures_git_progress_from_stderr(self, mock_mkdtemp, mock_run):
        """clone_repo() captures git progress output from stderr"""
        mock_mkdtemp.return_value = "/tmp/killhouse-sast-test"
        git_progress = (
            "Cloning into '/tmp/killhouse-sast-test'...\n"
            "remote: Enumerating objects: 150, done.\n"
            "remote: Counting objects: 100% (150/150), done.\n"
            "Receiving objects: 100% (150/150), 1.20 MiB | 5.00 MiB/s, done.\n"
        )
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr=git_progress)

        _, raw_output = self.scanner.clone_repo("https://github.com/test/repo.git", "main")

        assert "Enumerating objects" in raw_output
        assert "Receiving objects" in raw_output

    @patch("src.scanner.sast.subprocess.run")
    @patch("src.scanner.sast.tempfile.mkdtemp")
    def test_clone_returns_empty_output_on_silent_success(self, mock_mkdtemp, mock_run):
        """clone_repo() returns empty string when git produces no output"""
        mock_mkdtemp.return_value = "/tmp/killhouse-sast-test"
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        _, raw_output = self.scanner.clone_repo("https://github.com/test/repo.git", "main")

        assert raw_output == ""


class TestSemgrepRunRawOutput:
    """Tests for SemgrepScanner.run returning raw output alongside findings"""

    def setup_method(self):
        self.scanner = SemgrepScanner(timeout=60)

    @patch("src.scanner.sast.subprocess.run")
    @patch("src.scanner.sast.shutil.copytree")
    @patch("src.scanner.sast.shutil.rmtree")
    @patch("src.scanner.sast.tempfile.mkdtemp")
    def test_run_returns_tuple_with_findings_and_output(
        self, mock_mkdtemp, mock_rmtree, mock_copytree, mock_run
    ):
        """run() returns (findings, raw_output) tuple"""
        mock_mkdtemp.return_value = "/tmp/killhouse-scan-test"
        semgrep_stderr = "Running 500 rules...\nFinished in 2.5s\n"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"results": [], "errors": []}),
            stderr=semgrep_stderr,
        )

        result = self.scanner.run(Path("/tmp/repo"))

        assert isinstance(result, tuple)
        assert len(result) == 2
        findings, raw_output = result
        assert findings == []
        assert "Running 500 rules" in raw_output

    @patch("src.scanner.sast.subprocess.run")
    @patch("src.scanner.sast.shutil.copytree")
    @patch("src.scanner.sast.shutil.rmtree")
    @patch("src.scanner.sast.tempfile.mkdtemp")
    def test_run_does_not_use_quiet_flag(self, mock_mkdtemp, mock_rmtree, mock_copytree, mock_run):
        """run() does not pass --quiet flag to semgrep (allows raw output)"""
        mock_mkdtemp.return_value = "/tmp/killhouse-scan-test"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"results": [], "errors": []}),
            stderr="",
        )

        self.scanner.run(Path("/tmp/repo"))

        args = mock_run.call_args[0][0]
        assert "--quiet" not in args

    @patch("src.scanner.sast.subprocess.run")
    @patch("src.scanner.sast.shutil.copytree")
    @patch("src.scanner.sast.shutil.rmtree")
    @patch("src.scanner.sast.tempfile.mkdtemp")
    def test_run_captures_semgrep_warnings_from_stderr(
        self, mock_mkdtemp, mock_rmtree, mock_copytree, mock_run
    ):
        """run() captures semgrep warnings and progress from stderr"""
        mock_mkdtemp.return_value = "/tmp/killhouse-scan-test"
        semgrep_stderr = (
            "Scanning 25 files with 500 rules...\n"
            "Some files were skipped: 3 files\n"
            "Ran 500 rules on 22 files: 5 findings\n"
        )
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=json.dumps({"results": [], "errors": []}),
            stderr=semgrep_stderr,
        )

        _, raw_output = self.scanner.run(Path("/tmp/repo"))

        assert "Scanning 25 files" in raw_output
        assert "5 findings" in raw_output


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

        findings, _ = self.scanner.run(Path("/tmp/repo"))
        assert findings == []
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "semgrep"

    @patch("src.scanner.sast.subprocess.run")
    @patch("src.scanner.sast.shutil.copytree")
    @patch("src.scanner.sast.shutil.rmtree")
    @patch("src.scanner.sast.tempfile.mkdtemp")
    def test_run_timeout(self, mock_mkdtemp, mock_rmtree, mock_copytree, mock_run):
        """run() raises ScannerTimeoutError on timeout"""
        import subprocess

        mock_mkdtemp.return_value = "/tmp/killhouse-scan-test"
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="semgrep", timeout=60)

        with pytest.raises(ScannerTimeoutError, match="semgrep"):
            self.scanner.run(Path("/tmp/repo"))

    @patch("src.scanner.sast.subprocess.run")
    @patch("src.scanner.sast.shutil.copytree")
    @patch("src.scanner.sast.shutil.rmtree")
    @patch("src.scanner.sast.tempfile.mkdtemp")
    def test_run_not_found(self, mock_mkdtemp, mock_rmtree, mock_copytree, mock_run):
        """run() raises ScannerNotFoundError when semgrep is not installed"""
        mock_mkdtemp.return_value = "/tmp/killhouse-scan-test"
        mock_run.side_effect = FileNotFoundError("semgrep")

        with pytest.raises(ScannerNotFoundError, match="semgrep"):
            self.scanner.run(Path("/tmp/repo"))


class TestSemgrepScanRepoBackwardCompat:
    """Tests for SemgrepScanner.scan_repo backward compatibility"""

    def setup_method(self):
        self.scanner = SemgrepScanner(timeout=60)

    @patch("src.scanner.sast.shutil.rmtree")
    @patch.object(SemgrepScanner, "run")
    @patch.object(SemgrepScanner, "clone_repo")
    def test_scan_repo_returns_findings_only(self, mock_clone, mock_run, mock_rmtree):
        """scan_repo() returns List[Finding] (not tuple) for backward compatibility"""
        mock_clone.return_value = (Path("/tmp/repo"), "clone output")
        mock_run.return_value = ([], "scan output")

        result = self.scanner.scan_repo("https://github.com/test/repo.git")

        assert isinstance(result, list)
        assert result == []
