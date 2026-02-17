"""Semgrep SAST scanner wrapper"""

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List

from .exceptions import ScannerNotFoundError, ScannerTimeoutError
from .models import Finding

logger = logging.getLogger(__name__)


class SemgrepScanner:
    """Runs Semgrep SAST scan on a cloned repository"""

    def __init__(self, timeout: int = 300):
        self.timeout = timeout  # seconds

    def clone_repo(self, repo_url: str, branch: str = "main") -> Path:
        """Clone a git repository to a temporary directory"""
        repo_dir = Path(tempfile.mkdtemp(prefix="killhouse-sast-"))
        logger.info(f"Cloning {repo_url} (branch: {branch}) to {repo_dir}")
        try:
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--branch",
                    branch,
                    repo_url,
                    str(repo_dir),
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=True,
            )
            return repo_dir
        except subprocess.CalledProcessError as e:
            shutil.rmtree(repo_dir, ignore_errors=True)
            raise RuntimeError(f"Git clone failed: {e.stderr}") from e

    def run(self, repo_path: Path) -> List[Finding]:
        """Run Semgrep on a local repository path and return findings"""
        logger.info(f"Running Semgrep on {repo_path}")

        # Copy to temp dir to avoid semgrep's default .semgrepignore
        # which skips tests/ directories and other default patterns
        scan_dir = Path(tempfile.mkdtemp(prefix="killhouse-scan-"))
        try:
            shutil.copytree(repo_path, scan_dir, dirs_exist_ok=True)

            result = subprocess.run(
                [
                    "semgrep",
                    "scan",
                    "--config",
                    "auto",
                    "--json",
                    "--quiet",
                    "--no-git-ignore",
                    str(scan_dir),
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            # Semgrep returns exit code 1 when findings exist, 0 when clean
            if result.returncode not in (0, 1):
                logger.warning(
                    f"Semgrep exited with code {result.returncode}: {result.stderr[:500]}"
                )

            return self._parse_output(result.stdout, scan_dir)
        except subprocess.TimeoutExpired as e:
            raise ScannerTimeoutError("semgrep", self.timeout) from e
        except FileNotFoundError as e:
            raise ScannerNotFoundError("semgrep") from e
        finally:
            shutil.rmtree(scan_dir, ignore_errors=True)

    def _parse_output(self, raw_json: str, repo_path: Path) -> List[Finding]:
        """Parse Semgrep JSON output into Finding objects"""
        if not raw_json.strip():
            return []

        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep JSON: {e}")
            return []

        findings: List[Finding] = []
        for result in data.get("results", []):
            # Extract relative file path
            file_path = result.get("path", "")
            repo_str = str(repo_path)
            if file_path.startswith(repo_str):
                file_path = file_path[len(repo_str) :].lstrip("/")

            # Extract CWE from metadata
            metadata = result.get("extra", {}).get("metadata", {})
            cwe_list = metadata.get("cwe", [])
            cwe = (
                cwe_list[0]
                if isinstance(cwe_list, list) and cwe_list
                else (cwe_list if isinstance(cwe_list, str) else None)
            )

            # Extract reference URL
            references = metadata.get("references", [])
            reference = references[0] if references else metadata.get("source-url")

            severity_raw = result.get("extra", {}).get("severity", "INFO")

            findings.append(
                Finding(
                    tool="semgrep",
                    type="sast",
                    severity=Finding.normalize_severity(severity_raw),
                    title=result.get("check_id", "unknown"),
                    description=result.get("extra", {}).get("message", ""),
                    file_path=file_path,
                    line=result.get("start", {}).get("line"),
                    cwe=cwe,
                    reference=reference,
                )
            )

        logger.info(f"Semgrep found {len(findings)} issues")
        return findings

    def scan_repo(self, repo_url: str, branch: str = "main") -> List[Finding]:
        """Convenience method: clone + scan + cleanup"""
        repo_path = self.clone_repo(repo_url, branch)
        try:
            return self.run(repo_path)
        finally:
            shutil.rmtree(repo_path, ignore_errors=True)
