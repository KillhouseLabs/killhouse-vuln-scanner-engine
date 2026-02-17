"""Nuclei DAST scanner wrapper"""

import json
import logging
import subprocess
from typing import List

from .exceptions import ScannerNotFoundError, ScannerTimeoutError
from .models import Finding

logger = logging.getLogger(__name__)


class NucleiScanner:
    """Runs Nuclei DAST scan against a target URL"""

    def __init__(self, timeout: int = 300):
        self.timeout = timeout  # seconds

    def run(self, target_url: str) -> List[Finding]:
        """Run Nuclei against a target URL and return findings"""
        logger.info(f"Running Nuclei scan on {target_url}")
        try:
            result = subprocess.run(
                [
                    "nuclei",
                    "-u",
                    target_url,
                    "-jsonl",
                    "-silent",
                    "-severity",
                    "low,medium,high,critical",
                    "-timeout",
                    "10",
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            if result.returncode != 0 and not result.stdout.strip():
                logger.warning(
                    f"Nuclei exited with code {result.returncode}: {result.stderr[:500]}"
                )

            return self._parse_output(result.stdout)
        except subprocess.TimeoutExpired:
            raise ScannerTimeoutError("nuclei", self.timeout)
        except FileNotFoundError:
            raise ScannerNotFoundError("nuclei")

    def _parse_output(self, raw_output: str) -> List[Finding]:
        """Parse Nuclei JSONL output into Finding objects"""
        findings: List[Finding] = []

        for line in raw_output.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                logger.debug(f"Skipping non-JSON line: {line[:100]}")
                continue

            # Extract info from Nuclei JSON format
            info = data.get("info", {})
            classification = info.get("classification", {})

            # Get CWE
            cwe_list = classification.get("cwe-id", [])
            cwe = cwe_list[0] if cwe_list else None

            # Get reference
            references = info.get("reference", [])
            # reference can be a list or "references" can be in different places
            if isinstance(references, list) and references:
                reference = references[0]
            elif isinstance(references, str):
                reference = references
            else:
                reference = None

            severity_raw = info.get("severity", "info")

            findings.append(
                Finding(
                    tool="nuclei",
                    type="dast",
                    severity=Finding.normalize_severity(severity_raw),
                    title=data.get("template-id", info.get("name", "unknown")),
                    description=info.get("description", info.get("name", "")),
                    url=data.get("matched-at", data.get("host", "")),
                    cwe=cwe,
                    reference=reference,
                )
            )

        logger.info(f"Nuclei found {len(findings)} issues")
        return findings
