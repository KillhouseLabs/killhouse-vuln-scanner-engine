"""Nuclei DAST scanner wrapper"""

import json
import logging
import subprocess
from typing import List, Optional, Tuple

import docker

from .exceptions import ScannerNotFoundError, ScannerTimeoutError
from .models import Finding

logger = logging.getLogger(__name__)


class NucleiScanner:
    """Runs Nuclei DAST scan against a target URL"""

    def __init__(self, timeout: int = 300):
        self.timeout = timeout  # seconds

    def run(self, target_url: str, network_name: Optional[str] = None) -> Tuple[List[Finding], str]:
        """Run Nuclei against a target URL and return findings with raw output.

        If network_name is provided, connects the current container
        to that Docker network before scanning, and disconnects after.
        Raises RuntimeError if network connection fails.

        Returns:
            Tuple of (findings, raw_output) where raw_output is nuclei's stderr.
        """
        logger.info(f"Running Nuclei scan on {target_url}")
        connected = False

        if network_name:
            connected = self._connect_to_network(network_name)
            if not connected:
                raise RuntimeError(f"Failed to connect to Docker network '{network_name}'")

        try:
            result = subprocess.run(
                [
                    "nuclei",
                    "-u",
                    target_url,
                    "-jsonl",
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

            findings = self._parse_output(result.stdout)
            return findings, result.stderr
        except subprocess.TimeoutExpired as e:
            raise ScannerTimeoutError("nuclei", self.timeout) from e
        except FileNotFoundError as e:
            raise ScannerNotFoundError("nuclei") from e
        finally:
            if connected and network_name:
                self._disconnect_from_network(network_name)

    def _connect_to_network(self, network_name: str) -> bool:
        """Connect this container to the target Docker network."""
        try:
            client = docker.from_env()
            network = client.networks.get(network_name)
            # Get current container ID from /proc/self/cgroup or hostname
            import socket

            container_id = socket.gethostname()
            network.connect(container_id)
            logger.info(f"Connected to network {network_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to connect to network {network_name}: {e}")
            return False

    def _disconnect_from_network(self, network_name: str) -> None:
        """Disconnect this container from the target Docker network."""
        try:
            client = docker.from_env()
            network = client.networks.get(network_name)
            import socket

            container_id = socket.gethostname()
            network.disconnect(container_id)
            logger.info(f"Disconnected from network {network_name}")
        except Exception as e:
            logger.warning(f"Failed to disconnect from network {network_name}: {e}")

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
