"""Shared fixtures for scanner-engine tests"""

import json
import os

import pytest

# Set dummy environment variables before any src imports
os.environ.setdefault("OPENAI_API_KEY", "test-openai-key")
os.environ.setdefault("SCANNER_API_KEY", "test-scanner-key")


@pytest.fixture
def sample_semgrep_output():
    """Sample Semgrep JSON output for SAST parsing tests"""
    return json.dumps(
        {
            "results": [
                {
                    "check_id": "python.lang.security.audit.exec-detected",
                    "path": "/tmp/scan/app.py",
                    "start": {"line": 10, "col": 1},
                    "end": {"line": 10, "col": 30},
                    "extra": {
                        "severity": "WARNING",
                        "message": "Detected use of exec(). This can be dangerous.",
                        "metadata": {
                            "cwe": ["CWE-95: Improper Neutralization of Directives"],
                            "references": ["https://owasp.org/Top10/A03_2021"],
                            "source-url": "https://semgrep.dev/r/python.lang.security",
                        },
                    },
                },
                {
                    "check_id": "python.flask.security.injection.sql-injection",
                    "path": "/tmp/scan/db.py",
                    "start": {"line": 25, "col": 5},
                    "end": {"line": 25, "col": 60},
                    "extra": {
                        "severity": "ERROR",
                        "message": "SQL injection detected in query construction.",
                        "metadata": {
                            "cwe": ["CWE-89: SQL Injection"],
                            "references": ["https://cwe.mitre.org/data/definitions/89.html"],
                        },
                    },
                },
            ],
            "errors": [],
            "version": "1.50.0",
        }
    )


@pytest.fixture
def sample_nuclei_output():
    """Sample Nuclei JSONL output for DAST parsing tests"""
    lines = [
        json.dumps(
            {
                "template-id": "cve-2021-44228-log4j",
                "host": "http://target:8080",
                "matched-at": "http://target:8080/api/login",
                "info": {
                    "name": "Log4j RCE",
                    "severity": "critical",
                    "description": "Apache Log4j2 remote code execution vulnerability.",
                    "classification": {
                        "cwe-id": ["CWE-502"],
                        "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    },
                    "reference": [
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                        "https://logging.apache.org/log4j/2.x/security.html",
                    ],
                },
            }
        ),
        json.dumps(
            {
                "template-id": "http-missing-security-headers",
                "host": "http://target:8080",
                "matched-at": "http://target:8080/",
                "info": {
                    "name": "Missing X-Frame-Options",
                    "severity": "info",
                    "description": "The X-Frame-Options header is not set.",
                    "classification": {"cwe-id": []},
                    "reference": [],
                },
            }
        ),
    ]
    return "\n".join(lines)
