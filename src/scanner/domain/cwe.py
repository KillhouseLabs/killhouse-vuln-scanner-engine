"""CWE classification: maps CWE identifiers to exploit type categories."""

from __future__ import annotations

from typing import Optional

CWE_TO_EXPLOIT_TYPE: dict[str, str] = {
    "CWE-89": "sql_injection",
    "CWE-79": "xss",
    "CWE-78": "command_injection",
    "CWE-77": "command_injection",
    "CWE-22": "path_traversal",
    "CWE-918": "ssrf",
    "CWE-287": "auth_bypass",
    "CWE-306": "auth_bypass",
    "CWE-502": "deserialization",
    "CWE-611": "xxe",
    "CWE-94": "rce",
    "CWE-96": "rce",
}

DEFAULT_EXPLOIT_TYPE = "rce"


def classify_exploit_type(cwe: Optional[str]) -> str:
    """Classify a CWE identifier into an exploit type category."""
    if not cwe:
        return DEFAULT_EXPLOIT_TYPE
    return CWE_TO_EXPLOIT_TYPE.get(cwe, DEFAULT_EXPLOIT_TYPE)
