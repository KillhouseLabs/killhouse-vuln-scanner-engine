"""Unified Finding model for scanner results"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Finding:
    """Unified vulnerability finding from SAST or DAST scanners"""

    tool: str  # "semgrep" | "nuclei"
    type: str  # "sast" | "dast"
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    description: str
    file_path: Optional[str] = None  # SAST
    line: Optional[int] = None  # SAST
    url: Optional[str] = None  # DAST
    cwe: Optional[str] = None
    reference: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert finding to dictionary"""
        return asdict(self)

    @staticmethod
    def normalize_severity(severity: str) -> str:
        """Normalize severity string to standard format"""
        mapping = {
            "error": "HIGH",
            "warning": "MEDIUM",
            "info": "INFO",
            "note": "INFO",
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
        }
        return mapping.get(severity.lower(), severity.upper())
