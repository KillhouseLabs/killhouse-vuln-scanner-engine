"""Log callback: severity levels and message value object."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

DEFAULT_RAW_OUTPUT_MAX_LENGTH = 50_000


class LogLevel(str, Enum):
    """Severity level for log callbacks."""

    INFO = "info"
    ERROR = "error"


@dataclass(frozen=True)
class LogMessage:
    """Immutable log callback payload (Value Object).

    Encapsulates message construction and raw_output truncation.
    """

    message: str
    level: LogLevel = LogLevel.INFO
    raw_output: Optional[str] = None

    @classmethod
    def info(cls, message: str, raw_output: Optional[str] = None) -> LogMessage:
        return cls(message=message, level=LogLevel.INFO, raw_output=raw_output)

    @classmethod
    def error(cls, message: str, raw_output: Optional[str] = None) -> LogMessage:
        return cls(message=message, level=LogLevel.ERROR, raw_output=raw_output)

    def truncated_raw_output(
        self, max_length: int = DEFAULT_RAW_OUTPUT_MAX_LENGTH
    ) -> Optional[str]:
        """Return raw_output truncated to max_length, or None if absent."""
        if not self.raw_output:
            return None
        if len(self.raw_output) <= max_length:
            return self.raw_output
        return self.raw_output[:max_length] + "\n... (truncated)"

    def to_payload(self, max_length: int = DEFAULT_RAW_OUTPUT_MAX_LENGTH) -> dict:
        """Build webhook callback payload dict."""
        payload: dict = {
            "log_message": self.message,
            "log_level": self.level,
        }
        truncated = self.truncated_raw_output(max_length)
        if truncated:
            payload["raw_output"] = truncated
        return payload
