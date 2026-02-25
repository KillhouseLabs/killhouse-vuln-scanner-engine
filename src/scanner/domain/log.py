"""Log callback severity levels."""

from enum import Enum


class LogLevel(str, Enum):
    """Severity level for log callbacks."""

    INFO = "info"
    ERROR = "error"
