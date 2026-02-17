"""Custom exceptions for scanner operations"""


class ScannerNotFoundError(RuntimeError):
    """Raised when a scanner binary is not installed"""

    def __init__(self, scanner_name: str):
        self.scanner_name = scanner_name
        super().__init__(f"{scanner_name} is not installed")


class ScannerTimeoutError(RuntimeError):
    """Raised when a scanner exceeds the configured timeout"""

    def __init__(self, scanner_name: str, timeout: int):
        self.scanner_name = scanner_name
        self.timeout = timeout
        super().__init__(f"{scanner_name} timed out after {timeout}s")
