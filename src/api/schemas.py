"""Pydantic schemas for API requests and responses"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class ScanStatus(str, Enum):
    """Status of a vulnerability scan"""

    ACCEPTED = "ACCEPTED"
    SCANNING = "SCANNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScanRequest(BaseModel):
    """Request to initiate a vulnerability scan"""

    analysis_id: str
    repo_url: Optional[str] = None
    branch: str = "main"
    target_url: Optional[str] = None
    callback_url: Optional[str] = None
    local_path: Optional[str] = None  # Direct local path for SAST (skips git clone)


class ScanResponse(BaseModel):
    """Response after initiating a scan"""

    scan_id: str
    status: ScanStatus
    message: str = ""


class ScanStatusResponse(BaseModel):
    """Response containing current scan status"""

    scan_id: str
    analysis_id: str
    status: ScanStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
