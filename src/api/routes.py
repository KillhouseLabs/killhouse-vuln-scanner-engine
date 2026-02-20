"""API routes for scanner engine"""

import logging
from datetime import datetime
from typing import Any, Dict
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException

from src.policy import fetch_policy, get_plan_limits
from src.scanner.fix_generator import FixGenerator
from src.scanner.pipeline import ScanPipeline

from .schemas import (
    FixSuggestionRequest,
    FixSuggestionResponse,
    ScanRequest,
    ScanResponse,
    ScanStatus,
    ScanStatusResponse,
)

logger = logging.getLogger(__name__)

# In-memory storage for scan status
# Structure: {scan_id: {status, analysis_id, started_at, completed_at, error, request}}
scan_store: Dict[str, Dict[str, Any]] = {}

router = APIRouter()

# Pipeline instance
_pipeline = ScanPipeline()


async def _run_scan(scan_id: str, request: ScanRequest):
    """Execute scan pipeline as a background task"""
    await _pipeline.run(
        scan_id=scan_id,
        analysis_id=request.analysis_id,
        repo_url=request.repo_url,
        branch=request.branch,
        target_url=request.target_url,
        callback_url=request.callback_url,
        local_path=request.local_path,
        scan_store=scan_store,
        network_name=request.network_name,
    )


@router.post("/api/scans", response_model=ScanResponse)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
):
    """
    Initiate a new vulnerability scan

    Args:
        request: Scan configuration including analysis_id, repo_url, target_url
        background_tasks: FastAPI background task manager

    Returns:
        ScanResponse with scan_id and ACCEPTED status
    """
    # Check concurrency limit
    policy = fetch_policy()
    limits = get_plan_limits(policy, request.plan_id)

    active_scans = sum(
        1 for s in scan_store.values() if s["status"] in (ScanStatus.ACCEPTED, ScanStatus.SCANNING)
    )

    if active_scans >= limits.max_concurrent_scans:
        raise HTTPException(
            status_code=429,
            detail=f"동시 스캔 수 제한({limits.max_concurrent_scans}개)에 도달했습니다.",
        )

    scan_id = str(uuid4())[:8]

    logger.info(f"Creating scan {scan_id} for analysis {request.analysis_id}")

    # Store scan info
    scan_store[scan_id] = {
        "scan_id": scan_id,
        "analysis_id": request.analysis_id,
        "status": ScanStatus.ACCEPTED,
        "started_at": datetime.now(),
        "completed_at": None,
        "error": None,
        "request": request,
    }

    # Add background task
    background_tasks.add_task(_run_scan, scan_id, request)

    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.ACCEPTED,
        message=f"Scan {scan_id} accepted and queued",
    )


@router.get("/api/scans/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """
    Get current status of a scan

    Args:
        scan_id: Unique scan identifier

    Returns:
        ScanStatusResponse with current scan status

    Raises:
        HTTPException: If scan_id not found
    """
    if scan_id not in scan_store:
        logger.warning(f"Scan {scan_id} not found")
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    scan_data = scan_store[scan_id]

    return ScanStatusResponse(
        scan_id=scan_data["scan_id"],
        analysis_id=scan_data["analysis_id"],
        status=scan_data["status"],
        started_at=scan_data["started_at"],
        completed_at=scan_data["completed_at"],
        error=scan_data["error"],
    )


@router.post("/api/fix-suggestion", response_model=FixSuggestionResponse)
async def fix_suggestion(request: FixSuggestionRequest):
    """
    Generate AI-powered code fix suggestion

    Takes source code and vulnerability info, returns fixed code with explanation.
    """
    generator = FixGenerator()

    try:
        result = await generator.generate_fix(
            source_code=request.source_code,
            file_path=request.file_path,
            line=request.line,
            severity=request.severity,
            rule=request.rule,
            cwe=request.cwe,
            description=request.description,
        )
    except RuntimeError as err:
        raise HTTPException(
            status_code=503,
            detail="OpenAI API key is not configured",
        ) from err
    except Exception as err:
        logger.error("Fix suggestion generation failed: %s", err)
        raise HTTPException(
            status_code=502,
            detail=f"AI 코드 수정 생성 실패: {type(err).__name__}",
        ) from err

    return FixSuggestionResponse(
        explanation=result["explanation"],
        fixed_code=result["fixed_code"],
    )


@router.get("/health")
async def health_check():
    """
    Health check endpoint

    Returns:
        Health status response
    """
    return {
        "status": "ok",
        "service": "killhouse-scanner-engine",
    }
