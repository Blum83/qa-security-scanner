import asyncio
import logging
import uuid

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.core.store import get, save, get_all
from app.models.scan import (
    ScanRecord,
    ScanReport,
    ScanRequest,
    ScanResponse,
    ScanStatus,
    ScanSummary,
)
from app.services.scanner import run_scan
from app.services.pdf_report import generate_pdf
from app.utils.ssrf_protection import validate_url, SSRFError

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    target_url = str(request.url)

    # SSRF protection: validate URL is not internal
    try:
        validate_url(target_url)
    except SSRFError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan_id = str(uuid.uuid4())

    record = ScanRecord(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        target_url=target_url,
    )
    save(record)

    logger.info("Scan %s created for %s", scan_id, target_url)
    asyncio.create_task(run_scan(scan_id, target_url))

    return ScanResponse(scan_id=scan_id, status=ScanStatus.PENDING)


@router.get("", response_model=list[ScanResponse])
async def list_scans():
    """List all scans (most recent first)."""
    records = get_all()
    return [
        ScanResponse(scan_id=r.scan_id, status=r.status)
        for r in records
    ]


@router.get("/{scan_id}", response_model=ScanReport)
async def get_scan(scan_id: str):
    record = get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    finished = record.status in (
        ScanStatus.COMPLETED,
        ScanStatus.FAILED,
        ScanStatus.CANCELLED,
    )

    summary = _build_summary(record) if finished else None

    # Only send issues when scan is finished to keep poll responses small
    issues = record.issues if finished else []

    return ScanReport(
        scan_id=record.scan_id,
        status=record.status,
        target_url=record.target_url,
        progress=record.progress,
        phase=record.phase,
        phase_details=record.phase_details if not finished else [],
        summary=summary,
        issues=issues,
        error=record.error,
    )


@router.get("/{scan_id}/pdf")
async def get_scan_pdf(scan_id: str):
    """Download scan report as PDF."""
    record = get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    if record.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan is not completed")

    pdf_bytes = generate_pdf(record)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=scan-{scan_id[:8]}.pdf"
        },
    )


@router.post("/{scan_id}/stop", response_model=ScanResponse)
async def stop_scan(scan_id: str):
    record = get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    if record.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(status_code=400, detail="Scan is not running")

    record.status = ScanStatus.CANCELLED
    record.phase = "Scan cancelled by user"
    save(record)
    logger.info("Scan %s cancelled by user", scan_id)

    # Try to stop ZAP scans too
    from app.services.zap_scanner import stop_zap_scans
    asyncio.create_task(stop_zap_scans(scan_id))

    return ScanResponse(scan_id=scan_id, status=ScanStatus.CANCELLED)


def _build_summary(record: ScanRecord) -> ScanSummary:
    summary = ScanSummary()
    for issue in record.issues:
        match issue.risk:
            case "critical":
                summary.critical += 1
            case "high":
                summary.high += 1
            case "medium":
                summary.medium += 1
            case "low":
                summary.low += 1
            case "info":
                summary.info += 1
    return summary
