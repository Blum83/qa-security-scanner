"""Orchestrates the full scan pipeline."""

import asyncio
import logging

from app.core.config import settings
from app.core.store import get, save
from app.models.scan import ScanStatus
from app.services.header_checker import check_headers
from app.services.zap_scanner import scan_with_zap

logger = logging.getLogger(__name__)


def _is_cancelled(scan_id: str) -> bool:
    record = get(scan_id)
    return record is not None and record.status == ScanStatus.CANCELLED


async def run_scan(scan_id: str, target_url: str) -> None:
    record = get(scan_id)
    if not record:
        return

    record.status = ScanStatus.RUNNING
    record.progress = 0
    record.phase = "Connecting to target..."
    save(record)
    logger.info("Scan %s started for %s", scan_id, target_url)

    try:
        # Phase 1: Header checks
        record.phase = "Checking security headers"
        record.progress = 2
        save(record)
        logger.info("Scan %s: running header checks", scan_id)

        header_issues = await check_headers(target_url)

        if _is_cancelled(scan_id):
            logger.info("Scan %s: cancelled during header checks", scan_id)
            return

        record.issues.extend(header_issues)
        record.progress = 10
        record.phase = "Header checks complete"
        save(record)
        logger.info("Scan %s: header checks complete — %d issues", scan_id, len(header_issues))

        # Phase 2: ZAP scan
        if _is_cancelled(scan_id):
            logger.info("Scan %s: cancelled before ZAP scan", scan_id)
            return

        record.phase = "Crawling the website (ZAP Spider)"
        record.progress = 12
        save(record)
        logger.info("Scan %s: running ZAP scan", scan_id)

        try:
            # Wrap ZAP scan in timeout to prevent hanging forever
            zap_issues = await asyncio.wait_for(
                scan_with_zap(scan_id, target_url),
                timeout=settings.zap_scan_timeout_seconds
            )
            logger.info("Scan %s: ZAP scan completed within timeout", scan_id)
        except asyncio.TimeoutError:
            logger.error("Scan %s: ZAP scan timed out after %d seconds", 
                        scan_id, settings.zap_scan_timeout_seconds)
            record = get(scan_id)
            if record and record.status != ScanStatus.CANCELLED:
                record.phase = "ZAP scan timed out"
                record.progress = 95
                save(record)
            zap_issues = []

        if _is_cancelled(scan_id):
            logger.info("Scan %s: cancelled during ZAP scan", scan_id)
            return

        record.issues.extend(zap_issues)
        record.progress = 95
        save(record)
        logger.info("Scan %s: ZAP scan complete — %d issues", scan_id, len(zap_issues))

    except Exception:
        logger.exception("Scan %s failed", scan_id)
        record = get(scan_id)
        if record.status == ScanStatus.CANCELLED:
            return
        record.status = ScanStatus.FAILED
        record.error = "The scan encountered an unexpected error. Please try again."
        save(record)
        return

    record.phase = "Building report"
    record.progress = 98
    save(record)

    record.status = ScanStatus.COMPLETED
    record.progress = 100
    record.phase = "Done"
    save(record)
    total = len(record.issues)
    logger.info("Scan %s completed — %d total issues found", scan_id, total)
