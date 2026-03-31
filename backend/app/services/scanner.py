"""Orchestrates the full scan pipeline."""

import asyncio
import logging

from app.core.config import settings
from app.core.store import get, save
from app.models.scan import ScanStatus
from app.services.header_checker import check_headers
from app.services.nuclei_scanner import scan_with_nuclei
from app.services.ssl_auditor import audit_ssl
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

        # Phase 1.5: SSL/TLS Audit
        record.phase = "Auditing SSL/TLS certificate"
        record.progress = 12
        save(record)
        logger.info("Scan %s: running SSL/TLS audit", scan_id)

        ssl_issues = await audit_ssl(target_url)

        if _is_cancelled(scan_id):
            logger.info("Scan %s: cancelled during SSL audit", scan_id)
            return

        record.issues.extend(ssl_issues)
        record.progress = 15
        record.phase = "SSL audit complete"
        save(record)
        logger.info("Scan %s: SSL audit complete — %d issues", scan_id, len(ssl_issues))

        # Phase 2: Run ZAP and Nuclei in parallel
        if _is_cancelled(scan_id):
            logger.info("Scan %s: cancelled before parallel scans", scan_id)
            return

        record.phase = "Running vulnerability scans"
        record.progress = 15
        save(record)
        logger.info("Scan %s: starting ZAP + Nuclei scans", scan_id)

        # Each task manages its own timeout internally.
        # We just wait for both to finish.
        zap_task = asyncio.create_task(scan_with_zap(scan_id, target_url))
        nuclei_task = asyncio.create_task(scan_with_nuclei(scan_id, target_url))

        # Wait for both with overall timeout
        try:
            await asyncio.wait_for(
                asyncio.gather(zap_task, nuclei_task, return_exceptions=True),
                timeout=settings.scan_timeout_seconds,
            )
        except asyncio.TimeoutError:
            logger.warning("Scan %s: overall timeout reached (%ds)", scan_id, settings.scan_timeout_seconds)
            zap_task.cancel()
            nuclei_task.cancel()
            # Give tasks a moment to clean up
            await asyncio.gather(zap_task, nuclei_task, return_exceptions=True)

        if _is_cancelled(scan_id):
            logger.info("Scan %s: cancelled after parallel scans", scan_id)
            return

        # Collect results from both tasks (they already saved issues to record)
        record = get(scan_id)
        if not record:
            return

        # Brief pause for "Collecting results" phase visibility
        record.progress = 92
        record.phase = "Collecting scan results"
        save(record)
        await asyncio.sleep(1.5)

        record.progress = 95
        record.phase = "All scans complete"
        save(record)

    except asyncio.CancelledError:
        logger.info("Scan %s: cancelled", scan_id)
        return
    except Exception:
        logger.exception("Scan %s failed", scan_id)
        record = get(scan_id)
        if record and record.status == ScanStatus.CANCELLED:
            return
        record.status = ScanStatus.FAILED
        record.error = "The scan encountered an unexpected error. Please try again."
        save(record)
        return

    record = get(scan_id)
    if not record or record.status == ScanStatus.CANCELLED:
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
