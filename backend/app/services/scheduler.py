"""APScheduler-based scan scheduler.

Uses AsyncIOScheduler so all jobs run on the same event loop as FastAPI/uvicorn.
Schedule configuration is persisted in SQLite via schedule_store; APScheduler
uses an in-memory job store and re-registers all active jobs on startup.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from app.core.schedule_store import (
    get_all_schedules,
    get_schedule,
    update_last_scan,
    webhooks_from_json,
)
from app.core.store import get, save
from app.models.scan import ScanRecord, ScanStatus
from app.models.schedule import ScheduleStatus

logger = logging.getLogger(__name__)

_scheduler: AsyncIOScheduler | None = None


def get_scheduler() -> AsyncIOScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler(timezone="UTC")
    return _scheduler


async def start_scheduler() -> None:
    """Called from the FastAPI lifespan. Re-registers all active schedules."""
    scheduler = get_scheduler()
    records = get_all_schedules()
    for record in records:
        if record.status == ScheduleStatus.ACTIVE:
            _register_job(scheduler, record.schedule_id, record.cron)
    scheduler.start()
    logger.info("Scheduler started — %d active job(s) registered", scheduler.get_jobs().__len__())


async def stop_scheduler() -> None:
    """Called from the FastAPI lifespan on shutdown."""
    scheduler = get_scheduler()
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")


def _register_job(scheduler: AsyncIOScheduler, schedule_id: str, cron: str) -> None:
    """Add or replace a job in the in-memory scheduler."""
    trigger = CronTrigger.from_crontab(cron, timezone="UTC")
    scheduler.add_job(
        _run_scheduled_scan,
        trigger=trigger,
        id=schedule_id,
        replace_existing=True,
        args=[schedule_id],
        misfire_grace_time=300,  # allow up to 5 min late execution
    )
    logger.info("Registered schedule job %s (cron: %s)", schedule_id, cron)


def register_schedule(schedule_id: str, cron: str) -> None:
    """Public API: register a new or updated schedule."""
    _register_job(get_scheduler(), schedule_id, cron)


def unregister_schedule(schedule_id: str) -> None:
    """Public API: remove a schedule from the in-memory scheduler."""
    scheduler = get_scheduler()
    if scheduler.get_job(schedule_id):
        scheduler.remove_job(schedule_id)
        logger.info("Unregistered schedule job %s", schedule_id)


def pause_schedule(schedule_id: str) -> None:
    scheduler = get_scheduler()
    if scheduler.get_job(schedule_id):
        scheduler.pause_job(schedule_id)


def resume_schedule(schedule_id: str) -> None:
    scheduler = get_scheduler()
    if scheduler.get_job(schedule_id):
        scheduler.resume_job(schedule_id)


def get_next_run_at(schedule_id: str) -> str | None:
    """Return ISO-8601 UTC string of next scheduled run, or None."""
    job = get_scheduler().get_job(schedule_id)
    if job and job.next_run_time:
        return job.next_run_time.astimezone(timezone.utc).isoformat()
    return None


async def _run_scheduled_scan(schedule_id: str) -> None:
    """APScheduler job: create and run a scan for the given schedule."""
    # Import here to avoid circular imports at module level
    from app.services.notifier import dispatch_webhooks
    from app.services.scanner import run_scan

    schedule = get_schedule(schedule_id)
    if not schedule or schedule.status != ScheduleStatus.ACTIVE:
        logger.info("Skipping job for schedule %s (not active)", schedule_id)
        return

    scan_id = str(uuid.uuid4())
    scan_record = ScanRecord(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        target_url=schedule.url,
    )
    save(scan_record)
    update_last_scan(schedule_id, scan_id)
    logger.info("Schedule %s triggered scan %s for %s", schedule_id, scan_id, schedule.url)

    # Run scan and notify on completion
    async def _run_and_notify() -> None:
        await run_scan(scan_id, schedule.url)
        finished = get(scan_id)
        if finished and finished.status == ScanStatus.COMPLETED:
            webhooks = webhooks_from_json(schedule.webhooks_json)
            if webhooks:
                await dispatch_webhooks(scan_id, schedule.url, webhooks)

    asyncio.create_task(_run_and_notify())
