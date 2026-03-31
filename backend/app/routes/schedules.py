"""Schedule management endpoints."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from apscheduler.triggers.cron import CronTrigger
from fastapi import APIRouter, HTTPException

from app.core.schedule_store import (
    get_all_schedules,
    get_schedule,
    save_schedule,
    set_schedule_status,
    webhooks_to_json,
)
from app.models.schedule import (
    ScheduleRecord,
    ScheduleRequest,
    ScheduleResponse,
    ScheduleStatus,
    WebhookConfig,
)
from app.services.scheduler import (
    get_next_run_at,
    pause_schedule,
    register_schedule,
    resume_schedule,
    unregister_schedule,
)

router = APIRouter()


def _to_response(record: ScheduleRecord) -> ScheduleResponse:
    webhooks_data = json.loads(record.webhooks_json)
    webhooks = [WebhookConfig(**w) for w in webhooks_data]
    return ScheduleResponse(
        schedule_id=record.schedule_id,
        url=record.url,
        cron=record.cron,
        label=record.label,
        status=record.status,
        webhooks=webhooks,
        last_scan_id=record.last_scan_id,
        next_run_at=get_next_run_at(record.schedule_id) if record.status == ScheduleStatus.ACTIVE else None,
    )


def _validate_cron(cron: str) -> None:
    """Raise HTTPException 400 if the cron expression is invalid."""
    try:
        CronTrigger.from_crontab(cron, timezone="UTC")
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid cron expression: {exc}") from exc


@router.post("", response_model=ScheduleResponse, status_code=201)
async def create_schedule(body: ScheduleRequest):
    """Create a new recurring scan schedule."""
    _validate_cron(body.cron)

    schedule_id = str(uuid.uuid4())
    record = ScheduleRecord(
        schedule_id=schedule_id,
        url=str(body.url),
        cron=body.cron,
        label=body.label,
        status=ScheduleStatus.ACTIVE,
        webhooks_json=webhooks_to_json(body.webhooks),
        created_at=datetime.now(tz=timezone.utc).isoformat(),
    )
    save_schedule(record)
    register_schedule(schedule_id, body.cron)

    return _to_response(record)


@router.get("", response_model=list[ScheduleResponse])
async def list_schedules():
    """List all active and paused schedules."""
    records = get_all_schedules()
    return [_to_response(r) for r in records]


@router.get("/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule_detail(schedule_id: str):
    record = get_schedule(schedule_id)
    if not record or record.status == ScheduleStatus.DELETED:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return _to_response(record)


@router.put("/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(schedule_id: str, body: ScheduleRequest):
    """Update cron expression, label, or webhooks for a schedule."""
    record = get_schedule(schedule_id)
    if not record or record.status == ScheduleStatus.DELETED:
        raise HTTPException(status_code=404, detail="Schedule not found")

    _validate_cron(body.cron)

    record.url = str(body.url)
    record.cron = body.cron
    record.label = body.label
    record.webhooks_json = webhooks_to_json(body.webhooks)
    save_schedule(record)

    if record.status == ScheduleStatus.ACTIVE:
        register_schedule(schedule_id, body.cron)

    return _to_response(record)


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(schedule_id: str):
    """Soft-delete a schedule and remove it from the scheduler."""
    record = get_schedule(schedule_id)
    if not record or record.status == ScheduleStatus.DELETED:
        raise HTTPException(status_code=404, detail="Schedule not found")

    set_schedule_status(schedule_id, ScheduleStatus.DELETED)
    unregister_schedule(schedule_id)


@router.post("/{schedule_id}/pause", response_model=ScheduleResponse)
async def pause_schedule_route(schedule_id: str):
    record = get_schedule(schedule_id)
    if not record or record.status == ScheduleStatus.DELETED:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if record.status == ScheduleStatus.PAUSED:
        return _to_response(record)

    set_schedule_status(schedule_id, ScheduleStatus.PAUSED)
    pause_schedule(schedule_id)
    record.status = ScheduleStatus.PAUSED
    return _to_response(record)


@router.post("/{schedule_id}/resume", response_model=ScheduleResponse)
async def resume_schedule_route(schedule_id: str):
    record = get_schedule(schedule_id)
    if not record or record.status == ScheduleStatus.DELETED:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if record.status == ScheduleStatus.ACTIVE:
        return _to_response(record)

    set_schedule_status(schedule_id, ScheduleStatus.ACTIVE)
    resume_schedule(schedule_id)
    record.status = ScheduleStatus.ACTIVE
    return _to_response(record)
