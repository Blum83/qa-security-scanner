from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, HttpUrl


class WebhookType(str, Enum):
    SLACK = "slack"
    EMAIL = "email"


class WebhookConfig(BaseModel):
    type: WebhookType
    # Slack: incoming webhook URL; Email: recipient address
    target: str


class ScheduleStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    DELETED = "deleted"


class ScheduleRequest(BaseModel):
    url: HttpUrl
    cron: str  # standard 5-field cron expression, e.g. "0 9 * * 1"
    label: Optional[str] = None
    webhooks: list[WebhookConfig] = []


class ScheduleResponse(BaseModel):
    schedule_id: str
    url: str
    cron: str
    label: Optional[str] = None
    status: ScheduleStatus
    webhooks: list[WebhookConfig]
    last_scan_id: Optional[str] = None
    next_run_at: Optional[str] = None  # ISO-8601 UTC string


class ScheduleRecord(BaseModel):
    schedule_id: str
    url: str
    cron: str
    label: Optional[str] = None
    status: ScheduleStatus
    webhooks_json: str  # JSON-encoded list[WebhookConfig]
    last_scan_id: Optional[str] = None
    created_at: str  # ISO-8601 UTC string
