"""Persistent schedule store using the same SQLite database as scan records."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app.models.schedule import ScheduleRecord, ScheduleStatus, WebhookConfig

_DB_PATH = Path(__file__).parent.parent.parent / "data" / "scans.db"
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_DB_PATH), timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def _init_schedule_db() -> None:
    conn = _get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schedules (
            schedule_id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            cron TEXT NOT NULL,
            label TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            webhooks_json TEXT NOT NULL DEFAULT '[]',
            last_scan_id TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


_init_schedule_db()


def _row_to_record(row: sqlite3.Row) -> ScheduleRecord:
    return ScheduleRecord(
        schedule_id=row["schedule_id"],
        url=row["url"],
        cron=row["cron"],
        label=row["label"],
        status=ScheduleStatus(row["status"]),
        webhooks_json=row["webhooks_json"],
        last_scan_id=row["last_scan_id"],
        created_at=row["created_at"],
    )


def get_schedule(schedule_id: str) -> ScheduleRecord | None:
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM schedules WHERE schedule_id = ?", (schedule_id,)
    ).fetchone()
    conn.close()
    return _row_to_record(row) if row else None


def get_all_schedules() -> list[ScheduleRecord]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM schedules WHERE status != 'deleted' ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [_row_to_record(row) for row in rows]


def save_schedule(record: ScheduleRecord) -> None:
    conn = _get_conn()
    conn.execute(
        """
        INSERT OR REPLACE INTO schedules
        (schedule_id, url, cron, label, status, webhooks_json, last_scan_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record.schedule_id,
            record.url,
            record.cron,
            record.label,
            record.status.value,
            record.webhooks_json,
            record.last_scan_id,
            record.created_at,
        ),
    )
    conn.commit()
    conn.close()


def update_last_scan(schedule_id: str, scan_id: str) -> None:
    conn = _get_conn()
    conn.execute(
        "UPDATE schedules SET last_scan_id = ? WHERE schedule_id = ?",
        (scan_id, schedule_id),
    )
    conn.commit()
    conn.close()


def set_schedule_status(schedule_id: str, status: ScheduleStatus) -> None:
    conn = _get_conn()
    conn.execute(
        "UPDATE schedules SET status = ? WHERE schedule_id = ?",
        (status.value, schedule_id),
    )
    conn.commit()
    conn.close()


def webhooks_from_json(webhooks_json: str) -> list[WebhookConfig]:
    """Deserialize webhooks JSON string to list of WebhookConfig."""
    data = json.loads(webhooks_json)
    return [WebhookConfig(**item) for item in data]


def webhooks_to_json(webhooks: list[WebhookConfig]) -> str:
    """Serialize list of WebhookConfig to JSON string."""
    return json.dumps([wh.model_dump() for wh in webhooks])
