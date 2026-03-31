"""Persistent scan store using SQLite."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app.models.scan import ScanRecord

_DB_PATH = Path(__file__).parent.parent.parent / "data" / "scans.db"
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_DB_PATH), timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    conn = _get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            target_url TEXT NOT NULL,
            progress INTEGER NOT NULL DEFAULT 0,
            phase TEXT NOT NULL DEFAULT '',
            phase_details TEXT NOT NULL DEFAULT '[]',
            issues TEXT NOT NULL DEFAULT '[]',
            error TEXT
        )
        """
    )
    conn.commit()
    conn.close()


# Initialize DB on import
_init_db()


def _record_to_dict(row: sqlite3.Row) -> ScanRecord:
    issues_data = json.loads(row["issues"])
    phase_details = json.loads(row["phase_details"])
    
    # Reconstruct SecurityIssue objects from dict data
    from app.models.scan import SecurityIssue, IssueType, RiskLevel
    issues = []
    for item in issues_data:
        issues.append(
            SecurityIssue(
                type=IssueType(item["type"]),
                name=item["name"],
                risk=RiskLevel(item["risk"]),
                message=item["message"],
                recommendation=item["recommendation"],
                url=item["url"],
            )
        )
    
    return ScanRecord(
        scan_id=row["scan_id"],
        status=row["status"],
        target_url=row["target_url"],
        progress=row["progress"],
        phase=row["phase"],
        phase_details=phase_details,
        issues=issues,
        error=row["error"],
    )


def get(scan_id: str) -> ScanRecord | None:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    return _record_to_dict(row)


def save(record: ScanRecord) -> None:
    # Serialize issues to JSON
    issues_json = json.dumps([issue.model_dump() for issue in record.issues])
    phase_details_json = json.dumps(record.phase_details)
    
    conn = _get_conn()
    conn.execute(
        """
        INSERT OR REPLACE INTO scans 
        (scan_id, status, target_url, progress, phase, phase_details, issues, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record.scan_id,
            record.status.value,
            record.target_url,
            record.progress,
            record.phase,
            phase_details_json,
            issues_json,
            record.error,
        ),
    )
    conn.commit()
    conn.close()


def get_all() -> list[ScanRecord]:
    """Get all scan records, ordered by creation time (most recent first)."""
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM scans ORDER BY rowid DESC").fetchall()
    conn.close()
    return [_record_to_dict(row) for row in rows]
