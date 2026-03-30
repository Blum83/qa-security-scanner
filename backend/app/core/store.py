"""In-memory scan store for MVP."""

from app.models.scan import ScanRecord

_scans: dict[str, ScanRecord] = {}


def get(scan_id: str) -> ScanRecord | None:
    return _scans.get(scan_id)


def save(record: ScanRecord) -> None:
    _scans[record.scan_id] = record
