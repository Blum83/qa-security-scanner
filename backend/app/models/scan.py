from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, HttpUrl


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IssueType(str, Enum):
    HEADER = "header"
    ZAP = "zap"
    NUCLEI = "nuclei"
    CUSTOM = "custom"


class ScanRequest(BaseModel):
    url: HttpUrl


class ScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus


class SecurityIssue(BaseModel):
    type: IssueType
    name: str
    risk: RiskLevel
    message: str
    recommendation: str
    url: str


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanReport(BaseModel):
    scan_id: str
    status: ScanStatus
    target_url: str
    progress: int = 0
    phase: str = ""
    phase_details: list[str] = []
    summary: Optional[ScanSummary] = None
    issues: list[SecurityIssue] = []
    error: Optional[str] = None


class ScanRecord(BaseModel):
    scan_id: str
    status: ScanStatus
    target_url: str
    progress: int = 0
    phase: str = ""
    phase_details: list[str] = []
    issues: list[SecurityIssue] = []
    error: Optional[str] = None
