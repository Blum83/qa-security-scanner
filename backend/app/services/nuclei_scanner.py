"""Nuclei scanner integration for fast CVE detection."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from app.core.config import settings
from app.core.store import get
from app.models.scan import IssueType, RiskLevel, ScanStatus, SecurityIssue

logger = logging.getLogger(__name__)

# Nuclei risk levels to our RiskLevel mapping
NUCLEI_RISK_MAP = {
    "critical": RiskLevel.CRITICAL,
    "high": RiskLevel.HIGH,
    "medium": RiskLevel.MEDIUM,
    "low": RiskLevel.LOW,
    "info": RiskLevel.INFO,
    "unknown": RiskLevel.INFO,
}

# Cache for nuclei binary path
_nuclei_path: Optional[str] = None


def _is_cancelled(scan_id: str) -> bool:
    record = get(scan_id)
    return record is not None and record.status == ScanStatus.CANCELLED


def _find_nuclei() -> str | None:
    """Find nuclei binary in common locations."""
    global _nuclei_path
    
    if _nuclei_path is not None:
        return _nuclei_path
    
    # Check PATH
    path = shutil.which("nuclei")
    if path:
        _nuclei_path = path
        return path
    
    # Check common installation paths
    common_paths = [
        "/usr/local/bin/nuclei",
        "/usr/bin/nuclei",
        "/opt/nuclei/nuclei",
        str(Path.home() / ".nuclei" / "nuclei"),
    ]
    
    for p in common_paths:
        if Path(p).exists():
            _nuclei_path = p
            return p
    
    return None


def _normalize_url(target_url: str) -> str:
    """Ensure URL has proper scheme for Nuclei."""
    target_url = target_url.strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    return target_url


def _parse_nuclei_severity(severity: str) -> RiskLevel:
    """Map Nuclei severity string to RiskLevel."""
    normalized = severity.lower().strip()
    return NUCLEI_RISK_MAP.get(normalized, RiskLevel.INFO)


def _clean_nuclei_output(output: str) -> list[SecurityIssue]:
    """Parse Nuclei JSON output and convert to SecurityIssue list."""
    issues: list[SecurityIssue] = []
    
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            # Try to extract JSON from mixed output
            json_match = re.search(r"\{[\s\S]*\}", line)
            if json_match:
                try:
                    data = json.loads(json_match.group())
                except json.JSONDecodeError:
                    continue
            else:
                continue
        
        # Skip heartbeats and non-result lines
        if not isinstance(data, dict):
            continue
        
        # Nuclei v3 format uses "info" type, check for actual findings
        matched_at = data.get("matched-at") or data.get("host")
        if not matched_at:
            continue
        
        name = data.get("info", {}).get("name", "Unknown Vulnerability")
        severity = data.get("info", {}).get("severity", "info")
        description = data.get("info", {}).get("description", "")
        recommendation = data.get("info", {}).get("recommendation", "")
        matched_url = data.get("matched-at", data.get("host", ""))
        
        # Clean markdown/HTML from description
        description = re.sub(r"\[|\]|\*|`", "", description)
        description = re.sub(r"<[^>]+>", "", description).strip()
        recommendation = re.sub(r"\[|\]|\*|`", "", recommendation)
        recommendation = re.sub(r"<[^>]+>", "", recommendation).strip()
        
        # Build message
        if description:
            message = description[:500]  # Truncate long descriptions
        else:
            message = f"A known vulnerability pattern was detected: {name}"
        
        if not recommendation:
            recommendation = (
                "Review this vulnerability. Check if the affected component is used in your application "
                "and apply the latest security patches or configuration fixes."
            )
        
        issues.append(
            SecurityIssue(
                type=IssueType.NUCLEI,
                name=name,
                risk=_parse_nuclei_severity(severity),
                message=message,
                recommendation=recommendation,
                url=str(matched_url),
            )
        )
    
    return issues


async def scan_with_nuclei(scan_id: str, target_url: str) -> list[SecurityIssue]:
    """Run Nuclei scan and return normalized issues.
    
    Nuclei runs in parallel with ZAP spider, so it should complete quickly
    while ZAP is still crawling.
    """
    nuclei_path = _find_nuclei()
    
    if not nuclei_path:
        logger.warning("Scan %s: Nuclei not found — skipping Nuclei scan", scan_id)
        return []
    
    normalized_url = _normalize_url(target_url)
    
    # Build nuclei command
    cmd = [
        nuclei_path,
        "-u", normalized_url,
        "-json-export", "-",  # Output JSON to stdout
        "-rate-limit", str(settings.nuclei_rate_limit or 150),
        "-retries", "2",
        "-timeout", str(settings.nuclei_timeout or 10),
    ]
    
    # Add severity filter if configured (skip noise)
    if settings.nuclei_severities:
        severities = ",".join(settings.nuclei_severities)
        cmd.extend(["-severity", severities])
    
    # Add templates filter if configured
    if settings.nuclei_templates:
        cmd.extend(["-t", settings.nuclei_templates])
    
    logger.info("Scan %s: running Nuclei scan: %s", scan_id, " ".join(cmd))
    
    try:
        # Run nuclei with timeout (shorter than ZAP)
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=settings.nuclei_scan_timeout_seconds,
            )
        except asyncio.TimeoutError:
            logger.warning("Scan %s: Nuclei timed out after %ds", 
                          scan_id, settings.nuclei_scan_timeout_seconds)
            process.kill()
            await process.wait()
            return [
                SecurityIssue(
                    type=IssueType.NUCLEI,
                    name="Nuclei Scan Timeout",
                    risk=RiskLevel.INFO,
                    message="Nuclei scan timed out. Partial results may be missing.",
                    recommendation="The target may be slow to respond or may have too many endpoints.",
                    url=target_url,
                )
            ]
        
        if process.returncode not in (0, 1):  # 0 = no issues, 1 = issues found
            stderr_text = stderr.decode("utf-8", errors="ignore") if stderr else ""
            logger.warning("Scan %s: Nuclei exited with code %d: %s", 
                          scan_id, process.returncode, stderr_text[:200])
            return []
        
        stdout_text = stdout.decode("utf-8", errors="ignore")
        issues = _clean_nuclei_output(stdout_text)
        
        logger.info("Scan %s: Nuclei completed — %d issues found", scan_id, len(issues))
        return issues
        
    except FileNotFoundError:
        logger.warning("Scan %s: Nuclei binary not found at %s", scan_id, nuclei_path)
        return [
            SecurityIssue(
                type=IssueType.NUCLEI,
                name="Nuclei Scanner Not Found",
                risk=RiskLevel.INFO,
                message="The Nuclei binary could not be executed.",
                recommendation="Ensure Nuclei is installed and in your PATH.",
                url=target_url,
            )
        ]
    except Exception as exc:
        logger.warning("Scan %s: Nuclei scan failed — %s: %s", 
                      scan_id, type(exc).__name__, exc)
        return []
