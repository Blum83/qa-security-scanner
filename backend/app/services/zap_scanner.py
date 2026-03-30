"""OWASP ZAP integration via its REST API."""

import asyncio
import logging
import re

import httpx

from app.core.config import settings
from app.core.store import get, save
from app.models.scan import IssueType, RiskLevel, ScanStatus, SecurityIssue

logger = logging.getLogger(__name__)

ZAP_RISK_MAP = {
    "0": RiskLevel.INFO,
    "1": RiskLevel.LOW,
    "2": RiskLevel.MEDIUM,
    "3": RiskLevel.HIGH,
}

# Human-readable explanations for common ZAP alert types
ALERT_EXPLANATIONS: dict[str, dict[str, str]] = {
    "Cross Site Scripting": {
        "message": (
            "The application may be vulnerable to Cross-Site Scripting (XSS). "
            "An attacker could inject malicious scripts that run in other users' browsers, "
            "potentially stealing session cookies, credentials, or personal data."
        ),
        "recommendation": (
            "Ensure all user input is properly sanitized and encoded before being displayed. "
            "Use your framework's built-in escaping functions and consider implementing a Content Security Policy."
        ),
    },
    "SQL Injection": {
        "message": (
            "The application may be vulnerable to SQL Injection. "
            "An attacker could manipulate database queries to read, modify, or delete data, "
            "or even take control of the database server."
        ),
        "recommendation": (
            "Use parameterized queries or prepared statements instead of building SQL strings "
            "from user input. Never concatenate user input directly into SQL queries."
        ),
    },
    "Directory Browsing": {
        "message": (
            "Directory listing is enabled on the server. Anyone can see all files in certain "
            "directories, which may expose sensitive files, backups, or configuration data."
        ),
        "recommendation": "Disable directory listing in your web server configuration.",
    },
    "Absence of Anti-CSRF Tokens": {
        "message": (
            "Forms on the site do not include anti-CSRF tokens. An attacker could trick a logged-in "
            "user into submitting a malicious form that performs actions on their behalf, such as "
            "changing their password or making a purchase."
        ),
        "recommendation": (
            "Add CSRF tokens to all state-changing forms and validate them on the server side. "
            "Most web frameworks provide built-in CSRF protection — make sure it is enabled."
        ),
    },
}


def _is_cancelled(scan_id: str) -> bool:
    record = get(scan_id)
    return record is not None and record.status == ScanStatus.CANCELLED


async def stop_zap_scans(scan_id: str) -> None:
    """Best-effort stop of all ZAP spider and active scans."""
    try:
        async with httpx.AsyncClient(base_url=settings.zap_base_url, timeout=10.0) as client:
            await client.get("/JSON/spider/action/stopAllScans/", params={"apikey": settings.zap_api_key})
            await client.get("/JSON/ascan/action/stopAllScans/", params={"apikey": settings.zap_api_key})
            logger.info("Scan %s: ZAP scans stopped", scan_id)
    except Exception:
        logger.debug("Scan %s: could not stop ZAP scans (ZAP may be unavailable)", scan_id)


async def scan_with_zap(scan_id: str, target_url: str) -> list[SecurityIssue]:
    """Run ZAP spider + active scan and return normalized issues."""
    try:
        async with httpx.AsyncClient(base_url=settings.zap_base_url, timeout=30.0) as client:
            # Check ZAP is reachable
            await client.get("/JSON/core/view/version/")
            logger.info("Scan %s: ZAP is reachable", scan_id)

            # Spider
            if _is_cancelled(scan_id):
                return []
            await _run_spider(client, scan_id, target_url)

            # Active scan
            if _is_cancelled(scan_id):
                return []
            await _run_active_scan(client, scan_id, target_url)

            if _is_cancelled(scan_id):
                return []

            # Fetch alerts
            record = get(scan_id)
            if record:
                record.phase = "Collecting scan results"
                record.progress = 92
                save(record)

            return await _fetch_alerts(client, target_url)

    except httpx.ConnectError:
        logger.warning("Scan %s: ZAP is not reachable at %s — skipping ZAP scan", scan_id, settings.zap_base_url)
        return [
            SecurityIssue(
                type=IssueType.ZAP,
                name="ZAP Scanner Unavailable",
                risk=RiskLevel.INFO,
                message=(
                    "The OWASP ZAP scanner could not be reached. Only header-based checks were performed. "
                    "For a more thorough scan, ensure ZAP is running."
                ),
                recommendation="Start the ZAP Docker container and re-run the scan for full coverage.",
                url=target_url,
            )
        ]
    except httpx.TimeoutException:
        logger.warning("Scan %s: ZAP request timed out", scan_id)
        return [
            SecurityIssue(
                type=IssueType.ZAP,
                name="ZAP Scanner Timeout",
                risk=RiskLevel.INFO,
                message="The ZAP scanner timed out while scanning. Partial results may be missing.",
                recommendation="The target may be slow to respond. Try scanning again or increase timeout settings.",
                url=target_url,
            )
        ]


async def _run_spider(client: httpx.AsyncClient, scan_id: str, target_url: str) -> None:
    # Set spider options to limit crawl scope
    try:
        # Set max nodes limit
        await client.get(
            "/JSON/spider/action/setOptionMaxChildren/", 
            params={"Integer": settings.zap_max_children or 0, "apikey": settings.zap_api_key},
            timeout=30.0
        )
        # Set max depth
        await client.get(
            "/JSON/spider/action/setOptionMaxDepth/", 
            params={"Integer": settings.zap_max_depth, "apikey": settings.zap_api_key},
            timeout=30.0
        )
        logger.info("Scan %s: configured spider limits: maxDepth=%s, maxChildren=%s", 
                   scan_id, settings.zap_max_depth, settings.zap_max_children)
    except Exception as exc:
        logger.warning("Scan %s: failed to set spider options — %s", scan_id, exc)
    
    # Build spider params with limits
    params = {
        "url": target_url,
        "apikey": settings.zap_api_key,
        "maxDepth": settings.zap_max_depth,
        "threadCount": settings.zap_thread_count,
    }
    
    # Add optional limits
    if settings.zap_max_children is not None:
        params["maxChildren"] = settings.zap_max_children
    
    logger.info("Scan %s: starting spider with params: maxDepth=%s, maxChildren=%s, threads=%s",
                scan_id, settings.zap_max_depth, settings.zap_max_children, settings.zap_thread_count)
    
    try:
        resp = await client.get("/JSON/spider/action/scan/", params=params, timeout=60.0)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.warning("Scan %s: spider start request failed — %s: %s", scan_id, type(exc).__name__, exc)
        return
    
    # Check if response indicates an error
    if "scan" not in data or data.get("scan") is None:
        logger.warning("Scan %s: spider did not start — response: %s", scan_id, data)
        return
        
    spider_id = data.get("scan")

    if not spider_id:
        logger.warning("Scan %s: spider did not start — no scan ID returned", scan_id)
        return

    logger.info("Scan %s: spider started (id=%s)", scan_id, spider_id)

    while True:
        await asyncio.sleep(2)

        if _is_cancelled(scan_id):
            return

        try:
            resp = await client.get("/JSON/spider/view/status/", params={"scanId": spider_id}, timeout=30.0)
            resp.raise_for_status()
            status_data = resp.json()
            progress = int(status_data.get("status", "0"))
        except Exception as exc:
            logger.warning("Scan %s: spider status request failed — %s: %s", scan_id, type(exc).__name__, exc)
            # Try to get progress from results count as fallback
            try:
                r = await client.get("/JSON/spider/view/results/", params={"scanId": spider_id}, timeout=30.0)
                urls_found = len(r.json().get("results", []))
                if urls_found > 0:
                    logger.info("Scan %s: spider found %d URLs before status check failed", scan_id, urls_found)
            except Exception:
                pass
            break

        # Fetch spider results count and log milestone progress
        details = []
        try:
            r = await client.get("/JSON/spider/view/results/", params={"scanId": spider_id}, timeout=30.0)
            r.raise_for_status()
            results = r.json().get("results", [])
            urls_found = len(results)
            if urls_found:
                details.append(f"Discovered {urls_found} URLs so far")
                # Log milestone progress for debugging
                if urls_found in [10, 50, 100, 200, 300, 400, 500]:
                    logger.info("Scan %s: spider milestone — %d URLs discovered", scan_id, urls_found)
                    # Log sample URLs for insight
                    sample = results[:3] if results else []
                    if sample:
                        logger.debug("Scan %s: sample URLs: %s", scan_id, sample)
        except Exception:
            pass

        record = get(scan_id)
        if record and record.status == ScanStatus.RUNNING:
            record.progress = 10 + int(progress * 0.3)
            # Include discovered URL count in phase text if available
            if details and len(details) > 0:
                url_info = details[0][:40] + "..." if len(details[0]) > 40 else details[0]
                record.phase = f"Crawling the website ({url_info}) — {progress}%"
            else:
                record.phase = f"Crawling the website (ZAP Spider) — {progress}%"
            record.phase_details = details
            save(record)

        if progress >= 100:
            break

    # Log final spider results count
    try:
        r = await client.get("/JSON/spider/view/results/", params={"scanId": spider_id}, timeout=30.0)
        r.raise_for_status()
        total_urls = len(r.json().get("results", []))
        logger.info("Scan %s: spider complete — discovered %d total URLs", scan_id, total_urls)
    except Exception:
        logger.info("Scan %s: spider complete", scan_id)


async def _get_active_scan_details(client: httpx.AsyncClient, ascan_id: str) -> list[str]:
    """Fetch currently running plugin names from ZAP active scan.
    
    ZAP response format:
    {
      "scanProgress": [
        "https://example.com",
        {"HostProcess": [{"Plugin": [name, id, release, status, ...]}, ...]}
      ]
    }
    Plugin list: [name, id, release_status, scan_status, ...]
    """
    details = []
    try:
        resp = await client.get("/JSON/ascan/view/scanProgress/", params={"scanId": ascan_id}, timeout=30.0)
        resp.raise_for_status()
        data = resp.json()

        scan_progress = data.get("scanProgress", [])
        
        # scanProgress is [url, {HostProcess: [...]}]
        if len(scan_progress) < 2:
            return details
            
        host_data = scan_progress[1]
        if not isinstance(host_data, dict):
            return details
            
        plugins = host_data.get("HostProcess", [])
        if not isinstance(plugins, list):
            return details
        
        running_count = 0
        for plugin_item in plugins:
            if not isinstance(plugin_item, dict):
                continue
            plugin_list = plugin_item.get("Plugin", [])
            if not isinstance(plugin_list, list) or len(plugin_list) < 4:
                continue
            
            # Plugin format: [name, id, release_status, scan_status, ...]
            name = plugin_list[0]
            status = str(plugin_list[3]).lower()
            
            if status == "running" and name:
                running_count += 1
                # Try to get progress from position 4 if available
                progress = plugin_list[4] if len(plugin_list) > 4 else ""
                if progress and progress != "0":
                    details.append(f"{name} ({progress}%)")
                else:
                    details.append(name)
        
        if running_count == 0:
            logger.debug("No running plugins found in scan %s", ascan_id)
            
    except Exception as exc:
        logger.debug("Failed to fetch active scan details for scan %s: %s", ascan_id, exc)

    return details[:5]  # Limit to top 5 running plugins


async def _get_alert_count(client: httpx.AsyncClient) -> int:
    """Get total number of alerts found so far."""
    try:
        resp = await client.get("/JSON/core/view/numberOfAlerts/", params={"baseurl": ""}, timeout=30.0)
        resp.raise_for_status()
        return int(resp.json().get("numberOfAlerts", 0))
    except Exception:
        return 0


async def _run_active_scan(client: httpx.AsyncClient, scan_id: str, target_url: str) -> None:
    # Set active scan options to limit scope
    try:
        # Set number of threads for active scan
        await client.get(
            "/JSON/ascan/action/setOptionThreadCount/", 
            params={"Integer": settings.zap_thread_count, "apikey": settings.zap_api_key},
            timeout=30.0
        )
        logger.info("Scan %s: configured active scan threads=%s", scan_id, settings.zap_thread_count)
    except Exception as exc:
        logger.warning("Scan %s: failed to set active scan options — %s", scan_id, exc)
    
    params = {"url": target_url, "apikey": settings.zap_api_key}
    
    try:
        resp = await client.get("/JSON/ascan/action/scan/", params=params, timeout=60.0)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.warning("Scan %s: active scan start request failed — %s: %s", scan_id, type(exc).__name__, exc)
        return
    
    # Check if response indicates an error
    if "scan" not in data or data.get("scan") is None:
        logger.warning("Scan %s: active scan did not start — response: %s", scan_id, data)
        return
        
    ascan_id = data.get("scan")

    if not ascan_id:
        logger.warning("Scan %s: active scan did not start — no scan ID returned", scan_id)
        return

    logger.info("Scan %s: active scan started (id=%s)", scan_id, ascan_id)

    while True:
        await asyncio.sleep(3)

        if _is_cancelled(scan_id):
            return

        try:
            resp = await client.get("/JSON/ascan/view/status/", params={"scanId": ascan_id}, timeout=30.0)
            resp.raise_for_status()
            progress = int(resp.json().get("status", "0"))
        except Exception as exc:
            logger.warning("Scan %s: active scan status request failed — %s: %s", scan_id, type(exc).__name__, exc)
            # Try to fetch alerts found so far
            try:
                alert_count = await _get_alert_count(client)
                if alert_count > 0:
                    logger.info("Scan %s: active scan found %d alerts before status check failed", scan_id, alert_count)
            except Exception:
                pass
            break

        # Fetch what plugins are currently running
        plugin_details = await _get_active_scan_details(client, ascan_id)
        
        # Build phase_details: plugin names + alert count
        details = []
        if plugin_details:
            details.extend(plugin_details)
        
        # Always show alert count at the end
        alert_count = await _get_alert_count(client)
        if alert_count > 0:
            details.append(f"Found {alert_count} potential issues so far")

        record = get(scan_id)
        if record and record.status == ScanStatus.RUNNING:
            record.progress = 40 + int(progress * 0.55)
            # Show plugin name in phase, fallback to generic text
            if plugin_details and len(plugin_details) > 0:
                plugin_name = plugin_details[0][:40] + "..." if len(plugin_details[0]) > 40 else plugin_details[0]
                record.phase = f"Testing: {plugin_name}"
            else:
                record.phase = f"Testing for vulnerabilities — {progress}%"
            record.phase_details = details
            save(record)

        if progress >= 100:
            break

    logger.info("Scan %s: active scan complete", scan_id)


async def _fetch_alerts(client: httpx.AsyncClient, target_url: str) -> list[SecurityIssue]:
    params = {"baseurl": target_url, "start": "0", "count": "500"}
    try:
        resp = await client.get("/JSON/alert/view/alerts/", params=params, timeout=60.0)
        resp.raise_for_status()
        raw_alerts = resp.json().get("alerts", [])
    except Exception as exc:
        logger.warning("Failed to fetch alerts from ZAP: %s: %s", type(exc).__name__, exc)
        raw_alerts = []

    seen: set[str] = set()
    issues: list[SecurityIssue] = []

    for alert in raw_alerts:
        name = alert.get("name", "Unknown Issue")
        risk_code = alert.get("riskcode", "0")
        url = alert.get("url", target_url)

        # Deduplicate by name + risk
        dedup_key = f"{name}|{risk_code}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        risk = ZAP_RISK_MAP.get(risk_code, RiskLevel.INFO)

        # Use curated explanation if available, otherwise clean up ZAP's description
        explanation = _get_explanation(name, alert)

        issues.append(
            SecurityIssue(
                type=IssueType.ZAP,
                name=name,
                risk=risk,
                message=explanation["message"],
                recommendation=explanation["recommendation"],
                url=url,
            )
        )

    return issues


def _get_explanation(name: str, alert: dict) -> dict[str, str]:
    # Check for curated explanation
    for key, explanation in ALERT_EXPLANATIONS.items():
        if key.lower() in name.lower():
            return explanation

    # Fall back to cleaned-up ZAP description
    desc = alert.get("description", "").strip()
    solution = alert.get("solution", "").strip()

    desc = re.sub(r"<[^>]+>", "", desc).strip()
    solution = re.sub(r"<[^>]+>", "", solution).strip()

    return {
        "message": desc or f"A potential security issue was detected: {name}.",
        "recommendation": solution or "Review and address this finding based on your application's context.",
    }
