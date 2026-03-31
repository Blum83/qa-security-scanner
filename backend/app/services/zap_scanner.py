"""OWASP ZAP integration via its REST API."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

import httpx

from app.core.config import settings
from app.core.store import get, save
from app.models.scan import IssueType, RiskLevel, ScanStatus, SecurityIssue
from app.utils.url_priority import prioritize_urls

logger = logging.getLogger(__name__)

# Export for use by scanner.py
zap_base_url = settings.zap_base_url
zap_api_key = settings.zap_api_key

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
    """Run ZAP spider + active scan and return normalized issues.
    
    Strategy:
    1. Spider crawls the site to discover all URLs
    2. Active scan runs on the BASE URL only — ZAP automatically tests
       all URLs in its context (discovered by spider)
    3. Hard timeout prevents infinite scanning
    """
    try:
        async with httpx.AsyncClient(base_url=settings.zap_base_url, timeout=30.0) as client:
            # Check ZAP is reachable
            await client.get("/JSON/core/view/version/")
            logger.info("Scan %s: ZAP is reachable", scan_id)

            # Phase 1: Spider — discovers URLs
            if _is_cancelled(scan_id):
                return []
            discovered_urls = await _run_spider(client, scan_id, target_url)

            # Show URL prioritization info
            if discovered_urls:
                prioritized = prioritize_urls(discovered_urls, max_urls=5)
                logger.info(
                    "Scan %s: spider discovered %d URLs. Top 5 for reference:",
                    scan_id, len(discovered_urls),
                )
                for url, score, reasons in prioritized:
                    logger.info("  [score=%d] %s — %s", score, url, ", ".join(reasons))

            # Phase 2: Active scan on base URL only
            # ZAP's active scan automatically covers all URLs in its context
            # (i.e., everything the spider found), so we don't need to scan
            # each URL individually.
            if _is_cancelled(scan_id):
                return []

            record = get(scan_id)
            if record:
                record.phase = "Running active scan"
                record.progress = 40
                save(record)

            try:
                await asyncio.wait_for(
                    _run_active_scan(client, scan_id, target_url),
                    timeout=settings.zap_active_scan_timeout_seconds or 300,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Scan %s: active scan timed out after %ds — fetching partial results",
                    scan_id, settings.zap_active_scan_timeout_seconds or 300,
                )
                if record:
                    record.phase = "Active scan timed out (partial results)"
                    save(record)

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


async def _run_spider(client: httpx.AsyncClient, scan_id: str, target_url: str) -> list[str]:
    """Run ZAP spider and return list of discovered URLs."""
    # Set spider options to limit crawl scope
    try:
        await client.get(
            "/JSON/spider/action/setOptionMaxChildren/", 
            params={"Integer": settings.zap_max_children or 0, "apikey": settings.zap_api_key},
            timeout=30.0
        )
        await client.get(
            "/JSON/spider/action/setOptionMaxDepth/", 
            params={"Integer": settings.zap_max_depth, "apikey": settings.zap_api_key},
            timeout=30.0
        )
        logger.info("Scan %s: configured spider limits: maxDepth=%s, maxChildren=%s", 
                   scan_id, settings.zap_max_depth, settings.zap_max_children)
    except Exception as exc:
        logger.warning("Scan %s: failed to set spider options — %s", scan_id, exc)
    
    params = {
        "url": target_url,
        "apikey": settings.zap_api_key,
        "maxDepth": settings.zap_max_depth,
        "threadCount": settings.zap_thread_count,
    }
    
    if settings.zap_max_children is not None:
        params["maxChildren"] = settings.zap_max_children
    
    logger.info("Scan %s: starting spider", scan_id)
    
    try:
        resp = await client.get("/JSON/spider/action/scan/", params=params, timeout=60.0)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.warning("Scan %s: spider start request failed — %s: %s", scan_id, type(exc).__name__, exc)
        return [target_url]
    
    if "scan" not in data or data.get("scan") is None:
        logger.warning("Scan %s: spider did not start — response: %s", scan_id, data)
        return [target_url]
        
    spider_id = data.get("scan")
    if not spider_id:
        logger.warning("Scan %s: spider did not start — no scan ID returned", scan_id)
        return [target_url]

    logger.info("Scan %s: spider started (id=%s)", scan_id, spider_id)

    while True:
        await asyncio.sleep(2)

        if _is_cancelled(scan_id):
            return []

        try:
            resp = await client.get("/JSON/spider/view/status/", params={"scanId": spider_id}, timeout=30.0)
            resp.raise_for_status()
            progress = int(resp.json().get("status", "0"))
        except Exception as exc:
            logger.warning("Scan %s: spider status request failed — %s", scan_id, type(exc).__name__)
            break

        details = []
        try:
            r = await client.get("/JSON/spider/view/results/", params={"scanId": spider_id}, timeout=30.0)
            r.raise_for_status()
            results = r.json().get("results", [])
            urls_found = len(results)
            if urls_found:
                details.append(f"Discovered {urls_found} URLs so far")
                if urls_found in [10, 50, 100, 200, 300, 400, 500]:
                    logger.info("Scan %s: spider milestone — %d URLs discovered", scan_id, urls_found)
        except Exception:
            pass

        record = get(scan_id)
        if record and record.status == ScanStatus.RUNNING:
            record.progress = 10 + int(progress * 0.3)
            if details:
                url_info = details[0][:40] + "..." if len(details[0]) > 40 else details[0]
                record.phase = f"Crawling ({url_info}) — {progress}%"
            else:
                record.phase = f"Crawling (ZAP Spider) — {progress}%"
            record.phase_details = details
            save(record)

        if progress >= 100:
            break

    # Return discovered URLs
    try:
        r = await client.get("/JSON/spider/view/results/", params={"scanId": spider_id}, timeout=30.0)
        r.raise_for_status()
        results = r.json().get("results", [])
        urls = []
        for item in results:
            parts = item.split(" ", 1)
            url = parts[1] if len(parts) > 1 else parts[0]
            urls.append(url)
        logger.info("Scan %s: spider complete — %d URLs discovered", scan_id, len(urls))
        return urls
    except Exception:
        logger.info("Scan %s: spider complete — returning target only", scan_id)
        return [target_url]


async def _get_active_scan_details(client: httpx.AsyncClient, ascan_id: str) -> list[str]:
    """Fetch currently running plugin names from ZAP active scan."""
    details = []
    try:
        resp = await client.get("/JSON/ascan/view/scanProgress/", params={"scanId": ascan_id}, timeout=30.0)
        resp.raise_for_status()
        data = resp.json()

        scan_progress = data.get("scanProgress", [])
        if len(scan_progress) < 2:
            return details
            
        host_data = scan_progress[1]
        if not isinstance(host_data, dict):
            return details
            
        plugins = host_data.get("HostProcess", [])
        if not isinstance(plugins, list):
            return details
        
        for plugin_item in plugins:
            if not isinstance(plugin_item, dict):
                continue
            plugin_list = plugin_item.get("Plugin", [])
            if not isinstance(plugin_list, list) or len(plugin_list) < 4:
                continue
            
            name = plugin_list[0]
            status = str(plugin_list[3]).lower()
            
            if status == "running" and name:
                progress = plugin_list[4] if len(plugin_list) > 4 else ""
                if progress and progress != "0":
                    details.append(f"{name} ({progress}%)")
                else:
                    details.append(name)
                
    except Exception as exc:
        logger.debug("Failed to fetch active scan details: %s", exc)

    return details[:5]


async def _get_alert_count(client: httpx.AsyncClient) -> int:
    """Get total number of alerts found so far."""
    try:
        resp = await client.get("/JSON/core/view/numberOfAlerts/", params={"baseurl": ""}, timeout=30.0)
        resp.raise_for_status()
        return int(resp.json().get("numberOfAlerts", 0))
    except Exception:
        return 0


async def _run_active_scan(client: httpx.AsyncClient, scan_id: str, target_url: str) -> None:
    """Run ZAP active scan on the target URL.
    
    ZAP automatically scans all URLs in its context (discovered by spider),
    so we only need to start one scan on the base URL.
    
    Progress tracking uses alert count growth as a proxy when ZAP's
    built-in progress is unreliable (often jumps 0% → 100%).
    """
    try:
        await client.get(
            "/JSON/ascan/action/setOptionThreadCount/",
            params={"Integer": settings.zap_thread_count, "apikey": settings.zap_api_key},
            timeout=30.0
        )
    except Exception as exc:
        logger.warning("Scan %s: failed to set active scan options — %s", scan_id, exc)
    
    params = {"url": target_url, "apikey": settings.zap_api_key}
    
    try:
        resp = await client.get("/JSON/ascan/action/scan/", params=params, timeout=60.0)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.warning("Scan %s: active scan start failed — %s: %s", scan_id, type(exc).__name__, exc)
        return
    
    if "scan" not in data or data.get("scan") is None:
        logger.warning("Scan %s: active scan did not start — response: %s", scan_id, data)
        return
        
    ascan_id = data.get("scan")
    if not ascan_id:
        return

    logger.info("Scan %s: active scan started (id=%s)", scan_id, ascan_id)

    max_iterations = 200  # 200 * 3s = 10 min max
    stuck_threshold = 30  # iterations with no change = stuck (~90s)
    
    prev_alert_count = 0
    no_change_count = 0
    scan_started = False  # Wait for first alerts before considering scan "started"

    for iteration in range(max_iterations):
        await asyncio.sleep(3)

        if _is_cancelled(scan_id):
            logger.info("Scan %s: cancelled during active scan", scan_id)
            try:
                await client.get("/JSON/ascan/action/stop/", params={"scanId": ascan_id}, timeout=10.0)
            except Exception:
                pass
            return

        # Get alert count — our primary progress indicator
        alert_count = await _get_alert_count(client)
        
        # Also try to get ZAP's built-in progress (fallback)
        zap_progress = 0
        plugin_details = []
        try:
            resp = await client.get("/JSON/ascan/view/status/", params={"scanId": ascan_id}, timeout=30.0)
            resp.raise_for_status()
            zap_progress = int(resp.json().get("status", "0"))
            plugin_details = await _get_active_scan_details(client, ascan_id)
        except Exception:
            # Don't break on status failure — keep polling alerts
            pass

        # Track progress using alert count (more reliable than ZAP's %)
        if alert_count > 0:
            scan_started = True
        
        if alert_count == prev_alert_count:
            no_change_count += 1
            if no_change_count >= stuck_threshold and scan_started:
                logger.warning(
                    "Scan %s: active scan appears stuck (no new alerts for %ds) — stopping",
                    scan_id, no_change_count * 3,
                )
                try:
                    await client.get("/JSON/ascan/action/stop/", params={"scanId": ascan_id}, timeout=10.0)
                except Exception:
                    pass
                break
        else:
            no_change_count = 0
            prev_alert_count = alert_count

        # Build progress: use alert count growth, capped at 95%
        # (leave room for final alert fetching)
        # Estimate max alerts based on current rate
        if scan_started and alert_count > 0:
            # Assume ~50 alerts is "full scan" for a typical site
            estimated_max = max(alert_count * 2, 50)
            alert_progress = min(95, int((alert_count / estimated_max) * 100))
        else:
            alert_progress = 0
        
        # Use whichever progress is higher (ZAP % or alert-based)
        progress = max(zap_progress, alert_progress)

        details = plugin_details[:3]

        record = get(scan_id)
        if record and record.status == ScanStatus.RUNNING:
            record.progress = 40 + int(progress * 0.55)
            if plugin_details:
                plugin_name = plugin_details[0][:40] + "..." if len(plugin_details[0]) > 40 else plugin_details[0]
                record.phase = f"Testing: {plugin_name}"
            elif scan_started:
                record.phase = f"Testing for vulnerabilities ({alert_count} found so far)"
            else:
                record.phase = f"Testing for vulnerabilities — warming up"
            record.phase_details = details
            save(record)

        # ZAP reports 100% when done
        if zap_progress >= 100:
            break

    logger.info("Scan %s: active scan complete (iteration %d/%d, %d alerts)",
               scan_id, iteration + 1, max_iterations, alert_count)


async def _fetch_alerts(client: httpx.AsyncClient, target_url: str) -> list[SecurityIssue]:
    params = {"baseurl": target_url, "start": "0", "count": "500"}
    try:
        resp = await client.get("/JSON/alert/view/alerts/", params=params, timeout=60.0)
        resp.raise_for_status()
        raw_alerts = resp.json().get("alerts", [])
    except Exception as exc:
        logger.warning("Failed to fetch alerts from ZAP: %s", type(exc).__name__)
        raw_alerts = []

    seen: set[str] = set()
    issues: list[SecurityIssue] = []

    for alert in raw_alerts:
        name = alert.get("name", "Unknown Issue")
        risk_code = alert.get("riskcode", "0")
        url = alert.get("url", target_url)

        dedup_key = f"{name}|{risk_code}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        risk = ZAP_RISK_MAP.get(risk_code, RiskLevel.INFO)
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
    for key, explanation in ALERT_EXPLANATIONS.items():
        if key.lower() in name.lower():
            return explanation

    desc = alert.get("description", "").strip()
    solution = alert.get("solution", "").strip()

    desc = re.sub(r"<[^>]+>", "", desc).strip()
    solution = re.sub(r"<[^>]+>", "", solution).strip()

    return {
        "message": desc or f"A potential security issue was detected: {name}.",
        "recommendation": solution or "Review and address this finding based on your application's context.",
    }
