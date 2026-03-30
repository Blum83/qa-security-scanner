"""Checks HTTP response headers for common security misconfigurations."""

import logging

import httpx

from app.models.scan import IssueType, RiskLevel, SecurityIssue

logger = logging.getLogger(__name__)

# Timeout configuration: separate connect and read timeouts
DEFAULT_CONNECT_TIMEOUT = 10.0  # Max time to establish connection
DEFAULT_READ_TIMEOUT = 20.0  # Max time to receive response

# Each check: (header_name, missing_risk, missing_message, recommendation)
HEADER_CHECKS = [
    {
        "header": "Content-Security-Policy",
        "risk": RiskLevel.HIGH,
        "name": "Missing Content Security Policy",
        "message": (
            "The application does not define a Content Security Policy (CSP). "
            "Without CSP, attackers may be able to inject and execute malicious scripts (XSS attacks) "
            "on your pages, potentially stealing user data or hijacking sessions."
        ),
        "recommendation": (
            "Add a Content-Security-Policy header that restricts where scripts, styles, and other "
            "resources can load from. Start with a restrictive policy like "
            "\"default-src 'self'; script-src 'self'\" and adjust as needed."
        ),
    },
    {
        "header": "X-Frame-Options",
        "risk": RiskLevel.MEDIUM,
        "name": "Missing Clickjacking Protection",
        "message": (
            "The application does not set X-Frame-Options. This means attackers could embed your "
            "pages inside hidden frames on malicious sites, tricking users into clicking buttons "
            "or links they didn't intend to (clickjacking)."
        ),
        "recommendation": (
            "Add the header 'X-Frame-Options: DENY' (or SAMEORIGIN if you need to embed your own "
            "pages in frames). This prevents other sites from framing your content."
        ),
    },
    {
        "header": "Strict-Transport-Security",
        "risk": RiskLevel.HIGH,
        "name": "Missing HTTPS Enforcement (HSTS)",
        "message": (
            "The server does not enforce HTTPS via the Strict-Transport-Security header. "
            "Users who visit the site over plain HTTP could have their traffic intercepted, "
            "allowing attackers to steal credentials or inject malicious content."
        ),
        "recommendation": (
            "Add the header 'Strict-Transport-Security: max-age=31536000; includeSubDomains'. "
            "This tells browsers to always use HTTPS when connecting to your site."
        ),
    },
    {
        "header": "X-Content-Type-Options",
        "risk": RiskLevel.LOW,
        "name": "Missing MIME-Type Sniffing Protection",
        "message": (
            "The X-Content-Type-Options header is not set. Browsers may try to guess the type "
            "of a file (MIME sniffing), which could let an attacker trick the browser into "
            "executing a disguised script file."
        ),
        "recommendation": (
            "Add the header 'X-Content-Type-Options: nosniff' to prevent browsers from "
            "guessing file types."
        ),
    },
    {
        "header": "Referrer-Policy",
        "risk": RiskLevel.LOW,
        "name": "Missing Referrer Policy",
        "message": (
            "No Referrer-Policy header is set. When users click links on your site, the full "
            "page URL (which may contain sensitive data like tokens) could be leaked to the "
            "destination site via the Referer header."
        ),
        "recommendation": (
            "Add the header 'Referrer-Policy: strict-origin-when-cross-origin' to limit "
            "what URL information is shared with external sites."
        ),
    },
]


async def check_headers(target_url: str) -> list[SecurityIssue]:
    """Fetch headers from the target and report missing security headers."""
    issues: list[SecurityIssue] = []

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(DEFAULT_READ_TIMEOUT, connect=DEFAULT_CONNECT_TIMEOUT),
            verify=False,
        ) as client:
            logger.info("Fetching headers from %s (connect=%ds, read=%ds)", 
                       target_url, DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT)
            response = await client.get(target_url)
            logger.info("Headers received from %s, status=%s", target_url, response.status_code)
    except httpx.TimeoutException:
        logger.warning("Header check timed out for %s (connect=%ds, read=%ds)", 
                      target_url, DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT)
        issues.append(
            SecurityIssue(
                type=IssueType.HEADER,
                name="Connection Timeout",
                risk=RiskLevel.MEDIUM,
                message=f"The target did not respond within {DEFAULT_CONNECT_TIMEOUT + DEFAULT_READ_TIMEOUT} seconds. Header checks could not be completed.",
                recommendation="Verify the URL is correct and the server is reachable.",
                url=target_url,
            )
        )
        return issues
    except httpx.ConnectError as exc:
        logger.warning("Header check connection failed for %s: %s", target_url, exc)
        issues.append(
            SecurityIssue(
                type=IssueType.HEADER,
                name="Connection Failed",
                risk=RiskLevel.MEDIUM,
                message=f"Could not connect to the target: {type(exc).__name__} — {exc}.",
                recommendation="Verify the URL is correct and the server is reachable.",
                url=target_url,
            )
        )
        return issues
    except httpx.RequestError as exc:
        logger.warning("Header check request failed for %s: %s — %s", 
                      target_url, type(exc).__name__, exc)
        issues.append(
            SecurityIssue(
                type=IssueType.HEADER,
                name="Request Failed",
                risk=RiskLevel.MEDIUM,
                message=f"Request to target failed: {type(exc).__name__}.",
                recommendation="Verify the URL is correct and the server is reachable.",
                url=target_url,
            )
        )
        return issues
    except Exception as exc:
        logger.error("Unexpected error during header check for %s: %s — %s", 
                    target_url, type(exc).__name__, exc)
        issues.append(
            SecurityIssue(
                type=IssueType.HEADER,
                name="Unexpected Error",
                risk=RiskLevel.MEDIUM,
                message=f"An unexpected error occurred: {type(exc).__name__}.",
                recommendation="Check server logs for details.",
                url=target_url,
            )
        )
        return issues

    headers = response.headers

    # Check HTTPS
    if not target_url.startswith("https"):
        issues.append(
            SecurityIssue(
                type=IssueType.HEADER,
                name="Not Using HTTPS",
                risk=RiskLevel.HIGH,
                message=(
                    "The site is accessed over plain HTTP, not HTTPS. All data sent between "
                    "users and the server — including passwords and personal information — "
                    "can be intercepted by anyone on the same network."
                ),
                recommendation="Enable HTTPS (TLS/SSL) for all pages. Obtain a certificate and redirect all HTTP traffic to HTTPS.",
                url=target_url,
            )
        )

    # Check security headers
    for check in HEADER_CHECKS:
        if check["header"].lower() not in {k.lower() for k in headers.keys()}:
            issues.append(
                SecurityIssue(
                    type=IssueType.HEADER,
                    name=check["name"],
                    risk=check["risk"],
                    message=check["message"],
                    recommendation=check["recommendation"],
                    url=target_url,
                )
            )

    # Check cookies
    for cookie_header in headers.get_list("set-cookie"):
        _check_cookie(cookie_header, target_url, issues)

    return issues


def _check_cookie(cookie_header: str, target_url: str, issues: list[SecurityIssue]) -> None:
    cookie_lower = cookie_header.lower()
    cookie_name = cookie_header.split("=")[0].strip()

    if "secure" not in cookie_lower:
        issues.append(
            SecurityIssue(
                type=IssueType.HEADER,
                name=f"Cookie '{cookie_name}' Missing Secure Flag",
                risk=RiskLevel.MEDIUM,
                message=(
                    f"The cookie '{cookie_name}' does not have the Secure flag. "
                    "This means it can be sent over unencrypted HTTP connections, "
                    "making it possible for attackers to steal it."
                ),
                recommendation=f"Add the 'Secure' flag to the '{cookie_name}' cookie so it is only sent over HTTPS.",
                url=target_url,
            )
        )

    if "httponly" not in cookie_lower:
        issues.append(
            SecurityIssue(
                type=IssueType.HEADER,
                name=f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                risk=RiskLevel.MEDIUM,
                message=(
                    f"The cookie '{cookie_name}' does not have the HttpOnly flag. "
                    "JavaScript running on the page can read this cookie, which means "
                    "a cross-site scripting (XSS) attack could steal it."
                ),
                recommendation=f"Add the 'HttpOnly' flag to the '{cookie_name}' cookie to prevent JavaScript access.",
                url=target_url,
            )
        )
