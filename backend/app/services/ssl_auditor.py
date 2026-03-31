"""SSL/TLS audit service using Python stdlib ssl + socket modules."""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.models.scan import IssueType, RiskLevel, SecurityIssue

logger = logging.getLogger(__name__)

# Weak cipher suites to probe — set on SSLContext to test server acceptance.
# Modern OpenSSL may refuse some of these at library level (which counts as
# "server does not support them" — a good outcome, not a finding).
_WEAK_CIPHER_PROBE = "RC4:DES:3DES:NULL:EXPORT:aNULL"

# TLS versions considered obsolete
_LEGACY_VERSIONS = [
    ("TLSv1.0", getattr(ssl, "TLSVersion", None) and getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLSv1.1", getattr(ssl, "TLSVersion", None) and getattr(ssl.TLSVersion, "TLSv1_1", None)),
]

_CONNECT_TIMEOUT = 5  # seconds per probe


def _parse_host_port(target_url: str) -> tuple[str, int] | None:
    """Return (host, port) from URL, or None if not HTTPS."""
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        return None
    host = parsed.hostname or ""
    port = parsed.port or 443
    if not host:
        return None
    return host, port


def _fetch_cert_info(host: str, port: int) -> tuple[dict, str | None]:
    """
    Open a validating TLS connection and return (peercert_dict, error_str).
    error_str is None on success, or a human-readable message on failure.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return cert, None
    except ssl.SSLCertVerificationError as exc:
        return {}, f"Certificate verification failed: {exc.verify_message}"
    except ssl.SSLError as exc:
        return {}, f"SSL error: {exc}"
    except (socket.timeout, TimeoutError):
        return {}, "Connection timed out"
    except OSError as exc:
        return {}, f"Connection error: {exc}"


def _probe_tls_version(host: str, port: int, version_name: str, tls_version) -> bool:
    """
    Return True if the server accepts the given TLS version.
    tls_version is an ssl.TLSVersion enum value.
    """
    if tls_version is None:
        return False
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
        with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, OSError, socket.timeout, TimeoutError):
        # Either server rejected the version or OpenSSL won't negotiate it — good
        return False


def _probe_weak_ciphers(host: str, port: int) -> bool:
    """Return True if the server accepted a connection using weak cipher suites."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers(_WEAK_CIPHER_PROBE)
        with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLError:
        # set_ciphers may raise if all ciphers are disabled by local OpenSSL
        return False
    except (OSError, socket.timeout, TimeoutError):
        return False


def _sync_audit(host: str, port: int) -> list[SecurityIssue]:
    """
    Perform all SSL/TLS checks synchronously (runs in a thread pool executor).
    Returns a list of SecurityIssue objects.
    """
    issues: list[SecurityIssue] = []
    url = f"https://{host}:{port}"

    # ── Certificate validity + chain of trust ────────────────────────────────
    cert, chain_error = _fetch_cert_info(host, port)

    if chain_error:
        issues.append(SecurityIssue(
            type=IssueType.SSL,
            name="SSL Certificate Validation Failed",
            risk=RiskLevel.HIGH,
            message=chain_error,
            recommendation=(
                "Ensure the certificate is issued by a trusted CA, the chain is complete, "
                "the hostname matches, and the certificate has not expired."
            ),
            url=url,
        ))
        # Can't check expiry if we couldn't fetch the cert
    elif cert:
        # Parse notAfter — format: "Jan  1 12:00:00 2026 GMT"
        not_after_str = cert.get("notAfter", "")
        try:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            now = datetime.now(tz=timezone.utc)
            days_left = (not_after - now).days

            if days_left < 0:
                issues.append(SecurityIssue(
                    type=IssueType.SSL,
                    name="SSL Certificate Expired",
                    risk=RiskLevel.CRITICAL,
                    message=(
                        f"The SSL certificate expired {abs(days_left)} day(s) ago "
                        f"({not_after.strftime('%Y-%m-%d')}). Browsers will block access."
                    ),
                    recommendation=(
                        "Renew the certificate immediately from your CA or use Let's Encrypt "
                        "for free automatic renewal."
                    ),
                    url=url,
                ))
            elif days_left < 14:
                issues.append(SecurityIssue(
                    type=IssueType.SSL,
                    name="SSL Certificate Expiring Very Soon",
                    risk=RiskLevel.HIGH,
                    message=(
                        f"The SSL certificate expires in {days_left} day(s) "
                        f"({not_after.strftime('%Y-%m-%d')}). Users will see security warnings soon."
                    ),
                    recommendation=(
                        "Renew the certificate immediately. Consider enabling auto-renewal "
                        "via Let's Encrypt / Certbot."
                    ),
                    url=url,
                ))
            elif days_left < 30:
                issues.append(SecurityIssue(
                    type=IssueType.SSL,
                    name="SSL Certificate Expiring Soon",
                    risk=RiskLevel.MEDIUM,
                    message=(
                        f"The SSL certificate expires in {days_left} day(s) "
                        f"({not_after.strftime('%Y-%m-%d')})."
                    ),
                    recommendation=(
                        "Plan certificate renewal within the next few days to avoid service disruption."
                    ),
                    url=url,
                ))
        except ValueError:
            logger.warning("Could not parse certificate notAfter: %r", not_after_str)

    # ── Legacy TLS version probes ─────────────────────────────────────────────
    for version_name, tls_version in _LEGACY_VERSIONS:
        if _probe_tls_version(host, port, version_name, tls_version):
            issues.append(SecurityIssue(
                type=IssueType.SSL,
                name=f"Deprecated TLS Version Supported: {version_name}",
                risk=RiskLevel.HIGH,
                message=(
                    f"The server accepts connections using {version_name}, which is deprecated "
                    "and has known vulnerabilities (POODLE, BEAST, etc.). "
                    "Modern browsers have disabled support for these versions."
                ),
                recommendation=(
                    "Disable TLS 1.0 and TLS 1.1 in your server configuration. "
                    "Require TLS 1.2 as the minimum. Example for Nginx: "
                    "ssl_protocols TLSv1.2 TLSv1.3;"
                ),
                url=url,
            ))

    # ── Weak cipher probe ─────────────────────────────────────────────────────
    if _probe_weak_ciphers(host, port):
        issues.append(SecurityIssue(
            type=IssueType.SSL,
            name="Weak Cipher Suites Accepted",
            risk=RiskLevel.HIGH,
            message=(
                "The server accepted a connection using weak cipher suites (RC4, DES, 3DES, NULL, "
                "or EXPORT-grade). These ciphers can be broken and expose encrypted traffic."
            ),
            recommendation=(
                "Configure your server to only allow strong cipher suites. "
                "For Nginx, use: ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...'; "
                "and add ssl_prefer_server_ciphers on;"
            ),
            url=url,
        ))

    logger.info("SSL audit for %s:%d complete — %d issue(s) found", host, port, len(issues))
    return issues


async def audit_ssl(target_url: str) -> list[SecurityIssue]:
    """
    Async entry point for SSL/TLS audit. Runs synchronous checks in a thread
    pool executor to avoid blocking the event loop.
    """
    parsed = _parse_host_port(target_url)
    if parsed is None:
        # HTTP target — return an info-level notice
        return [SecurityIssue(
            type=IssueType.SSL,
            name="Site Not Using HTTPS",
            risk=RiskLevel.HIGH,
            message=(
                "The target URL uses plain HTTP. All traffic is transmitted unencrypted, "
                "exposing users to eavesdropping and man-in-the-middle attacks."
            ),
            recommendation=(
                "Configure your server to serve traffic over HTTPS. Obtain a free TLS "
                "certificate from Let's Encrypt and redirect all HTTP traffic to HTTPS."
            ),
            url=target_url,
        )]

    host, port = parsed
    loop = asyncio.get_running_loop()
    try:
        issues = await asyncio.wait_for(
            loop.run_in_executor(None, _sync_audit, host, port),
            timeout=30.0,
        )
        return issues
    except asyncio.TimeoutError:
        logger.warning("SSL audit timed out for %s:%d", host, port)
        return []
    except Exception:
        logger.exception("SSL audit failed for %s:%d", host, port)
        return []
