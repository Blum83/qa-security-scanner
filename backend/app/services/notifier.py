"""Webhook notification service for scheduled scan completions.

Supports Slack (incoming webhook) and email (SMTP).
All failures are logged and swallowed — notifications must never cause a scan
to appear failed.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx

from app.core.config import settings
from app.core.store import get
from app.models.schedule import WebhookConfig, WebhookType

logger = logging.getLogger(__name__)


async def dispatch_webhooks(
    scan_id: str,
    target_url: str,
    webhooks: list[WebhookConfig],
) -> None:
    """Send all configured webhooks for a completed scan. Errors are suppressed."""
    scan = get(scan_id)
    if not scan:
        return

    summary = {
        "critical": sum(1 for i in scan.issues if i.risk.value == "critical"),
        "high": sum(1 for i in scan.issues if i.risk.value == "high"),
        "medium": sum(1 for i in scan.issues if i.risk.value == "medium"),
        "low": sum(1 for i in scan.issues if i.risk.value == "low"),
    }
    total = len(scan.issues)

    tasks = []
    for wh in webhooks:
        if wh.type == WebhookType.SLACK:
            tasks.append(_send_slack(wh.target, target_url, scan_id, summary, total))
        elif wh.type == WebhookType.EMAIL:
            tasks.append(_send_email(wh.target, target_url, scan_id, summary, total))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def _send_slack(
    webhook_url: str,
    target_url: str,
    scan_id: str,
    summary: dict,
    total: int,
) -> None:
    """POST a Block Kit message to a Slack incoming webhook URL."""
    status_emoji = "🔴" if summary["critical"] or summary["high"] else (
        "🟡" if summary["medium"] else "🟢"
    )
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{status_emoji} Security Scan Complete",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Target:* `{target_url}`\n*Total issues:* {total}",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"🔴 *Critical:* {summary['critical']}"},
                {"type": "mrkdwn", "text": f"🟠 *High:* {summary['high']}"},
                {"type": "mrkdwn", "text": f"🟡 *Medium:* {summary['medium']}"},
                {"type": "mrkdwn", "text": f"🟢 *Low:* {summary['low']}"},
            ],
        },
    ]
    payload = {"blocks": blocks}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
        logger.info("Slack notification sent for scan %s", scan_id)
    except Exception as exc:
        logger.warning("Failed to send Slack notification for scan %s: %s", scan_id, exc)


def _send_email_sync(
    to_address: str,
    target_url: str,
    scan_id: str,
    summary: dict,
    total: int,
) -> None:
    """Send an email via SMTP (synchronous — must be called in executor)."""
    if not settings.smtp_host:
        logger.warning("SMTP not configured — skipping email notification for scan %s", scan_id)
        return

    subject = f"Security Scan Complete: {target_url} — {total} issue(s) found"

    plain = (
        f"Security scan completed for {target_url}\n\n"
        f"Results:\n"
        f"  Critical: {summary['critical']}\n"
        f"  High:     {summary['high']}\n"
        f"  Medium:   {summary['medium']}\n"
        f"  Low:      {summary['low']}\n"
        f"  Total:    {total}\n\n"
        f"Scan ID: {scan_id}\n"
    )

    html = f"""
    <html><body style="font-family:sans-serif;color:#1e293b">
      <h2>Security Scan Complete</h2>
      <p><strong>Target:</strong> <code>{target_url}</code></p>
      <table style="border-collapse:collapse;margin-top:12px">
        <tr><td style="padding:4px 12px 4px 0;color:#dc2626"><strong>Critical</strong></td>
            <td style="padding:4px 0"><strong>{summary['critical']}</strong></td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:#ea580c"><strong>High</strong></td>
            <td style="padding:4px 0"><strong>{summary['high']}</strong></td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:#d97706"><strong>Medium</strong></td>
            <td style="padding:4px 0"><strong>{summary['medium']}</strong></td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:#16a34a"><strong>Low</strong></td>
            <td style="padding:4px 0"><strong>{summary['low']}</strong></td></tr>
      </table>
      <p style="margin-top:16px;color:#64748b;font-size:0.85em">Scan ID: {scan_id}</p>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = to_address
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        if settings.smtp_use_tls:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=15)

        if settings.smtp_user:
            server.login(settings.smtp_user, settings.smtp_password)
        server.sendmail(settings.smtp_from, [to_address], msg.as_string())
        server.quit()
        logger.info("Email notification sent to %s for scan %s", to_address, scan_id)
    except Exception as exc:
        logger.warning(
            "Failed to send email notification to %s for scan %s: %s",
            to_address,
            scan_id,
            exc,
        )


async def _send_email(
    to_address: str,
    target_url: str,
    scan_id: str,
    summary: dict,
    total: int,
) -> None:
    """Async wrapper for synchronous SMTP email sending."""
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(
                None,
                _send_email_sync,
                to_address,
                target_url,
                scan_id,
                summary,
                total,
            ),
            timeout=20.0,
        )
    except asyncio.TimeoutError:
        logger.warning("Email notification timed out for scan %s", scan_id)
    except Exception as exc:
        logger.warning("Email notification failed for scan %s: %s", scan_id, exc)
