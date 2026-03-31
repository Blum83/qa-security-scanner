from __future__ import annotations

from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    zap_base_url: str = "http://zap:8080"
    zap_api_key: str = ""
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    scan_timeout_seconds: int = 600
    
    # ZAP scan limits
    zap_max_depth: int = 3  # Max crawl depth (0 = unlimited)
    zap_max_children: Optional[int] = None  # Max children to crawl (None = unlimited)
    zap_max_nodes: int = 500  # Max total nodes to crawl
    zap_thread_count: int = 10  # Number of threads for spider
    zap_scan_timeout_seconds: int = 600  # Max time for ZAP phase (spider + active scan)
    zap_max_active_scan_urls: int = 20  # Max URLs to actively scan (after prioritization)
    zap_active_scan_timeout_seconds: int = 600  # Hard timeout for active scan phase (10 min)
    zap_max_concurrent_scans: int = 2  # Max parallel active scans (higher = more load)
    
    # Nuclei scan settings
    nuclei_scan_timeout_seconds: int = 120  # Max time for Nuclei scan
    nuclei_rate_limit: int = 150  # Requests per second
    nuclei_timeout: int = 10  # Per request timeout in seconds
    nuclei_severities: list[str] = ["critical", "high", "medium", "low"]  # Filter by severity
    nuclei_templates: Optional[str] = None  # Custom template path (None = all templates)

    # Scheduler
    scheduler_timezone: str = "UTC"

    # Webhook notifications (SMTP for email)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "scanner@example.com"
    smtp_use_tls: bool = True

    model_config = {"env_prefix": "QA_SCANNER_"}


settings = Settings()
