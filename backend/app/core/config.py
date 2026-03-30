from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    zap_base_url: str = "http://zap:8080"
    zap_api_key: str = ""
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    scan_timeout_seconds: int = 600
    
    # ZAP scan limits
    zap_max_depth: int = 3  # Max crawl depth (0 = unlimited)
    zap_max_children: int | None = None  # Max children to crawl (None = unlimited)
    zap_max_nodes: int = 500  # Max total nodes to crawl
    zap_thread_count: int = 10  # Number of threads for spider
    zap_scan_timeout_seconds: int = 600  # Max time for ZAP phase (spider + active scan)

    model_config = {"env_prefix": "QA_SCANNER_"}


settings = Settings()
