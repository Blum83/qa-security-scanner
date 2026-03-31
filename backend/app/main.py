import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.routes import scans
from app.routes import schedules
from app.services.nuclei_scanner import _find_nuclei
from app.services.scheduler import start_scheduler, stop_scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await start_scheduler()
    yield
    await stop_scheduler()


app = FastAPI(
    title="QA Security Scanner",
    version="1.0.0",
    description="Scan websites and get human-readable security reports.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router, prefix="/scan", tags=["scans"])
app.include_router(schedules.router, prefix="/schedules", tags=["schedules"])


@app.get("/health")
async def health():
    """Health check with scanner availability."""
    scanners = {
        "zap": False,
        "nuclei": False,
    }

    # Check ZAP
    try:
        async with httpx.AsyncClient(base_url=settings.zap_base_url, timeout=5.0) as client:
            await client.get("/JSON/core/view/version/")
            scanners["zap"] = True
    except Exception:
        pass

    # Check Nuclei
    scanners["nuclei"] = _find_nuclei() is not None

    return {
        "status": "ok",
        "scanners": scanners,
    }
