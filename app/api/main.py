"""
NIGHTWATCH — Application Entry Point & FastAPI Application Assembly
Product: NIGHTWATCH — Lightweight Security Intelligence Platform
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes_alerts import router as alerts_router
from app.api.routes_events import router as events_router
from app.api.routes_inputs import router as inputs_router
from app.api.routes_saved_searches import router as saved_searches_router
from app.api.routes_search import router as search_router
from app.api.routes_system import router as system_router
from app.collectors.file_collector import get_file_collector
from app.collectors.host_telemetry import get_host_telemetry_collector
from app.collectors.syslog_listener import get_syslog_listener
from app.collectors.windows_collector import get_windows_collector
from app.core.config import get_settings
from app.detection.engine import get_detection_engine
from app.storage.engine import get_storage_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("nightwatch")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    settings = get_settings()
    logger.info(f"Starting {settings.app_title} v{settings.version}...")

    # Ensure storage engine and database are initialized
    storage = get_storage_engine()
    logger.info(f"Storage initialized at: {storage.db_path}")

    # 1. Start Continuous File Ingestion Subsystem (monitors configured real log files)
    file_collector = get_file_collector()
    file_collector.start()

    # 2. Start Real-Time Native Windows Event Log Collector (System, Application, PowerShell)
    windows_collector = get_windows_collector()
    windows_collector.start()

    # 3. Start Real-Time Host Process & Network Activity Monitor
    host_collector = get_host_telemetry_collector()
    host_collector.start()

    # 4. Start Real-Time UDP Syslog Server (port 1514)
    syslog_listener = get_syslog_listener()
    syslog_listener.start()

    # 5. Start Detection Subsystem
    detection = get_detection_engine()
    detection.start()

    logger.info("NIGHTWATCH Real-Time Collectors initialized successfully and ready for analysis.")
    yield

    # Shutdown actions
    logger.info("Shutting down NIGHTWATCH real-time background services...")
    file_collector.stop()
    windows_collector.stop()
    host_collector.stop()
    syslog_listener.stop()
    detection.stop()
    logger.info("NIGHTWATCH shutdown complete.")


settings = get_settings()
app = FastAPI(
    title=settings.app_title,
    description="Lightweight, local-first security information and event management (SIEM) and log analytics platform.",
    version=settings.version,
    lifespan=lifespan
)

# CORS middleware for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.server.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(search_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(inputs_router)
app.include_router(saved_searches_router)
app.include_router(system_router)

# Mount Static UI Files
static_dir = Path(__file__).resolve().parent.parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/", include_in_schema=False)
def serve_index():
    index_file = static_dir / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "NIGHTWATCH API online. Web UI index.html not yet built."}


@app.post("/services/collector/event", include_in_schema=False)
@app.post("/services/collector/raw", include_in_schema=False)
async def splunk_hec_endpoint(request: Request):
    """Splunk-compatible HTTP Event Collector endpoint."""
    from app.api.routes_events import http_event_collector
    try:
        body = await request.json()
    except Exception:
        raw_b = await request.body()
        body = {"event": raw_b.decode("utf-8", errors="replace")}
    return http_event_collector(body)

