"""
NIGHTWATCH — Application Entry Point & FastAPI Application Assembly
Product: NIGHTWATCH — Lightweight Security Intelligence Platform
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
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

    # Start Ingestion Subsystem
    collector = get_file_collector()
    collector.start()

    # Start Detection Subsystem
    detection = get_detection_engine()
    detection.start()

    logger.info("NIGHTWATCH initialized successfully and ready for analysis.")
    yield

    # Shutdown actions
    logger.info("Shutting down NIGHTWATCH background services...")
    collector.stop()
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
