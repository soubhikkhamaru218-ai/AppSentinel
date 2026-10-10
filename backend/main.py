"""
AppSentinel // Backend Server Entrypoint
FastAPI Application serving the Evidence Correlation Engine.
"""

from contextlib import asynccontextmanager
import asyncio
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from backend.config import get_settings
from backend.models.database import get_database_file_path, init_db
from backend.api.routes_health import router as health_router
from backend.api.routes_scan import router as scan_router
from backend.utils.logging_config import logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Initializes database tables and storage directories on startup.
    """
    settings = get_settings()
    logger.info("APPSENTINEL_SERVER: Initializing database and storage directories...")
    
    # Ensure storage paths exist
    settings.upload_path.mkdir(parents=True, exist_ok=True)
    db_file = get_database_file_path()
    if db_file:
        db_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Initialize configured database schema
    init_db()
    logger.info("APPSENTINEL_SERVER: Database tables verified and ready.")
    
    yield
    logger.info("APPSENTINEL_SERVER: Shutting down cleanly.")


settings = get_settings()

app = FastAPI(
    title="AppSentinel // Digital Scam Evidence Correlation Engine",
    description=(
        "Deterministic correlation engine that analyzes suspicious messages, URLs, "
        "and Android APK packages using Rules R1–R7 with explainable verdicts."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ─── CORS CONFIGURATION ─────────────────────────────────────────────────────
def get_allowed_origins() -> list[str]:
    base_origins = [settings.frontend_origin.rstrip("/")] if settings.frontend_origin else []
    if settings.is_dev:
        base_origins.extend([
            "http://localhost:8088",
            "http://127.0.0.1:8088",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ])
    if getattr(settings, "cors_origins", ""):
        for o in settings.cors_origins.split(","):
            cleaned = o.strip().rstrip("/")
            if cleaned and cleaned not in base_origins:
                base_origins.append(cleaned)
    return list(dict.fromkeys(base_origins))

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$" if settings.is_dev else None,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ─── SCAN RATE LIMITER MIDDLEWARE ──────────────────────────────────────────
import time
from collections import defaultdict

_scan_rate_records: dict[str, list[float]] = defaultdict(list)
_scan_semaphore = asyncio.Semaphore(max(1, settings.scan_concurrency_limit))

@app.middleware("http")
async def scan_rate_limiter(request: Request, call_next):
    if request.url.path.startswith("/api/scan") and request.method == "POST":
        client_ip = request.client.host if request.client else "127.0.0.1"
        now = time.time()
        window_start = now - settings.scan_rate_limit_window_seconds
        recent = [t for t in _scan_rate_records[client_ip] if t > window_start]
        if len(recent) >= settings.scan_rate_limit_max:
            logger.warning(f"RATE_LIMIT: Client '{client_ip}' exceeded limit on {request.url.path}")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "detail": f"Scan request limit of {settings.scan_rate_limit_max} per {settings.scan_rate_limit_window_seconds:.0f} seconds exceeded. Please wait.",
                },
            )
        recent.append(now)
        _scan_rate_records[client_ip] = recent

        acquired = False
        try:
            await asyncio.wait_for(_scan_semaphore.acquire(), timeout=0.01)
            acquired = True
        except asyncio.TimeoutError:
            logger.warning("CONCURRENCY_LIMIT: Scan capacity exceeded on %s", request.url.path)
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too many concurrent scans",
                    "detail": "Scan capacity is temporarily full. Please retry shortly.",
                },
            )

        try:
            return await call_next(request)
        finally:
            if acquired:
                _scan_semaphore.release()

    return await call_next(request)

# ─── ROUTER REGISTRATION ────────────────────────────────────────────────────
app.include_router(health_router)
app.include_router(scan_router)


# ─── GLOBAL ERROR HANDLER ───────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"APPSENTINEL_UNHANDLED_ERROR on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": str(exc) if settings.is_dev else "An unexpected error occurred during processing.",
            "path": request.url.path,
        },
    )


# ─── ROOT & STATIC FILES ───────────────────────────────────────────────────
from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

frontend_dir = Path(__file__).resolve().parent.parent / "frontend"

@app.get("/")
def root_endpoint(request: Request):
    """
    Root endpoint: returns operational JSON metadata for API clients and health probes,
    or serves index.html for interactive browser user-agents.
    """
    accept = request.headers.get("accept", "")
    if "text/html" in accept and "application/json" not in accept and accept != "*/*":
        index_file = frontend_dir / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
    return {
        "engine": "AppSentinel // Evidence Correlation Engine v1.0",
        "version": "1.0.0",
        "status": "OPERATIONAL",
        "documentation": "/docs",
        "health": "/api/health",
    }

if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")


if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=settings.is_dev,
        log_level=settings.log_level.lower(),
    )
