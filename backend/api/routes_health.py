"""
AppSentinel // Health & Status Endpoints
Provides system diagnostics, database connectivity, and external service checks.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.api.schemas import HealthResponse
from backend.config import get_settings
from backend.models.database import get_db
from backend.utils.logging_config import logger

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
@router.get("/api/health", response_model=HealthResponse)
def health_check(db: Session = Depends(get_db)):
    """
    Returns system status, engine version, database health,
    and availability of external intelligence providers.
    """
    settings = get_settings()

    # Check database connectivity
    db_healthy = False
    try:
        db.execute(text("SELECT 1"))
        db_healthy = True
    except Exception as e:
        logger.error(f"HEALTH_CHECK: Database probe failed: {e}")

    # Check upload storage directory
    storage_writable = False
    try:
        test_file = settings.upload_path / ".health_probe"
        test_file.touch()
        test_file.unlink()
        storage_writable = True
    except Exception as e:
        logger.warning(f"HEALTH_CHECK: Storage check failed: {e}")

    from backend.services.mobsf_service import check_mobsf_status
    mobsf_diag = check_mobsf_status()

    services = {
        "database": "online" if db_healthy else "offline",
        "storage": "writable" if storage_writable else "read-only",
        "gemini_ai_configured": bool(settings.gemini_api_key),
        "ai_model": settings.ai_model,
        "androguard_status": "ready (in-process static APK analysis)",
        "mobsf_status": mobsf_diag.get("status", "offline"),
        "mobsf_running": mobsf_diag.get("running", False),
        "mobsf_url": mobsf_diag.get("url", ""),
        "virustotal_configured": bool(settings.virustotal_api_key),
        "urlscan_configured": bool(settings.urlscan_api_key),
        "environment": settings.app_env,
    }

    return HealthResponse(
        status="ok" if db_healthy else "degraded",
        version="1.0.0",
        engine="AppSentinel Evidence Correlation Engine v1.0",
        services=services,
    )
