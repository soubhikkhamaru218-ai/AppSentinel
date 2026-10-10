"""
AppSentinel // Scan API Endpoints
Exposes scan endpoints delegating entirely to the central scan_orchestrator.
Maintains pure REST contracts with no duplicated pipeline or security logic.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from sqlalchemy.orm import Session

from backend.api.schemas import (
    ActionsBlock,
    AIOutput,
    CorrelationOutput,
    InputCoverage,
    MessageScanRequest,
    UrlScanRequest,
    FullScanRequest,
    ScanResponse,
    EvidenceNode,
    ScanHistoryResponse,
    ScanHistoryItem,
    VerdictDetail,
)
from backend.models.database import get_db
from backend.models.result_models import ScanRecord
from backend.services.file_service import stage_apk, cleanup_file, FileServiceError
from backend.services.scan_orchestrator import run_scan
from backend.utils.logging_config import logger

router = APIRouter(prefix="/api", tags=["Scans"])


def require_scan_history_authorization():
    """
    Temporary fail-closed guard for scan history APIs.

    Scan records can contain submitted messages, URLs, identities, and APK
    metadata. Until the app has authenticated users and per-record ownership,
    historical scan access must not be exposed to anonymous clients.
    """
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Scan history access is disabled until authentication and per-user authorization are available.",
    )


# ─── 1. MESSAGE SCAN ────────────────────────────────────────────────────────
@router.post("/scan/message", response_model=ScanResponse)
async def scan_message_endpoint(
    req: MessageScanRequest,
    db: Session = Depends(get_db),
):
    """Analyze a suspicious SMS, email, or instant message for scam signals."""
    logger.info("API: Message scan requested identity_supplied=%s", bool(req.identity))
    return await run_scan(
        message=req.message,
        identity=req.identity,
        scan_mode="message",
        db=db,
    )


# ─── 2. URL SCAN ────────────────────────────────────────────────────────────
@router.post("/scan/url", response_model=ScanResponse)
async def scan_url_endpoint(
    req: UrlScanRequest,
    db: Session = Depends(get_db),
):
    """Analyze a suspicious URL / domain with safe static inspection & reputation checks."""
    logger.info("API: URL scan requested url_length=%s identity_supplied=%s", len(req.url), bool(req.identity))
    return await run_scan(
        url=req.url,
        identity=req.identity,
        message=req.context_message,
        scan_mode="url",
        db=db,
    )


# ─── 3. APK SCAN ────────────────────────────────────────────────────────────
@router.post("/scan/apk", response_model=ScanResponse)
async def scan_apk_endpoint(
    file: UploadFile = File(..., description="Android APK package to inspect"),
    identity: str = Form(default=""),
    context_message: str = Form(default=""),
    db: Session = Depends(get_db),
):
    """Safely stage and inspect an APK package with Androguard and MobSF independently."""
    logger.info("API: APK scan requested filename_supplied=%s", bool(file.filename))

    try:
        staged = await stage_apk(file)
    except FileServiceError as e:
        logger.warning(f"API: APK staging rejected: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    try:
        return await run_scan(
            apk_path=staged["filepath"],
            identity=identity,
            message=context_message,
            scan_mode="apk",
            db=db,
        )
    finally:
        cleanup_file(staged["filepath"])


# ─── 4. FULL / MULTI-VECTOR SCAN ───────────────────────────────────────────
@router.post("/scan/full", response_model=ScanResponse)
async def scan_full_endpoint(
    req: FullScanRequest,
    db: Session = Depends(get_db),
):
    """Comprehensive multi-vector scan correlating message, identity, URL, and APK evidence simultaneously."""
    logger.info("API: Multi-vector comprehensive scan requested")

    apk_meta = None
    if req.apk_filename or req.apk_package_name or req.apk_permissions:
        apk_meta = {
            "filename": req.apk_filename,
            "hash": req.apk_hash,
            "package_name": req.apk_package_name,
            "permissions": req.apk_permissions,
            "size": req.apk_size or "0 MB",
        }

    return await run_scan(
        message=req.message,
        identity=req.identity,
        url=req.url,
        apk_metadata=apk_meta,
        scan_mode="full",
        db=db,
    )


# ─── 5. SCAN HISTORY & LOOKUP ──────────────────────────────────────────────
@router.get("/scans", response_model=ScanHistoryResponse)
def get_scan_history(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    _: None = Depends(require_scan_history_authorization),
):
    """List historical scan records from the configured database."""
    total = db.query(ScanRecord).count()
    records = (
        db.query(ScanRecord)
        .order_by(ScanRecord.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    items = [
        ScanHistoryItem(
            scan_id=r.scan_id,
            created_at=r.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if r.created_at else "",
            scan_mode=r.scan_mode,
            verdict=r.verdict,
            confidence=r.confidence,
            identity=r.input_identity or "",
        )
        for r in records
    ]

    return ScanHistoryResponse(total=total, scans=items)


@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan_by_id(
    scan_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(require_scan_history_authorization),
):
    """Retrieve complete evidence chain and findings for a historical scan ID."""
    record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found.",
        )

    evidence_nodes = [
        EvidenceNode(
            node=ev.node_label,
            desc=ev.description,
            rule=ev.rule_ref or "",
            severity=ev.severity,
        )
        for ev in record.evidence_items
    ]

    inputs = {
        "message": record.input_message,
        "identity": record.input_identity,
        "url": record.input_url,
        "apk_filename": record.input_apk_filename,
        "apk_hash": record.input_apk_hash,
    }

    input_coverage = InputCoverage(
        message=bool(record.input_message),
        identity=bool(record.input_identity),
        url=bool(record.input_url),
        apk=bool(record.input_apk_filename or record.input_apk_hash),
        supplied_count=record.vector_count,
        total_count=4,
        summary=f"{record.vector_count} of 4 supplied",
    )

    verdict_detail = VerdictDetail(
        label=record.verdict,
        confidence=record.confidence,
        severity="high" if record.verdict == "HIGH_RISK" else ("medium" if record.verdict == "SUSPICIOUS" else "low"),
    )

    return ScanResponse(
        scan_id=record.scan_id,
        timestamp=record.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if record.created_at else "",
        scan_mode=record.scan_mode,
        verdict=verdict_detail,
        confidence=record.confidence,
        input_coverage=input_coverage,
        correlation=CorrelationOutput(
            evidence_chain=evidence_nodes,
            findings=[ev.desc for ev in evidence_nodes],
        ),
        ai=AIOutput(
            status="completed" if record.explanation else "unavailable",
            summary=record.explanation or "",
            recommended_actions=record.get_actions(),
        ),
        limitations=[],
        actions=ActionsBlock(recommended=record.get_actions(), avoid=[]),
        vector_count=record.vector_count,
        findings_count=record.findings_count,
        triggered_rules=record.get_triggered_rules(),
        inputs=inputs,
        evidence_chain=evidence_nodes,
        explanation=record.explanation or "",
        schema_output={
            "scan_id": record.scan_id,
            "verdict": record.verdict,
            "confidence": record.confidence,
            "triggered_rules": record.get_triggered_rules(),
        },
    )


@router.delete("/scans/{scan_id}")
def delete_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(require_scan_history_authorization),
):
    """Delete a historical scan record from the database."""
    record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record '{scan_id}' not found.",
        )
    db.delete(record)
    db.commit()
    return {"status": "deleted", "scan_id": scan_id}
