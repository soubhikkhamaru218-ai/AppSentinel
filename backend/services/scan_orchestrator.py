"""
AppSentinel // Central Scan Orchestrator
Controls the entire multi-vector analysis pipeline:
1. Input validation & coverage mapping
2. Independent execution of real analyzers (Message, URL, VirusTotal, urlscan, Androguard, MobSF)
3. Evidence normalization & limitation aggregation
4. Authoritative deterministic correlation (Rules R1–R7)
5. Plain-language AI explanation synthesis (Gemini)
6. Structured logging and database persistence
"""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
import random
from typing import Any, Dict, List, Optional, Union

from sqlalchemy.orm import Session

from backend.api.schemas import (
    ActionsBlock,
    AIOutput,
    AIExplanationResult,
    ApkAnalysisResult,
    CorrelationOutput,
    EvidenceNode,
    InputCoverage,
    MessageAnalysisResult,
    MobSfAnalysisResult,
    PipelineStep,
    ScanResponse,
    TriggeredRuleDetail,
    UrlAnalysisResult,
    VerdictDetail,
)
from backend.config import get_settings
from backend.models.result_models import EvidenceItem, ScanRecord
from backend.services import ai_explanation_service
from backend.services.androguard_service import analyze_apk_file, analyze_apk_metadata
from backend.services.correlation_engine import correlate
from backend.services.identity_analyzer import check_identity_consistency
from backend.services.message_analyzer import analyze_message
from backend.services.mobsf_service import scan_apk_with_mobsf
from backend.services.url_analyzer import analyze_url
from backend.services.virustotal_service import check_file_hash, check_url as vt_check_url
from backend.services.urlscan_service import search_url as urlscan_search
from backend.utils.logging_config import logger


def generate_scan_id() -> str:
    """Generate standardized AppSentinel scan identifier."""
    return f"AS-{random.randint(10000, 99999)}-CORR"


async def run_scan(
    message: str = "",
    identity: str = "",
    url: str = "",
    apk_path: Optional[Union[str, Path]] = None,
    apk_metadata: Optional[Dict[str, Any]] = None,
    scan_mode: str = "full",
    db: Optional[Session] = None,
    scan_id: Optional[str] = None,
) -> ScanResponse:
    """
    Central scan orchestrator controlling the end-to-end security pipeline.
    Routes delegate directly to this function without duplicating logic.
    """
    settings = get_settings()
    sid = scan_id or generate_scan_id()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    logger.info(f"SCAN START scan_id={sid} mode={scan_mode}")

    # ── 1. INPUT VALIDATION & COVERAGE ──────────────────────────────────────
    has_message = bool(message and message.strip())
    has_identity = bool(identity and identity.strip())
    has_url = bool(url and url.strip())
    has_apk = bool(apk_path or apk_metadata)

    supplied_count = sum([has_message, has_identity, has_url, has_apk])
    input_coverage = InputCoverage(
        message=has_message,
        identity=has_identity,
        url=has_url,
        apk=has_apk,
        supplied_count=supplied_count,
        total_count=4,
        summary=f"{supplied_count} of 4 supplied",
    )

    pipeline: List[PipelineStep] = []
    limitations: List[str] = []
    analyzers_output: Dict[str, Any] = {}

    # ── 2. MESSAGE ANALYZER ─────────────────────────────────────────────────
    message_result = MessageAnalysisResult(status="skipped", reason="No message provided")
    if has_message:
        try:
            message_result = analyze_message(message)
            message_result.status = "completed"
            pipeline.append(PipelineStep(name="Message Analyzer", status="completed"))
            logger.info("MESSAGE ANALYZER status=completed")
        except Exception as e:
            logger.warning(f"MESSAGE ANALYZER status=failed: {e}")
            message_result.status = "failed"
            message_result.reason = str(e)
            limitations.append(f"Message analysis error: {e}")
            pipeline.append(PipelineStep(name="Message Analyzer", status="failed", reason=str(e)))
    else:
        pipeline.append(PipelineStep(name="Message Analyzer", status="skipped"))

    analyzers_output["message"] = message_result.model_dump()

    # ── 3. URL ANALYZER & REPUTATION ────────────────────────────────────────
    url_result = UrlAnalysisResult(status="skipped", reason="No URL provided")
    if has_url:
        try:
            url_result = analyze_url(url)
            pipeline.append(PipelineStep(name="URL Analyzer", status="completed"))
            logger.info(f"URL ANALYZER status={url_result.status}")
        except Exception as e:
            logger.warning(f"URL ANALYZER status=failed: {e}")
            url_result.status = "failed"
            url_result.reason = str(e)
            limitations.append(f"URL analysis error: {e}")
            pipeline.append(PipelineStep(name="URL Analyzer", status="failed", reason=str(e)))

        # VirusTotal URL reputation check
        # VirusTotal URL reputation check
        if settings.virustotal_api_key:
            try:
                vt_data = vt_check_url(url, settings.virustotal_api_key)
                if vt_data:
                    if vt_data.get("rate_limited"):
                        analyzers_output["virustotal"] = {"status": "rate_limited", "reason": vt_data.get("reason", "VirusTotal quota exceeded")}
                        pipeline.append(PipelineStep(name="VirusTotal", status="rate_limited", reason=vt_data.get("reason")))
                        limitations.append("VirusTotal reputation rate limit / quota exceeded.")
                    elif vt_data.get("unauthorized"):
                        analyzers_output["virustotal"] = {"status": "failed", "reason": vt_data.get("reason")}
                        pipeline.append(PipelineStep(name="VirusTotal", status="failed", reason=vt_data.get("reason")))
                        limitations.append("VirusTotal API authorization failed.")
                    elif vt_data.get("status") == "skipped":
                        analyzers_output["virustotal"] = {"status": "skipped", "reason": vt_data.get("reason")}
                        pipeline.append(PipelineStep(name="VirusTotal", status="skipped", reason=vt_data.get("reason")))
                        limitations.append("VirusTotal probe skipped (SSRF destination protection).")
                    else:
                        analyzers_output["virustotal"] = {"status": "completed", **vt_data}
                        pipeline.append(PipelineStep(name="VirusTotal", status="completed"))
                        logger.info("VIRUSTOTAL status=completed")
                else:
                    analyzers_output["virustotal"] = {"status": "unavailable", "reason": "No response from VirusTotal"}
                    pipeline.append(PipelineStep(name="VirusTotal", status="unavailable", reason="No response"))
                    limitations.append("VirusTotal reputation lookup returned no result.")
            except Exception as vte:
                analyzers_output["virustotal"] = {"status": "failed", "reason": str(vte)}
                pipeline.append(PipelineStep(name="VirusTotal", status="failed", reason=str(vte)))
                limitations.append("VirusTotal lookup failed.")
        else:
            analyzers_output["virustotal"] = {"status": "not_configured", "reason": "VirusTotal API key not configured"}
            pipeline.append(PipelineStep(name="VirusTotal", status="not_configured"))
            limitations.append("VirusTotal reputation intelligence not configured.")

        # urlscan.io URL reputation check
        if settings.urlscan_api_key:
            try:
                uscan_data = urlscan_search(url, settings.urlscan_api_key)
                if uscan_data:
                    if uscan_data.get("rate_limited"):
                        analyzers_output["urlscan"] = {"status": "rate_limited", "reason": uscan_data.get("reason", "urlscan.io quota exceeded")}
                        pipeline.append(PipelineStep(name="urlscan.io", status="rate_limited", reason=uscan_data.get("reason")))
                        limitations.append("urlscan.io rate limit exceeded.")
                    elif uscan_data.get("unauthorized"):
                        analyzers_output["urlscan"] = {"status": "failed", "reason": uscan_data.get("reason")}
                        pipeline.append(PipelineStep(name="urlscan.io", status="failed", reason=uscan_data.get("reason")))
                        limitations.append("urlscan.io API authorization failed.")
                    elif uscan_data.get("status") == "skipped":
                        analyzers_output["urlscan"] = {"status": "skipped", "reason": uscan_data.get("reason")}
                        pipeline.append(PipelineStep(name="urlscan.io", status="skipped", reason=uscan_data.get("reason")))
                        limitations.append("urlscan.io probe skipped (SSRF destination protection).")
                    else:
                        analyzers_output["urlscan"] = {"status": "completed", **uscan_data}
                        pipeline.append(PipelineStep(name="urlscan.io", status="completed"))
                        logger.info("URLSCAN status=completed")
                else:
                    analyzers_output["urlscan"] = {"status": "unavailable", "reason": "No response from urlscan.io"}
                    pipeline.append(PipelineStep(name="urlscan.io", status="unavailable", reason="No response"))
                    limitations.append("urlscan.io search returned no result.")
            except Exception as use:
                analyzers_output["urlscan"] = {"status": "failed", "reason": str(use)}
                pipeline.append(PipelineStep(name="urlscan.io", status="failed", reason=str(use)))
                limitations.append("urlscan.io lookup failed.")
        else:
            analyzers_output["urlscan"] = {"status": "not_configured", "reason": "urlscan.io API key not configured"}
            pipeline.append(PipelineStep(name="urlscan.io", status="not_configured"))
            limitations.append("urlscan.io intelligence not configured.")
    else:
        pipeline.append(PipelineStep(name="URL Analyzer", status="skipped"))
        pipeline.append(PipelineStep(name="VirusTotal", status="skipped"))
        pipeline.append(PipelineStep(name="urlscan.io", status="skipped"))
        analyzers_output["virustotal"] = {"status": "skipped"}
        analyzers_output["urlscan"] = {"status": "skipped"}

    analyzers_output["url"] = url_result.model_dump()

    # ── 4. APK ANALYZERS: ANDROGUARD + MOBSF (INDEPENDENT) ─────────────────
    androguard_result = ApkAnalysisResult(status="skipped", reason="No APK provided")
    mobsf_result: Dict[str, Any] = {"source": "mobsf", "status": "skipped", "reason": "No APK provided"}

    if has_apk:
        if apk_path:
            # 4a. Androguard independent static analysis
            try:
                androguard_result = analyze_apk_file(apk_path)
                logger.info(f"ANDROGUARD status={androguard_result.status}")
                pipeline.append(PipelineStep(name="Androguard", status=androguard_result.status, reason=androguard_result.reason))
                if androguard_result.status == "failed":
                    limitations.append(f"Androguard static analysis note: {androguard_result.reason or 'Parse issue'}")
            except Exception as age:
                logger.warning(f"ANDROGUARD status=failed: {age}")
                androguard_result.status = "failed"
                androguard_result.reason = str(age)
                pipeline.append(PipelineStep(name="Androguard", status="failed", reason=str(age)))
                limitations.append(f"Androguard failed: {age}")

            # 4b. MobSF independent remote analysis
            try:
                mobsf_result = scan_apk_with_mobsf(
                    apk_path,
                    timeout=settings.mobsf_timeout_seconds,
                    max_retries=settings.mobsf_max_retries,
                    poll_interval=settings.mobsf_poll_interval_seconds,
                )
                logger.info(f"MOBSF status={mobsf_result.get('status')}")
                pipeline.append(PipelineStep(
                    name="MobSF",
                    status=mobsf_result.get("status", "unavailable"),
                    reason=mobsf_result.get("reason"),
                ))
                if mobsf_result.get("status") in ["unavailable", "failed", "timed_out"]:
                    limitations.append(f"MobSF analysis was {mobsf_result.get('status')}: {mobsf_result.get('reason', 'No response')}")
                elif mobsf_result.get("status") == "not_configured":
                    limitations.append("MobSF security framework service not configured.")
            except Exception as me:
                logger.warning(f"MOBSF status=failed: {me}")
                mobsf_result = {"source": "mobsf", "status": "failed", "reason": str(me)}
                pipeline.append(PipelineStep(name="MobSF", status="failed", reason=str(me)))
                limitations.append(f"MobSF analysis failed: {me}")

        elif apk_metadata:
            # Metadata pre-parsed ingestion
            androguard_result = analyze_apk_metadata(
                filename=apk_metadata.get("filename", ""),
                file_hash=apk_metadata.get("hash", ""),
                package_name=apk_metadata.get("package_name", ""),
                permissions=apk_metadata.get("permissions", []),
                size=apk_metadata.get("size", "0 MB"),
            )
            pipeline.append(PipelineStep(name="Androguard", status="completed"))
            mobsf_result = {"source": "mobsf", "status": "skipped", "reason": "Pre-parsed metadata input only"}
            pipeline.append(PipelineStep(name="MobSF", status="skipped"))
    else:
        pipeline.append(PipelineStep(name="Androguard", status="skipped"))
        pipeline.append(PipelineStep(name="MobSF", status="skipped"))

    analyzers_output["androguard"] = androguard_result.model_dump()
    analyzers_output["mobsf"] = mobsf_result

    # ── 5. IDENTITY CONSISTENCY CHECK ───────────────────────────────────────
    identity_check = check_identity_consistency(
        claimed_identity=identity,
        message_result=message_result if has_message else None,
        url_result=url_result if has_url else None,
        apk_result=androguard_result if has_apk else None,
    )
    analyzers_output["identity"] = identity_check

    # Static URL analysis limitation note
    if has_url and not has_apk and not has_message:
        limitations.append("No conclusion about absolute safety can be made from static URL analysis alone.")

    # ── 6. DETERMINISTIC CORRELATION ENGINE (RULES R1–R7) ───────────────────
    corr_result = correlate(
        message_result=message_result if has_message else None,
        url_result=url_result if has_url else None,
        apk_result=androguard_result if has_apk else None,
        mobsf_result=mobsf_result if mobsf_result.get("status") == "completed" else None,
        identity_check=identity_check,
        claimed_identity=identity,
    )

    rule_codes = corr_result.get("triggered_rules", [])
    logger.info(f"CORRELATION rules={','.join(rule_codes) or 'NONE'} verdict={corr_result.get('verdict')}")
    pipeline.append(PipelineStep(name="Correlation Engine", status="completed"))

    # ── 7. PLAIN-LANGUAGE AI EXPLANATION (GEMINI) ───────────────────────────
    analyzer_status_map = {step.name: step.status for step in pipeline}
    ai_evidence_package = _build_ai_evidence_package(
        analyzers_output=analyzers_output,
        url_result=url_result,
        androguard_result=androguard_result,
        mobsf_result=mobsf_result,
    )
    try:
        ai_raw = await asyncio.wait_for(
            ai_explanation_service.generate_ai_explanation(
                normalized_evidence=ai_evidence_package,
                correlation_result=corr_result,
                limitations=limitations,
                analyzer_status=analyzer_status_map,
            ),
            timeout=settings.ai_total_timeout_seconds,
        )
    except asyncio.TimeoutError:
        logger.warning(
            "AI_EXPLANATION: Timed out after %.1f seconds",
            settings.ai_total_timeout_seconds,
        )
        ai_raw = {
            "status": "unavailable",
            "reason": f"AI explanation timed out after {settings.ai_total_timeout_seconds:.0f} seconds",
            "summary": "",
            "why_it_matters": [],
            "technical_to_plain_language": [],
            "limitations": limitations,
            "recommended_actions": [],
            "avoid_actions": [],
        }
    except Exception as ai_err:
        logger.warning(f"AI_EXPLANATION: Unexpected failure in explanation service: {ai_err}")
        ai_raw = {
            "status": "unavailable",
            "reason": f"AI explanation service failed: {ai_err}",
            "summary": "",
            "why_it_matters": [],
            "technical_to_plain_language": [],
            "limitations": limitations,
            "recommended_actions": [],
            "avoid_actions": [],
        }

    ai_status = ai_raw.get("status", "unavailable")
    logger.info(f"GEMINI status={ai_status}")
    pipeline.append(PipelineStep(name="Gemini AI", status=ai_status, reason=ai_raw.get("reason")))

    ai_output = AIOutput(
        status=ai_status,
        reason=ai_raw.get("reason"),
        summary=ai_raw.get("summary", ""),
        why_it_matters=ai_raw.get("why_it_matters", []),
        technical_to_plain_language=ai_raw.get("technical_to_plain_language", []),
        limitations=ai_raw.get("limitations", limitations),
        recommended_actions=ai_raw.get("recommended_actions", []),
        avoid_actions=ai_raw.get("avoid_actions", []),
    )

    # Backward compatible AI explanation card model
    ai_explanation_card: Optional[AIExplanationResult] = None
    if ai_status == "completed" and ai_raw.get("summary"):
        ai_explanation_card = AIExplanationResult(
            ai_available=True,
            headline=f"AppSentinel Verdict: {corr_result.get('verdict')}",
            summary=ai_raw.get("summary", ""),
            why_it_matters="; ".join(ai_raw.get("why_it_matters", [])),
            why_this_result=corr_result.get("explanation", ""),
            precautions=ai_raw.get("recommended_actions", []),
            what_not_to_do=ai_raw.get("avoid_actions", []),
            limitations=ai_raw.get("limitations", limitations),
        )

    # ── 8. BUILD FINAL REPORT ────────────────────────────────────────────────
    verdict_detail = VerdictDetail(
        label=corr_result.get("verdict", "LOW_CONCERN"),
        confidence=corr_result.get("confidence", 0.72),
        severity=corr_result.get("severity", "low"),
    )

    actions_block = ActionsBlock(
        recommended=ai_output.recommended_actions or corr_result.get("actions", []),
        avoid=ai_output.avoid_actions or [
            "Do NOT share OTPs, PINs, or net banking passwords.",
            "Do NOT install unverified APK packages sent via chat or messaging apps.",
        ],
    )

    correlation_output = CorrelationOutput(
        triggered_rules=corr_result.get("triggered_rule_details", []),
        evidence_chain=corr_result.get("evidence_chain", []),
        findings=corr_result.get("findings", []),
    )

    inputs_echo = {
        "message": message,
        "identity": identity,
        "url": url,
        "apk_filename": (androguard_result.filename or (apk_metadata.get("filename") if apk_metadata else "") or ""),
        "apk_hash": (androguard_result.sha256 or (apk_metadata.get("hash") if apk_metadata else "") or ""),
    }

    response = ScanResponse(
        scan_id=sid,
        timestamp=now_str,
        scan_mode=scan_mode,
        verdict=verdict_detail,
        confidence=corr_result.get("confidence", 0.72),
        input_coverage=input_coverage,
        analyzers=analyzers_output,
        pipeline=pipeline,
        correlation=correlation_output,
        ai=ai_output,
        limitations=limitations,
        actions=actions_block,
        # Legacy backward-compatibility fields:
        vector_count=input_coverage.supplied_count,
        findings_count=corr_result.get("findings_count", 0),
        triggered_rules=corr_result.get("triggered_rules", []),
        inputs=inputs_echo,
        evidence_chain=corr_result.get("evidence_chain", []),
        explanation=ai_raw.get("summary") or corr_result.get("explanation", ""),
        ai_explanation=ai_explanation_card,
        schema_output={
            "scan_id": sid,
            "verdict": verdict_detail.label,
            "verdict_detail": verdict_detail.model_dump(),
            "confidence": corr_result.get("confidence", 0.72),
            "input_coverage": input_coverage.model_dump(),
            "analyzers": analyzers_output,
            "ai_evidence_package": ai_evidence_package,
            "url_analysis": analyzers_output.get("url", {}),
            "apk_analysis": analyzers_output.get("androguard", {}),
            "analysis": analyzers_output.get("message", {}),
            "correlation": correlation_output.model_dump(),
            "ai": ai_output.model_dump(),
            "pipeline": [p.model_dump() for p in pipeline],
        },
    )

    # ── 9. PERSIST TO DATABASE (IF DB SESSION PROVIDED) ─────────────────────
    if db is not None:
        try:
            record = ScanRecord(
                scan_id=sid,
                scan_mode=scan_mode,
                input_message=message,
                input_identity=identity,
                input_url=url,
                input_apk_filename=inputs_echo.get("apk_filename", ""),
                input_apk_hash=inputs_echo.get("apk_hash", ""),
                verdict=verdict_detail.label,
                confidence=corr_result.get("confidence", 0.72),
                vector_count=input_coverage.supplied_count,
                findings_count=corr_result.get("findings_count", 0),
                explanation=corr_result.get("explanation", ""),
            )
            record.set_triggered_rules(corr_result.get("triggered_rules", []))
            record.set_actions(actions_block.recommended)

            db.add(record)
            db.flush()

            for ev in corr_result.get("evidence_chain", []):
                db.add(EvidenceItem(
                    scan_id=record.id,
                    node_label=ev.node,
                    description=ev.desc,
                    severity=ev.severity,
                    rule_ref=ev.rule,
                ))

            db.commit()
            logger.info(f"SCAN RECORD SAVED id={record.id} scan_id={sid}")
        except Exception as dbe:
            db.rollback()
            logger.error(f"DATABASE PERSISTENCE ERROR scan_id={sid}: {dbe}", exc_info=True)

    logger.info(f"SCAN COMPLETE scan_id={sid}")
    return response


def _build_ai_evidence_package(
    analyzers_output: Dict[str, Any],
    url_result: UrlAnalysisResult,
    androguard_result: ApkAnalysisResult,
    mobsf_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Package raw analyzer outputs for AI explanation without changing the
    deterministic verdict contract. The AI receives these raw/near-raw fields
    only to explain evidence; correlation remains authoritative.
    """
    raw_outputs = {
        "url_analyzer": url_result.model_dump(),
        "urlscan": analyzers_output.get("urlscan", {}),
        "androguard": androguard_result.model_dump(),
        "mobsf": mobsf_result,
    }

    return {
        "normalized_evidence": _strip_provider_payload_blobs(analyzers_output),
        "raw_analyzer_outputs": _strip_provider_payload_blobs(raw_outputs),
        "ai_instruction_boundary": (
            "Use the supplied analyzer evidence only to explain. "
            "Do not override the deterministic correlation verdict."
        ),
    }


def _strip_provider_payload_blobs(value: Any) -> Any:
    """Keep normalized evidence while excluding duplicated provider response bodies."""
    if isinstance(value, dict):
        return {
            key: _strip_provider_payload_blobs(item)
            for key, item in value.items()
            if key not in {"raw_report", "raw_response"}
        }
    if isinstance(value, list):
        return [_strip_provider_payload_blobs(item) for item in value]
    return value
