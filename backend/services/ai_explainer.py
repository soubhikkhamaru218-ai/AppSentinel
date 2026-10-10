"""
AppSentinel // AI Explainer Bridge
Provides backward-compatible bridge for older callers while delegating
to the authoritative ai_explanation_service.py.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional

from backend.api.schemas import (
    AIExplanationResult,
    AIFinding,
    ApkAnalysisResult,
    EvidenceNode,
    MessageAnalysisResult,
    UrlAnalysisResult,
)
from backend.services.ai_explanation_service import generate_ai_explanation
from backend.utils.logging_config import logger


async def generate_explanation(
    verdict: str,
    confidence: float,
    triggered_rules: list[str],
    evidence_chain: list[EvidenceNode],
    claimed_identity: str = "",
    default_explanation: str = "",
    default_actions: list[str] | None = None,
    scan_id: str = "",
    scan_mode: str = "",
    message_result: Optional[MessageAnalysisResult] = None,
    url_result: Optional[UrlAnalysisResult] = None,
    apk_result: Optional[ApkAnalysisResult] = None,
    mobsf_result: Optional[dict] = None,
) -> dict:
    """Backward-compatible wrapper around generate_ai_explanation."""
    normalized = {
        "message": message_result.model_dump() if message_result else {},
        "url": url_result.model_dump() if url_result else {},
        "apk": apk_result.model_dump() if apk_result else {},
        "mobsf": mobsf_result or {},
    }
    correlation = {
        "verdict": verdict,
        "confidence": confidence,
        "triggered_rules": triggered_rules,
        "evidence_chain": evidence_chain,
    }

    ai_res = await generate_ai_explanation(
        normalized_evidence=normalized,
        correlation_result=correlation,
    )

    if ai_res.get("status") == "completed" and ai_res.get("summary"):
        return {
            "explanation": ai_res.get("summary") or default_explanation,
            "actions": ai_res.get("recommended_actions") or default_actions or [],
            "ai_enhanced": True,
            "ai_explanation": AIExplanationResult(
                ai_available=True,
                headline="Verification Analysis",
                summary=ai_res.get("summary", ""),
                why_it_matters="; ".join(ai_res.get("why_it_matters", [])),
                precautions=ai_res.get("recommended_actions", []),
                what_not_to_do=ai_res.get("avoid_actions", []),
                limitations=ai_res.get("limitations", []),
            ),
        }

    return {
        "explanation": default_explanation,
        "actions": default_actions or [],
        "ai_enhanced": False,
        "ai_explanation": None,
    }
